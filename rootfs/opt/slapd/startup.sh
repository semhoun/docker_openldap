#!/usr/bin/bash -e
set -o pipefail

# set -x (bash debug) if log level is trace
log-helper level eq trace && set -x

# Reduce maximum number of number of open file descriptors to 1024
# otherwise slapd consumes two orders of magnitude more of RAM
# see https://github.com/docker/docker/issues/8231
ulimit -n $LDAP_NOFILE


# usage: file_env VAR
#    ie: file_env 'XYZ_DB_PASSWORD'
# (will allow for "$XYZ_DB_PASSWORD_FILE" to fill in the value of
#  "$XYZ_DB_PASSWORD" from a file, especially for Docker's secrets feature)
file_env() {
        local var="$1"
        local fileVar="${var}_FILE"

  # The variables are already defined from the docker-light-baseimage
  # So if the _FILE variable is available we ovewrite them
        if [ "${!fileVar:-}" ]; then
    log-helper trace "${fileVar} was defined"

                val="$(< "${!fileVar}")"
    log-helper debug "${var} was repalced with the contents of ${fileVar} (the value was: ${val})"

    export "$var"="$val"
        fi

        unset "$fileVar"
}


file_env 'LDAP_ADMIN_PASSWORD'
file_env 'LDAP_CONFIG_PASSWORD'
file_env 'LDAP_READONLY_USER_PASSWORD'

# create dir if they not already exists
[ -d /var/lib/ldap ] || mkdir -p /var/lib/ldap
[ -d /etc/ldap/slapd.d ] || mkdir -p /etc/ldap/slapd.d

log-helper info "openldap user and group adjustments"
LDAP_OPENLDAP_UID=${LDAP_OPENLDAP_UID:-911}
LDAP_OPENLDAP_GID=${LDAP_OPENLDAP_GID:-911}

log-helper info "get current openldap uid/gid info inside container"
CUR_USER_GID=`id -g openldap || true`
CUR_USER_UID=`id -u openldap || true`

LDAP_UIDGID_CHANGED=false
if [ "$LDAP_OPENLDAP_UID" != "$CUR_USER_UID" ]; then
    log-helper info "CUR_USER_UID (${CUR_USER_UID}) does't match LDAP_OPENLDAP_UID (${LDAP_OPENLDAP_UID}), adjusting..."
    usermod -o -u "$LDAP_OPENLDAP_UID" openldap
    LDAP_UIDGID_CHANGED=true
fi
if [ "$LDAP_OPENLDAP_GID" != "$CUR_USER_GID" ]; then
    log-helper info "CUR_USER_GID (${CUR_USER_GID}) does't match LDAP_OPENLDAP_GID (${LDAP_OPENLDAP_GID}), adjusting..."
    groupmod -o -g "$LDAP_OPENLDAP_GID" openldap
    LDAP_UIDGID_CHANGED=true
fi

log-helper info '-------------------------------------'
log-helper info 'openldap GID/UID'
log-helper info '-------------------------------------'
log-helper info "User uid:    $(id -u openldap)"
log-helper info "User gid:    $(id -g openldap)"
log-helper info "uid/gid changed: ${LDAP_UIDGID_CHANGED}"
log-helper info "-------------------------------------"

# fix file permissions
if [ "${DISABLE_CHOWN,,}" == "false" ]; then
  log-helper info "updating file uid/gid ownership"
  mkdir -p /var/run/slapd
  chown -R openldap:openldap /var/run/slapd
  chown -R openldap:openldap /var/lib/ldap
  chown -R openldap:openldap /etc/ldap
  chown -R openldap:openldap /opt/slapd
fi

FIRST_START_DONE="/etc/ldap/slapd.d/slapd-first-start-done"
WAS_ADMIN_PASSWORD_SET="/etc/ldap/slapd.d/docker-openldap-was-admin-password-set"

copy_internal_seed_if_exists() {
  local src=$1
  local dest=$2
  if [ ! -z "${src}" ]; then
    echo  -e "Copy from internal path ${src} to ${dest}"
    cp -R ${src} ${dest}
  fi
}

# Copy seed files from internal path if specified
copy_internal_seed_if_exists "${LDAP_SEED_INTERNAL_SCHEMA_PATH}" "/opt/slapd/assets/config/bootstrap/schema/custom"
file_env 'LDAP_SEED_INTERNAL_LDIF_PATH'
copy_internal_seed_if_exists "${LDAP_SEED_INTERNAL_LDIF_PATH}" "/opt/slapd/assets/config/bootstrap/ldif/custom"

# container first start
if [ ! -e "$FIRST_START_DONE" ]; then

  #
  # Helpers
  #
  function get_ldap_base_dn() {
    # if LDAP_BASE_DN is empty set value from LDAP_DOMAIN
    if [ -z "$LDAP_BASE_DN" ]; then
      IFS='.' read -ra LDAP_BASE_DN_TABLE <<< "$LDAP_DOMAIN"
      for i in "${LDAP_BASE_DN_TABLE[@]}"; do
        EXT="dc=$i,"
        LDAP_BASE_DN=$LDAP_BASE_DN$EXT
      done

      LDAP_BASE_DN=${LDAP_BASE_DN::-1}
    fi
    # Check that LDAP_BASE_DN and LDAP_DOMAIN are in sync
    domain_from_base_dn=$(echo $LDAP_BASE_DN | tr ',' '\n' | sed -e 's/^.*=//' | tr '\n' '.' | sed -e 's/\.$//')
    if `echo "$domain_from_base_dn" | egrep -q ".*$LDAP_DOMAIN\$" || echo $LDAP_DOMAIN | egrep -q ".*$domain_from_base_dn\$"`; then
      : # pass
    else
      log-helper error "Error: domain $domain_from_base_dn derived from LDAP_BASE_DN $LDAP_BASE_DN does not match LDAP_DOMAIN $LDAP_DOMAIN"
      exit 1
    fi
  }

  function is_new_schema() {
    local COUNT=$(ldapsearch -Q -Y EXTERNAL -H ldapi:/// -b cn=schema,cn=config cn | grep -c "}$1,")
    if [ "$COUNT" -eq 0 ]; then
      echo 1
    else
      echo 0
    fi
  }

  function ldap_add_or_modify (){
    local LDIF_FILE=$1

    log-helper debug "Processing file ${LDIF_FILE}"
    sed -i "s|{{ LDAP_BASE_DN }}|${LDAP_BASE_DN}|g" $LDIF_FILE
    sed -i "s|{{ LDAP_BACKEND }}|${LDAP_BACKEND}|g" $LDIF_FILE
    sed -i "s|{{ LDAP_DOMAIN }}|${LDAP_DOMAIN}|g" $LDIF_FILE
    if [ "${LDAP_READONLY_USER,,}" == "true" ]; then
      sed -i "s|{{ LDAP_READONLY_USER_USERNAME }}|${LDAP_READONLY_USER_USERNAME}|g" $LDIF_FILE
      sed -i "s|{{ LDAP_READONLY_USER_PASSWORD_ENCRYPTED }}|${LDAP_READONLY_USER_PASSWORD_ENCRYPTED}|g" $LDIF_FILE
    fi
    if grep -iq changetype $LDIF_FILE ; then
        ( ldapmodify -Y EXTERNAL -Q -H ldapi:/// -f $LDIF_FILE 2>&1 || ldapmodify -h localhost -p 389 -D cn=admin,$LDAP_BASE_DN -w "$LDAP_ADMIN_PASSWORD" -f $LDIF_FILE 2>&1 ) | log-helper debug
    else
        ( ldapadd -Y EXTERNAL -Q -H ldapi:/// -f $LDIF_FILE 2>&1 || ldapadd -h localhost -p 389 -D cn=admin,$LDAP_BASE_DN -w "$LDAP_ADMIN_PASSWORD" -f $LDIF_FILE 2>&1 ) | log-helper debug
    fi
  }

  #
  # Global variables
  #
  BOOTSTRAP=false
  
  #
  # Source first start env file
  #
  . /opt/slapd/first-start.env
  
  #
  # database and config directory are empty
  # setup bootstrap config - Part 1
  #
  if [ -z "$(ls -A -I lost+found --ignore=.* /var/lib/ldap)" ] && \
    [ -z "$(ls -A -I lost+found --ignore=.* /etc/ldap/slapd.d)" ]; then

    BOOTSTRAP=true
    log-helper info "Database and config directory are empty..."
    log-helper info "Init new ldap server..."

    get_ldap_base_dn
    cat <<EOF | debconf-set-selections
slapd slapd/internal/generated_adminpw password ${LDAP_ADMIN_PASSWORD}
slapd slapd/internal/adminpw password ${LDAP_ADMIN_PASSWORD}
slapd slapd/password2 password ${LDAP_ADMIN_PASSWORD}
slapd slapd/password1 password ${LDAP_ADMIN_PASSWORD}
slapd slapd/dump_database_destdir string /var/backups/slapd-VERSION
slapd slapd/domain string ${LDAP_DOMAIN}
slapd shared/organization string ${LDAP_ORGANISATION}
slapd slapd/backend string ${LDAP_BACKEND^^}
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/allow_ldap_v2 boolean false
slapd slapd/no_configuration boolean false
slapd slapd/dump_database select when needed
EOF

    dpkg-reconfigure -f noninteractive slapd  2>&1 | log-helper debug

    # RFC2307bis schema
    if [ "${LDAP_RFC2307BIS_SCHEMA,,}" == "true" ]; then

      log-helper info "Switching schema to RFC2307bis..."
      cp /opt/slapd/assets/config/bootstrap/schema/rfc2307bis.* /etc/ldap/schema/

      rm -f /etc/ldap/slapd.d/cn=config/cn=schema/*

      mkdir -p /tmp/schema
      slaptest -f /opt/slapd/assets/config/bootstrap/schema/rfc2307bis.conf -F /tmp/schema
      mv /tmp/schema/cn=config/cn=schema/* /etc/ldap/slapd.d/cn=config/cn=schema
      rm -r /tmp/schema

      if [ "${DISABLE_CHOWN,,}" == "false" ]; then
        chown -R openldap:openldap /etc/ldap/slapd.d/cn=config/cn=schema
      fi
    fi

    rm -f /opt/slapd/assets/config/bootstrap/schema/rfc2307bis.*

  #
  # Error: the database directory (/var/lib/ldap) is empty but not the config directory (/etc/ldap/slapd.d)
  #
  elif [ -z "$(ls -A -I lost+found --ignore=.* /var/lib/ldap)" ] && [ ! -z "$(ls -A -I lost+found --ignore=.* /etc/ldap/slapd.d)" ]; then
    log-helper error "Error: the database directory (/var/lib/ldap) is empty but not the config directory (/etc/ldap/slapd.d)"
    exit 1

  #
  # Error: the config directory (/etc/ldap/slapd.d) is empty but not the database directory (/var/lib/ldap)
  #
  elif [ ! -z "$(ls -A -I lost+found --ignore=.* /var/lib/ldap)" ] && [ -z "$(ls -A -I lost+found --ignore=.* /etc/ldap/slapd.d)" ]; then
    log-helper error "Error: the config directory (/etc/ldap/slapd.d) is empty but not the database directory (/var/lib/ldap)"
    exit 1

  #
  # We have a database and config directory
  #
  else

    # try to detect if ldap backend is hdb but LDAP_BACKEND environment variable is mdb
    # due to default switch from hdb to mdb in 1.2.x
    if [ "${LDAP_BACKEND}" = "mdb" ]; then
      if [ -e "/etc/ldap/slapd.d/cn=config/olcDatabase={1}hdb.ldif" ]; then
        log-helper warning -e "\n\n\nWarning: LDAP_BACKEND environment variable is set to mdb but hdb backend is detected."
        log-helper warning "Going to use hdb as LDAP_BACKEND. Set LDAP_BACKEND=hdb to discard this message."
        LDAP_BACKEND="hdb"
      fi
    fi

  fi

  if [ "${KEEP_EXISTING_CONFIG,,}" == "true" ]; then
    log-helper info "/!\ KEEP_EXISTING_CONFIG = true configration will not be updated"
  else
    #
    # start OpenLDAP
    #

    # get previous hostname if OpenLDAP was started with replication
    # to avoid configuration pbs
    PREVIOUS_HOSTNAME_PARAM=""
    if [ -e "$WAS_STARTED_WITH_REPLICATION" ]; then

      source $WAS_STARTED_WITH_REPLICATION

      # if previous hostname != current hostname
      # set previous hostname to a loopback ip in /etc/hosts
      if [ "$PREVIOUS_HOSTNAME" != "$HOSTNAME" ]; then
        echo "127.0.0.2 $PREVIOUS_HOSTNAME" >> /etc/hosts
        PREVIOUS_HOSTNAME_PARAM="ldap://$PREVIOUS_HOSTNAME"
      fi
    fi

    # start OpenLDAP
    log-helper info "Start OpenLDAP..."
    # At this stage, we can just listen to ldap:// and ldap:// without naming any names
    if log-helper level ge debug; then
      slapd -h "ldap:/// ldapi:///" -u openldap -g openldap -d "$LDAP_LOG_LEVEL" 2>&1 &
    else
      slapd -h "ldap:/// ldapi:///" -u openldap -g openldap
    fi


    log-helper info "Waiting for OpenLDAP to start..."
    while [ ! -e /run/slapd/slapd.pid ]; do sleep 0.1; done

    #
    # setup bootstrap config - Part 2
    #
    if $BOOTSTRAP; then

      log-helper info "Add bootstrap schemas..."

      # convert schemas to ldif
      SCHEMAS=""
      for f in $(find /opt/slapd/assets/config/bootstrap/schema -name \*.schema -type f|sort); do
        SCHEMAS="$SCHEMAS ${f}"
      done
      /opt/bin/schema2ldif.sh "$SCHEMAS"

      # add converted schemas
      for f in $(find /opt/slapd/assets/config/bootstrap/schema -name \*.ldif -type f|sort); do
        log-helper debug "Processing file ${f}"
        # add schema if not already exists
        SCHEMA=$(basename "${f}" .ldif)
        ADD_SCHEMA=$(is_new_schema $SCHEMA)
        if [ "$ADD_SCHEMA" -eq 1 ]; then
          ldapadd -c -Y EXTERNAL -Q -H ldapi:/// -f $f 2>&1 | log-helper debug
        else
          log-helper info "schema ${f} already exists"
        fi
      done

      # set config password
      LDAP_CONFIG_PASSWORD_ENCRYPTED=$(slappasswd -s "$LDAP_CONFIG_PASSWORD")
      sed -i "s|{{ LDAP_CONFIG_PASSWORD_ENCRYPTED }}|${LDAP_CONFIG_PASSWORD_ENCRYPTED}|g" /opt/slapd/assets/config/bootstrap/ldif/01-config-password.ldif

      # adapt security config file
      get_ldap_base_dn
      sed -i "s|{{ LDAP_BASE_DN }}|${LDAP_BASE_DN}|g" /opt/slapd/assets/config/bootstrap/ldif/02-security.ldif

      # process config files (*.ldif) in bootstrap directory (do no process files in subdirectories)
      log-helper info "Add image bootstrap ldif..."
      for f in $(find /opt/slapd/assets/config/bootstrap/ldif -mindepth 1 -maxdepth 1 -type f -name \*.ldif  | sort); do
        log-helper debug "Processing file ${f}"
        ldap_add_or_modify "$f"
      done

      # read only user
      if [ "${LDAP_READONLY_USER,,}" == "true" ]; then
        log-helper info "Add read only user..."

        LDAP_READONLY_USER_PASSWORD_ENCRYPTED=$(slappasswd -s $LDAP_READONLY_USER_PASSWORD)

        ldap_add_or_modify "/opt/slapd/assets/config/bootstrap/ldif/readonly-user/readonly-user.ldif"
        ldap_add_or_modify "/opt/slapd/assets/config/bootstrap/ldif/readonly-user/readonly-user-acl.ldif"
      fi

      log-helper info "Add custom bootstrap ldif..."
      for f in $(find /opt/slapd/assets/config/bootstrap/ldif/custom -type f -name \*.ldif  | sort); do
        ldap_add_or_modify "$f"
      done

    fi
	
    if [[ -f "$WAS_ADMIN_PASSWORD_SET" ]]; then
      get_ldap_base_dn
      LDAP_CONFIG_PASSWORD_ENCRYPTED=$(slappasswd -s "$LDAP_CONFIG_PASSWORD")
      LDAP_ADMIN_PASSWORD_ENCRYPTED=$(slappasswd -s "$LDAP_ADMIN_PASSWORD")
      sed -i "s|{{ LDAP_CONFIG_PASSWORD_ENCRYPTED }}|${LDAP_CONFIG_PASSWORD_ENCRYPTED}|g" /opt/slapd/assets/config/admin/root-password-change.ldif
      sed -i "s|{{ LDAP_ADMIN_PASSWORD_ENCRYPTED }}|${LDAP_ADMIN_PASSWORD_ENCRYPTED}|g" /opt/slapd/assets/config/admin/root-password-change.ldif
      sed -i "s|{{ LDAP_BACKEND }}|${LDAP_BACKEND}|g" /opt/slapd/assets/config/admin/root-password-change.ldif
      sed -i "s|{{ LDAP_ADMIN_PASSWORD_ENCRYPTED }}|${LDAP_ADMIN_PASSWORD_ENCRYPTED}|g" /opt/slapd/assets/config/admin/admin-password-change.ldif
      sed -i "s|{{ LDAP_BASE_DN }}|${LDAP_BASE_DN}|g" /opt/slapd/assets/config/admin/admin-password-change.ldif

      ldap_add_or_modify "/opt/slapd/assets/config/admin/root-password-change.ldif"
      ldap_add_or_modify "/opt/slapd/assets/config/admin/admin-password-change.ldif" | log-helper debug || true

    else
        touch "$WAS_ADMIN_PASSWORD_SET"
    fi

    #
    # stop OpenLDAP
    #
    log-helper info "Stop OpenLDAP..."

    SLAPD_PID=$(cat /run/slapd/slapd.pid)
    kill -15 $SLAPD_PID
    while [ -e /proc/$SLAPD_PID ]; do sleep 0.1; done # wait until slapd is terminated
  fi

  #
  # ldap client config
  #
  if [ "${LDAP_TLS,,}" == "true" ]; then
    log-helper info "Configure ldap client TLS configuration..."
    sed -i --follow-symlinks "s,TLS_CACERT.*,TLS_CACERT ${LDAP_TLS_CA_CRT_PATH},g" /etc/ldap/ldap.conf
    echo "TLS_REQCERT ${LDAP_TLS_VERIFY_CLIENT}" >> /etc/ldap/ldap.conf
    cp -f /etc/ldap/ldap.conf /opt/slapd/assets/ldap.conf

    [[ -f "$HOME/.ldaprc" ]] && rm -f $HOME/.ldaprc
    echo "TLS_CERT ${LDAP_TLS_CRT_PATH}" > $HOME/.ldaprc
    echo "TLS_KEY ${LDAP_TLS_KEY_PATH}" >> $HOME/.ldaprc
    cp -f $HOME/.ldaprc /opt/slapd/assets/.ldaprc
  fi

  #
  # remove container config files
  #
  if [ "${LDAP_REMOVE_CONFIG_AFTER_SETUP,,}" == "true" ]; then
    log-helper info "Remove config files..."
    rm -rf /opt/slapd/assets/config
  fi

  #
  # setup done :)
  #
  log-helper info "First start is done..."
  touch $FIRST_START_DONE
  
  log-helper info '-------------------------------------'
  log-helper info 'openldap user info'
  log-helper info '-------------------------------------'
  log-helper info "BaseDN:      ${LDAP_BASE_DN}"
  log-helper info "Admin DN:    cn=admin,${LDAP_BASE_DN}"
  if [ "${LDAP_READONLY_USER,,}" == "true" ]; then
  log-helper info "ReadOnly DN: cn=${LDAP_READONLY_USER_USERNAME},${LDAP_BASE_DN}"
  fi
  log-helper info "-------------------------------------"
fi

ln -sf /opt/slapd/assets/.ldaprc $HOME/.ldaprc
ln -sf /opt/slapd/assets/ldap.conf /etc/ldap/ldap.conf

exit 0
