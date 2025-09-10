FROM debian:trixie-slim 
LABEL maintainer="Nathanaël SEMHOUN <nathanael@semhoun.net>"

ARG LDAP_OPENLDAP_GID
ARG LDAP_OPENLDAP_UID

# Add openldap user and group first to make sure their IDs get assigned consistently, regardless of whatever dependencies get added
# If explicit uid or gid is given, use it.
RUN if [ -z "${LDAP_OPENLDAP_GID}" ]; then groupadd -g 911 -r openldap; else groupadd -r -g ${LDAP_OPENLDAP_GID} openldap; fi \
    && if [ -z "${LDAP_OPENLDAP_UID}" ]; then useradd -u 911 -r -g openldap openldap; else useradd -r -g openldap -u ${LDAP_OPENLDAP_UID} openldap; fi

# Install OpenLDAP, ldap-utils and ssl-tools
RUN set -ex \
	\
    # echo "path-include /usr/share/doc/krb5*" >> /etc/dpkg/dpkg.cfg.d/docker \
    && apt-get update -q && LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		vim \
        ca-certificates \
        iputils-ping \
        ldap-utils \
        libsasl2-modules \
        libsasl2-modules-db \
        libsasl2-modules-ldap \
        openssl \
        slapd \
        slapd-contrib \
        krb5-kdc-ldap \
    && update-ca-certificates \
    && rm -rf /var/lib/ldap /etc/ldap/slapd.d \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY rootfs/ /

# Log level
ENV LDAP_LOG_LEVEL 256
# Ulimit
ENV LDAP_NOFILE 1024
#ÊDo not perform any chown to fix file ownership
ENV DISABLE_CHOWN false
# Default port to bind slapd
ENV LDAP_PORT 389

# Expose default ldap and ldaps ports
EXPOSE 389

ENTRYPOINT ["/opt/bin/entrypoint.sh"]
CMD ["/opt/slapd/process.sh"]

# Put ldap config and database dir in a volume to persist data.
VOLUME ["/etc/ldap/slapd.d ", "/var/lib/ldap"]