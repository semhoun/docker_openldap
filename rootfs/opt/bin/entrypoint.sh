#!/usr/bin/env bash

export PATH=${PATH}:/opt/bin

/opt/slapd/startup.sh

exec $@