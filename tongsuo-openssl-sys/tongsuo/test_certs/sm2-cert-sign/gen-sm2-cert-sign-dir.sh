#!/bin/bash

# create dir certs db private crl csr newcerts under sm2-ca dir.
if [ ! -d sm2-ca/certs ]; then
    mkdir -p sm2-ca/certs
fi

if [ ! -d sm2-ca/db ]; then
    mkdir -p sm2-ca/db
    touch sm2-ca/db/index
    openssl rand -hex 16 > sm2-ca/db/serial
    echo 1001 > sm2-ca/db/crlnumber
fi

if [ ! -d sm2-ca/private ]; then
    mkdir -p sm2-ca/private
    chmod 700 sm2-ca/private
fi

if [ ! -d sm2-ca/crl ]; then
    mkdir -p sm2-ca/crl
fi

if [ ! -d sm2-ca/newcerts ]; then
    mkdir -p sm2-ca/newcerts
fi

if [ ! -d sm2-ca/csr ]; then
    mkdir -p sm2-ca/csr
fi

