#!/bin/bash

cd $(dirname $0)

openssl s_server -accept 15418 -www -cert cert.pem -key key.pem >/dev/null 2>&1 &
openssl s_server -accept 15419 -www -cert cert.pem -key key.pem \
    -nextprotoneg "http/1.1,spdy/3.1" -alpn "http/1.1,spdy/3.1" >/dev/null 2>&1 &
openssl s_server -no_ssl2 -accept 15420 -www -cert cert.pem -key key.pem >/dev/null 2>&1 &

if test "$TRAVIS_OS_NAME" == "osx"; then
	return
fi

for port in `seq 15411 15430`; do
    echo hello | openssl s_server -accept $port -dtls1 -cert cert.pem \
        -key key.pem 2>&1 >/dev/null &
done

# the server for the test ssl::tests::test_write_dtlsv1 must wait to receive
# data from the client
yes | openssl s_server -accept 15410 -dtls1 -cert cert.pem -key key.pem 2>&1 >/dev/null &
