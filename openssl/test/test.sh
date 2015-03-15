#!/bin/bash
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

openssl s_server -accept 15418 -www -cert openssl/test/cert.pem -key openssl/test/key.pem >/dev/null 2>&1 &

for port in `seq 15411 15430`; do
	echo hello | openssl s_server -accept $port -dtls1 -cert openssl/test/cert.pem \
	  -key openssl/test/key.pem 2>&1 >/dev/null &
done

rm -f /tmp/rust_openssl_test_pipe
mkfifo /tmp/rust_openssl_test_pipe
# the server for the test ssl::tests::test_write_dtlsv1 must wait to receive
# data from the client
openssl s_server -accept 15410 -dtls1 -cert openssl/test/cert.pem \
  -key openssl/test/key.pem 2>&1 >/dev/null </tmp/rust_openssl_test_pipe
