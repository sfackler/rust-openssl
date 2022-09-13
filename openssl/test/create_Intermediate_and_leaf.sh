ext="
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
keyUsage = keyCertSign, cRLSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
"

openssl req -nodes -newkey rsa:2048 -keyout intermediate.key -out intermediate.csr -subj "/C=/ST=/L=/O=/OU=/CN=intermediate" \
&& openssl x509 -req -CA root-ca.pem -CAkey root-ca.key -in intermediate.csr -out intermediate.pem -days 1550 -CAcreateserial -extfile <(echo "$ext") \
&& openssl req -nodes -newkey rsa:2048 -keyout leaf-cert.key -out leaf-cert.csr -subj "/C=/ST=/L=/O=/OU=/CN=foobar.com" \
&& openssl x509 -req -CA intermediate.pem -CAkey intermediate.key -in leaf-cert.csr -out leaf-cert.pem -days 1550 -CAcreateserial

rm intermediate.srl intermediate.csr intermediate.key leaf-cert.csr root-ca.srl