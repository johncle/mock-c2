#!/usr/bin/env bash
CERT_DIR=cert
SUBJECT="/C=US/ST=CA/L=SanFrancisco/O=ZeroTen"

# generate CA key
openssl genrsa -out "${CERT_DIR}/ca.key" 4096
# generate CA cert
openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" -sha256 -days 365 \
-out "${CERT_DIR}/ca.crt" -subj "$SUBJECT"

# generate server key
openssl genrsa -out "${CERT_DIR}/server.key" 2048
# generate server cert signing request (CSR)
openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" \
-subj "$SUBJECT"

# create config file for Subject Alternative Names (SAN)
tee "${CERT_DIR}/server.ext" > /dev/null << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
# add your C2 IPs here as "IP.N = AAA.BBB.CCC.DDD"
DNS.1 = localhost
EOF

# sign CSR with CA
openssl x509 -req -in "${CERT_DIR}/server.csr" -CA "${CERT_DIR}/ca.crt" \
-CAkey "${CERT_DIR}/ca.key" -CAcreateserial -out "${CERT_DIR}/server.crt" \
-days 365 -sha256 -extfile "${CERT_DIR}/server.ext" -subj "$SUBJECT"

# generate reverse shell cert and key
openssl req -x509 -newkey rsa:4096 -keyout "${CERT_DIR}/key.pem" \
-out "${CERT_DIR}/cert.pem" -sha256 -days 365 -subj "$SUBJECT"
