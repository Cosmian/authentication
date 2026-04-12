#!/bin/bash
set -e

# Generate P-256 (secp256r1) certificates with PKCS#8 keys
echo "Generating P-256 (secp256r1) certificates with PKCS#8 keys..."

# Clean up old files
rm -f auth.root.key.pem auth.ca.pem auth.server.key.pem auth.server.cert.pem
rm -f auth.user1.key.pem auth.user1.cert.pem auth.user2.key.pem auth.user2.cert.pem
rm -f auth.user1.p12 auth.user2.p12
rm -f *.csr

# 1. Generate Root CA
echo "Generating Root CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out auth.root.key.pem
openssl req -new -x509 -days 3650 -key auth.root.key.pem -out auth.ca.pem \
    -subj "/CN=acme.com" \
    -addext "subjectAltName=IP:127.0.0.1" \
    -addext "basicConstraints=CA:TRUE,pathlen:0" \
    -addext "keyUsage = digitalSignature,cRLSign,keyCertSign" \
    -addext "extendedKeyUsage = serverAuth, clientAuth" \
    -addext "crlDistributionPoints=URI:https://acme.com/crl.pem"

# 2. Generate Server Certificate
echo "Generating Server Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out auth.server.key.pem
openssl req -new -key auth.server.key.pem -out server.csr \
    -subj "/CN=auth.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"

openssl x509 -req -sha256 -in server.csr -CA auth.ca.pem -CAkey auth.root.key.pem \
    -CAcreateserial -out auth.server.cert.pem -days 365 \
    -extfile <(cat server_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# 3. Generate User 1 Certificate
echo "Generating User 1 Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out auth.user1.key.pem
openssl req -new -key auth.user1.key.pem -out user1.csr \
    -subj "/CN=user1.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"
openssl x509 -req  -sha256 -in user1.csr -CA auth.ca.pem -CAkey auth.root.key.pem \
    -CAcreateserial -out auth.user1.cert.pem -days 365 \
    -extfile <(cat user_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# 4. Generate User 2 Certificate
echo "Generating User 2 Certificate..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out auth.user2.key.pem
openssl req -new -key auth.user2.key.pem -out user2.csr \
    -subj "/CN=user2.acme.com" \
    -addext "subjectAltName=IP:127.0.0.1"
openssl x509 -req  -sha256 -in user2.csr -CA auth.ca.pem -CAkey auth.root.key.pem \
    -CAcreateserial -out auth.user2.cert.pem -days 365 \
    -extfile <(cat user_extensions && echo "subjectAltName=IP:127.0.0.1") \
    -extensions v3_req

# Clean up CSR files
rm -f *.csr *.srl

# 5. Generate PKCS12 files for users
echo "Generating PKCS12 files..."
openssl pkcs12 -export -out auth.user1.p12 \
    -inkey auth.user1.key.pem \
    -in auth.user1.cert.pem \
    -certfile auth.ca.pem \
    -passout pass:secret

openssl pkcs12 -export -out auth.user2.p12 \
    -inkey auth.user2.key.pem \
    -in auth.user2.cert.pem \
    -certfile auth.ca.pem \
    -passout pass:secret

echo "Done! Generated P-256 certificates with PKCS#8 keys:"
echo "  Root CA: auth.ca.pem (key: auth.root.key.pem)"
echo "  Server: auth.server.cert.pem (key: auth.server.key.pem)"
echo "  User 1: auth.user1.cert.pem (key: auth.user1.key.pem, p12: auth.user1.p12)"
echo "  User 2: auth.user2.cert.pem (key: auth.user2.key.pem, p12: auth.user2.p12)"
echo "  PKCS12 password: secret"
