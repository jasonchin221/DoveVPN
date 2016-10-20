#!/bin/bash

#dir=`dirname $0`
#cd $dir
key_bits=2048
expire_days=10950
subj=/C="CN"/ST="Liaoning"/L="Shenyang"/O="Dove"/OU="dove"/CN="dove"
subj2=/C="CN"/ST="Liaoning"/L="Shenyang"/O="DoveCERT"/OU="dove"/CN="dove"
if [ $# -eq 0 ]; then
#Root
openssl genrsa -out ca.key $key_bits
openssl req -x509 -newkey rsa:$key_bits -keyout ca.key -nodes -out ca.cer -subj $subj -days $expire_days
else
#Client
openssl genrsa -out client.key $key_bits
openssl req -new -key client.key -sha256 -out client.csr -subj $subj2 -days $expire_days
openssl x509 -req -in client.csr -sha256 -out client.cer -CA ca.cer -CAkey ca.key -CAserial t_ssl_ca.srl -CAcreateserial -days $expire_days -extensions v3_req
#openssl pkcs12 -export -clcerts -in client.cer -inkey client.key -out client.p12
#Server
openssl genrsa -out server.key $key_bits
openssl req -new -key server.key -sha256 -out server.csr -subj $subj2 -days $expire_days
openssl x509 -req -in server.csr -sha256 -out server.cer -CA ca.cer -CAkey ca.key -CAserial t_ssl_ca.srl -CAcreateserial -days $expire_days -extensions v3_req
rm -f *.csr *.srl
fi
# openssl verify -CAfile ca.cer client.cer
