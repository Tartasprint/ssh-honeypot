#!/bin/sh

echo Generating CA
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -sha256 -key ca.key -out ca.crt

generate_leaf(){
	openssl ecparam -name prime256v1 -genkey -noout -out "$1".key
	openssl req -new -sha256 -key "$1".key -out "$1".csr
	openssl x509 -req -in "$1".csr -CA ca.crt -CAkey ca.key -CAcreateserial -out "$1".crt -days 1000 -sha256
}

echo Generating Server
generate_leaf server

echo Generating Client
generate_leaf client
# openssl s_client -connect 127.0.0.1:8888 -cert client.crt -key client.key
