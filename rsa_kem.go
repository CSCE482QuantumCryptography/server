package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
)

func RSAKem(conn net.Conn) ([]byte, error) {

	fmt.Println("Reading client pub key")

	clientPubKeyBytes := make([]byte, 270)
	_, err := readFromClient(conn, clientPubKeyBytes, 270)
	if err != nil {
		return nil, err
	}

	fmt.Println("Parsing client pub key")

	clientPublicKey, err := x509.ParsePKCS1PublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, err
	}

	fmt.Println("Encaping secret")
	ciphertext, sharedSecretServer, err := EncapSecret(clientPublicKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("Cipher text len: ", len(ciphertext))

	// write cipher text to client
	conn.Write(ciphertext)

	fmt.Println("sharedSecret: ", sharedSecretServer)

	fmt.Println("Returning")

	return sharedSecretServer, nil

}

func EncapSecret(clientPublicKey *rsa.PublicKey) ([]byte, []byte, error) {
	sharedSecretServer := make([]byte, 32) // AES-256
	if _, err := rand.Read(sharedSecretServer); err != nil {
		return nil, nil, err
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, clientPublicKey, sharedSecretServer, nil)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, sharedSecretServer, nil
}
