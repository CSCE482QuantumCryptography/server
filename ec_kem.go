package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

func ECKem(conn net.Conn) ([]byte, error) {

	fmt.Println("Reading in client pub key!")

	clientPubKeyBytes := make([]byte, 65)

	readClientKeyStart := time.Now()
	_, err := readFromClient(conn, clientPubKeyBytes, 65)
	if err != nil {
		return nil, err
	}
	readClientKeyEnd := time.Now()
	timeMap["readClientKey"] = []time.Time{readClientKeyStart, readClientKeyEnd}

	clientPubECDHKey, err := ecdh.P256().NewPublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, err
	}

	fmt.Println("Creating server key pair!")

	genECKeyPairStart := time.Now()
	serverPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serverPubKey := serverPrivKey.PublicKey
	genECKeyPairEnd := time.Now()
	timeMap["genECKeyPair"] = []time.Time{genECKeyPairStart, genECKeyPairEnd}

	fmt.Println("Sending pub key to client!")

	serverPubECDHKey, err := serverPubKey.ECDH()
	if err != nil {
		return nil, err
	}
	fmt.Println("Server ecdh len: ", len(serverPubECDHKey.Bytes()))

	writeServerKeyStart := time.Now()
	conn.Write(serverPubECDHKey.Bytes())
	writeServerKeyEnd := time.Now()
	timeMap["writeServerKey"] = []time.Time{writeServerKeyStart, writeServerKeyEnd}

	fmt.Println("Getting shared secret!")

	serverPrivECDHKey, _ := serverPrivKey.ECDH()

	genSecretStart := time.Now()
	serverSharedSecret, err := serverPrivECDHKey.ECDH(clientPubECDHKey)
	if err != nil {
		return nil, err
	}
	genSecretEnd := time.Now()
	timeMap["genSecret"] = []time.Time{genSecretStart, genSecretEnd}

	return serverSharedSecret, nil

}
