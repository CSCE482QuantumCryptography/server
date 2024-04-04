package main

import (
	"fmt"
	"net"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func OqsKem(conn net.Conn) ([]byte, error) {
	server := oqs.KeyEncapsulation{}
	defer server.Clean() // clean up even in case of panic

	if err := server.Init(*kemAlg, nil); err != nil {
		return nil, err
	}

	clientPubKey := make([]byte, server.Details().LengthPublicKey)

	readClientPubKeyStart := time.Now()
	_, err := readFromClient(conn, clientPubKey, server.Details().LengthPublicKey)
	if err != nil {
		return nil, err
	}
	readClientPubKeyEnd := time.Now()
	timeMap["readClientPubKey"] = []time.Time{readClientPubKeyStart, readClientPubKeyEnd}

	fmt.Println("Received client public key!")

	encapSecretStart := time.Now()
	ciphertext, sharedSecretServer, err := server.EncapSecret(clientPubKey)
	if err != nil {
		return nil, err
	}
	encapSecretEnd := time.Now()
	timeMap["encapSecret"] = []time.Time{encapSecretStart, encapSecretEnd}

	fmt.Println("Sending client shared secret in cipher!")

	sendCipherStart := time.Now()
	conn.Write(ciphertext)
	sendCipherEnd := time.Now()

	timeMap["sendCipher"] = []time.Time{sendCipherStart, sendCipherEnd}

	return sharedSecretServer, nil
}
