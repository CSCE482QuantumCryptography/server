package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func CertAuth(conn net.Conn, serverCertLen []byte, serverCertFile []byte) (bool, error) {
	writeServerCertStart := time.Now()
	fmt.Println("Writing my Certificate to Client!")
	_, err := conn.Write(serverCertLen)
	if err != nil {
		return false, err
	}

	_, err = conn.Write(serverCertFile)
	if err != nil {
		return false, err
	}
	writeServerCertEnd := time.Now()
	timeMap["writeServerCert"] = []time.Time{writeServerCertStart, writeServerCertEnd}

	fmt.Println("Reading Client Certificate!")
	clientCertLenBytes := make([]byte, 4)

	readClientCertStart := time.Now()
	_, err = readFromClient(conn, clientCertLenBytes, 4)
	if err != nil {
		return false, err
	}

	clientCertLenInt := int(binary.BigEndian.Uint32(clientCertLenBytes))

	fmt.Println("Client Cert Size: ", clientCertLenInt)

	clientCertFile := make([]byte, clientCertLenInt)
	_, err = readFromClient(conn, clientCertFile, clientCertLenInt)
	if err != nil {
		return false, err
	}
	readClientCertEnd := time.Now()
	timeMap["readClientCert"] = []time.Time{readClientCertStart, readClientCertEnd}

	verifyClientCertStart := time.Now()
	isValid, err := qs509.VerifyCertificate(*caCert, clientCertFile)
	if err != nil {
		return false, err
	}

	if !isValid {
		panic("I dont trust this client!")
	}
	verifyClientCertEnd := time.Now()
	timeMap["verifyClientCert"] = []time.Time{verifyClientCertStart, verifyClientCertEnd}

	fmt.Println("Verified Cert Certificate!")
	fmt.Println()

	return true, nil
}
