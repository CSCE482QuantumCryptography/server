package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func CreateCsr() ([]byte, []byte, error) {
	// Initialize qs509 and Create signed certificate for the server
	qs509.Init(*opensslPath, *opensslCNFPath)

	var sa qs509.SignatureAlgorithm
	sa.Set(*signingAlg)

	signCsrStart := time.Now()
	_, err2 := qs509.GenerateCsr(sa, "server_private_key.key", "server_csr.csr")
	if err2 != nil {
		return nil, nil, err2
	}

	qs509.SignCsr("./server_csr.csr", "server_signed_crt.crt", *caCert, *caKey)
	signCsrEnd := time.Now()
	timeMap["signCsr"] = []time.Time{signCsrStart, signCsrEnd}

	// Read server certificate to bytes that can be sent to client
	serverCertFile, err := os.ReadFile("server_signed_crt.crt")
	if err != nil {
		return nil, nil, err
	}
	serverCertLen := make([]byte, 4)
	binary.BigEndian.PutUint32(serverCertLen, uint32(len(serverCertFile)))

	fmt.Println("Server Certificate Size: ", len(serverCertFile))

	return serverCertFile, serverCertLen, nil
}
