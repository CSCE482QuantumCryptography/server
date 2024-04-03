package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/CSCE482QuantumCryptography/qs509"
	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func readFromClient(conn net.Conn, buf []byte, readLen int) (int, error) {
	totalRead := 0
	for totalRead < readLen {
		n, err := conn.Read(buf[totalRead:])
		if err != nil {
			return 0, err
		}
		totalRead += n
	}
	return totalRead, nil

}

func main() {

	opensslPath := flag.String("openssl-path", "../../build/bin/openssl", "the path to openssl 3.3")
	opensslCNFPath := flag.String("openssl-cnf-path", "../../openssl/apps/openssl.cnf", "the path to openssl config")
	src := flag.String("src", "127.0.0.1:9080", "the path address being listened on")
	signingAlg := flag.String("sa", "DILITHIUM3", "the algorithm used to sign the client certificate")
	kemAlg := flag.String("ka", "Kyber512", "the algorithm used for generating shared secret")

	// Parse flags
	flag.Parse()

	qs509.Init(*opensslPath, *opensslCNFPath)

	var sa qs509.SignatureAlgorithm
	sa.Set(*signingAlg)

	_, err2 := qs509.GenerateCsr(sa, "server_private_key.key", "server_csr.csr")
	if err2 != nil {
		panic(err2.Error())
	}

	qs509.SignCsr("./server_csr.csr", "server_signed_crt.crt", "../qs509/etc/crt/dilithium3_CA.crt", "../qs509/etc/keys/dilithium3_CA.key")

	serverCertFile, err := os.ReadFile("server_signed_crt.crt")
	if err != nil {
		panic(err)
	}
	serverCertLen := make([]byte, 4)
	binary.BigEndian.PutUint32(serverCertLen, uint32(len(serverCertFile)))

	fmt.Println("Server Certificate Size: ", len(serverCertFile))

	ln, err := net.Listen("tcp", *src)

	if err != nil {
		panic(err)
	}

	fmt.Println("Started Listening on: ", *src)

	for {
		conn, err := ln.Accept()

		if err != nil {
			fmt.Errorf(
				"Error while handling request from",
				conn.RemoteAddr(),
				":",
				err,
			)
		}

		go func(conn net.Conn) {
			defer func() {
				fmt.Println(
					conn.RemoteAddr(),
					"Closed Connection",
				)

				conn.Close()
			}()

			// Cert Auth
			fmt.Println("Writing my Certificate to Client!")
			_, err = conn.Write(serverCertLen)
			if err != nil {
				panic(err)
			}

			_, err = conn.Write(serverCertFile)
			if err != nil {
				panic(err)
			}

			fmt.Println("Reading Client Certificate!")
			clientCertLenBytes := make([]byte, 4)
			_, err := readFromClient(conn, clientCertLenBytes, 4)
			if err != nil {
				panic(err)
			}

			clientCertLenInt := int(binary.BigEndian.Uint32(clientCertLenBytes))

			fmt.Println("Client Cert Size: ", clientCertLenInt)

			clientCertFile := make([]byte, clientCertLenInt)
			_, err = readFromClient(conn, clientCertFile, clientCertLenInt)
			if err != nil {
				panic(err)
			}

			isValid, err := qs509.VerifyCertificate("../qs509/etc/crt/dilithium3_CA.crt", clientCertFile)
			if err != nil {
				panic(err)
			}

			if !isValid {
				panic("I dont trust this client!")
			}

			fmt.Println("Verified Cert Certificate!")
			fmt.Println()

			// KEM
			kemName := *kemAlg
			server := oqs.KeyEncapsulation{}
			defer server.Clean() // clean up even in case of panic

			if err := server.Init(kemName, nil); err != nil {
				panic(err)
			}

			clientPubKey := make([]byte, server.Details().LengthPublicKey)
			_, err = readFromClient(conn, clientPubKey, server.Details().LengthPublicKey)
			if err != nil {
				panic(err)
			}

			fmt.Println("Received client public key!")

			ciphertext, sharedSecretServer, err := server.EncapSecret(clientPubKey)
			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("Sending client shared secret in cipher!")

			conn.Write(ciphertext)

			// AES
			block, blockErr := aes.NewCipher(sharedSecretServer)

			if blockErr != nil {
				fmt.Println("Creating Cipher Error:", blockErr)
				return
			}

			iv := make([]byte, block.BlockSize())

			ivReadLen, err := readFromClient(conn, iv, block.BlockSize())
			if err != nil {
				panic(err)
			}

			iv = iv[:ivReadLen]

			if len(iv) < aes.BlockSize {
				fmt.Println("Invalid IV length:", len(iv))
				return
			}

			fmt.Println("Received IV:", iv)

			stream := cipher.NewCFBDecrypter(block, iv)

			fmt.Println("Hello", conn.RemoteAddr())

			buf := make([]byte, 4096)

			for {
				rLen, rErr := conn.Read(buf)

				if rErr == nil {
					stream.XORKeyStream(buf[:rLen], buf[:rLen])

					fmt.Println("Data:", string(buf[:rLen]), rLen)

					continue
				}

				if rErr == io.EOF {
					stream.XORKeyStream(buf[:rLen], buf[:rLen])

					fmt.Println("Data:", string(buf[:rLen]), rLen, "EOF -")

					break
				}

				fmt.Errorf(
					"Error while reading from",
					conn.RemoteAddr(),
					":",
					rErr,
				)
				break
			}
		}(conn)
	}
}
