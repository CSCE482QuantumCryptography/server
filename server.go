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
	"time"

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

	timeMap := make(map[string][]time.Time)

	opensslPath := flag.String("openssl-path", "../../build/bin/openssl", "the path to openssl 3.3")
	opensslCNFPath := flag.String("openssl-cnf-path", "../../openssl/apps/openssl.cnf", "the path to openssl config")
	src := flag.String("src", "127.0.0.1:9080", "the path address being listened on")
	signingAlg := flag.String("sa", "DILITHIUM3", "the algorithm used to sign the client certificate")
	kemAlg := flag.String("ka", "Kyber512", "the algorithm used for generating shared secret")

	// Parse flags
	flag.Parse()

	fileOut := "../" + *signingAlg + "_" + *kemAlg + ".xlsx"
	qs509.CreateFile(fileOut)

	totalTimeStart := time.Now()

	qs509.Init(*opensslPath, *opensslCNFPath)

	var sa qs509.SignatureAlgorithm
	sa.Set(*signingAlg)

	signCsrStart := time.Now()
	_, err2 := qs509.GenerateCsr(sa, "server_private_key.key", "server_csr.csr")
	if err2 != nil {
		panic(err2.Error())
	}

	qs509.SignCsr("./server_csr.csr", "server_signed_crt.crt", "../qs509/etc/crt/dilithium3_CA.crt", "../qs509/etc/keys/dilithium3_CA.key")
	signCsrEnd := time.Now()
	timeMap["signCsr"] = []time.Time{signCsrStart, signCsrEnd}

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

				fmt.Println("writing to file")
				qs509.BenchmarkMap(timeMap, *signingAlg, *kemAlg, fileOut, "server")

				conn.Close()
			}()

			writeServerCertStart := time.Now()
			// Cert Auth
			certAuthStart := time.Now()

			fmt.Println("Writing my Certificate to Client!")
			_, err = conn.Write(serverCertLen)
			if err != nil {
				panic(err)
			}

			_, err = conn.Write(serverCertFile)
			if err != nil {
				panic(err)
			}
			writeServerCertEnd := time.Now()
			timeMap["writeServerCert"] = []time.Time{writeServerCertStart, writeServerCertEnd}

			fmt.Println("Reading Client Certificate!")
			clientCertLenBytes := make([]byte, 4)

			readClientCertStart := time.Now()
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
			readClientCertEnd := time.Now()
			timeMap["readClientCert"] = []time.Time{readClientCertStart, readClientCertEnd}

			verifyClientCertStart := time.Now()
			isValid, err := qs509.VerifyCertificate("../qs509/etc/crt/dilithium3_CA.crt", clientCertFile)
			if err != nil {
				panic(err)
			}

			if !isValid {
				panic("I dont trust this client!")
			}
			verifyClientCertEnd := time.Now()
			timeMap["verifyClientCert"] = []time.Time{verifyClientCertStart, verifyClientCertEnd}

			fmt.Println("Verified Cert Certificate!")
			fmt.Println()

			certAuthEnd := time.Now()
			timeMap["certAuth"] = []time.Time{certAuthStart, certAuthEnd}

			// KEM
			kemStart := time.Now()

			kemName := *kemAlg
			server := oqs.KeyEncapsulation{}
			defer server.Clean() // clean up even in case of panic

			if err := server.Init(kemName, nil); err != nil {
				panic(err)
			}

			clientPubKey := make([]byte, server.Details().LengthPublicKey)

			readClientPubKeyStart := time.Now()
			_, err = readFromClient(conn, clientPubKey, server.Details().LengthPublicKey)
			if err != nil {
				panic(err)
			}
			readClientPubKeyEnd := time.Now()
			timeMap["readClientPubKey"] = []time.Time{readClientPubKeyStart, readClientPubKeyEnd}

			fmt.Println("Received client public key!")

			encapSecretStart := time.Now()
			ciphertext, sharedSecretServer, err := server.EncapSecret(clientPubKey)
			if err != nil {
				log.Fatal(err)
			}
			encapSecretEnd := time.Now()
			timeMap["encapSecret"] = []time.Time{encapSecretStart, encapSecretEnd}

			fmt.Println("Sending client shared secret in cipher!")

			sendCipherStart := time.Now()
			conn.Write(ciphertext)
			sendCipherEnd := time.Now()

			timeMap["sendCipher"] = []time.Time{sendCipherStart, sendCipherEnd}

			kemEnd := time.Now()
			timeMap["kem"] = []time.Time{kemStart, kemEnd}

			// AES
			aesStart := time.Now()

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

			aesEnd := time.Now()
			timeMap["aes"] = []time.Time{aesStart, aesEnd}

			totalTimeEnd := time.Now()
			timeMap["TotalTime"] = []time.Time{totalTimeStart, totalTimeEnd}

			for {

				readEncryptedMsgStart := time.Now()
				rLen, rErr := conn.Read(buf)
				readEncryptedMsgEnd := time.Now()
				timeMap["readEncryptedMsg"] = []time.Time{readEncryptedMsgStart, readEncryptedMsgEnd}

				if rErr == nil {
					decryptMsgStart := time.Now()
					stream.XORKeyStream(buf[:rLen], buf[:rLen])
					decryptMsgEnd := time.Now()
					timeMap["decryptMsg"] = []time.Time{decryptMsgStart, decryptMsgEnd}

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
