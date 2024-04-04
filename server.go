package main

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/CSCE482QuantumCryptography/qs509"
)

func main() {

	// Create file for benchmark results
	fileOut := "../" + *signingAlg + "_" + *kemAlg + ".xlsx"
	qs509.CreateFile(fileOut)

	totalTimeStart := time.Now()

	// Create and sign certificate for main
	serverCertFile, serverCertLen, err := CreateCsr()
	if err != nil {
		panic(err)
	}

	// Listen for client connections
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

			// Cert Auth
			certAuthStart := time.Now()
			_, err := CertAuth(conn, serverCertLen, serverCertFile)
			if err != nil {
				panic(err)
			}
			certAuthEnd := time.Now()
			timeMap["certAuth"] = []time.Time{certAuthStart, certAuthEnd}

			// KEM
			kemStart := time.Now()
			sharedSecretServer, err := OqsKem(conn)
			if err != nil {
				panic(err)
			}
			kemEnd := time.Now()
			timeMap["kem"] = []time.Time{kemStart, kemEnd}

			// AES
			aesStart := time.Now()
			stream, err := SetupAES(conn, sharedSecretServer)
			if err != nil {
				panic(err)
			}
			aesEnd := time.Now()

			timeMap["aes"] = []time.Time{aesStart, aesEnd}

			totalTimeEnd := time.Now()
			timeMap["TotalTime"] = []time.Time{totalTimeStart, totalTimeEnd}

			buf := make([]byte, 4096)

			// Constantly read messages from the client
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
