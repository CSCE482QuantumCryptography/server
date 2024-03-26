package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {

	ln, err := net.Listen("tcp", "127.0.0.1:9080")

	if err != nil {
		panic(err)
	}

	fmt.Println("Started Listening")

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

			// KEM
			kemName := "Kyber512"
			clientPubKey := make([]byte, 800)
			_, pubKeyReadErr := conn.Read(clientPubKey)

			if pubKeyReadErr != nil {
				panic("Error reading client public key!")
			}

			fmt.Println("Received client public key!")

			server := oqs.KeyEncapsulation{}
			defer server.Clean() // clean up even in case of panic

			if err := server.Init(kemName, nil); err != nil {
				panic(err)
			}

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

			iv := make([]byte, 32)

			ivReadLen, ivReadErr := conn.Read(iv)

			if ivReadErr != nil {
				fmt.Println("Can't read IV:", ivReadErr)

				return
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
