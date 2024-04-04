package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"net"
)

func SetupAES(conn net.Conn, sharedSecretServer []byte) (cipher.Stream, error) {
	block, blockErr := aes.NewCipher(sharedSecretServer)

	if blockErr != nil {
		fmt.Println("Creating Cipher Error:", blockErr)
		return nil, blockErr
	}

	iv := make([]byte, block.BlockSize())

	ivReadLen, err := readFromClient(conn, iv, block.BlockSize())
	if err != nil {
		panic(err)
	}

	iv = iv[:ivReadLen]

	if len(iv) < aes.BlockSize {
		return nil, fmt.Errorf("invalid IV length: ", len(iv))
	}

	fmt.Println("Received IV:", iv)

	stream := cipher.NewCFBDecrypter(block, iv)

	fmt.Println("Hello", conn.RemoteAddr())

	return stream, nil
}
