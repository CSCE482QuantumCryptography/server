package main

import "net"

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
