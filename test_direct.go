
package main

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

func main() {
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  MODO DIRETO - HTTP:80")
	fmt.Println("════════════════════════════════════════")

	listener, _ := net.Listen("tcp", ":80")
	fmt.Println("  Porta 80 ativa...")

	for {
		conn, _ := listener.Accept()
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	fmt.Printf("[%s] CONN %s\n", time.Now().Format("15:04:05"), remote)

	reader := bufio.NewReader(conn)
	var path string
	
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "GET ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				path = parts[1]
			}
		}
	}

	var body string
	if strings.Contains(path, "bytes=") {
		parts := strings.Split(path, "bytes=")
		if len(parts) >= 2 {
			size := parts[1]
			switch size {
			case "100":
				body = "OK:" + strings.Repeat("A", 97)
			case "1000":
				body = "OK:" + strings.Repeat("B", 997)
			case "10000":
				body = "OK:" + strings.Repeat("C", 9997)
			case "50000":
				body = "OK:" + strings.Repeat("D", 49997)
			case "100000":
				body = "OK:" + strings.Repeat("E", 99997)
			case "500000":
				body = "OK:" + strings.Repeat("F", 499997)
			case "1000000":
				body = "OK:" + strings.Repeat("G", 999997)
			default:
				body = "USE: bytes=100|1000|10000|50000|100000|500000|1000000"
			}
		}
	} else if path == "/ping" {
		body = "PONG"
	} else {
		body = "GRATISBET-OK"
	}

	response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	conn.Write([]byte(response))
	fmt.Printf("[%s] SENT %d bytes\n", time.Now().Format("15:04:05"), len(body))
}
