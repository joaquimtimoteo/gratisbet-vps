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
	fmt.Println("  Host: saldo.unitel.ao")
	fmt.Println("════════════════════════════════════════")

	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Println("Erro:", err)
		return
	}
	fmt.Println("  Porta 80 ativa...")
	fmt.Println("")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	
	remote := conn.RemoteAddr().String()
	fmt.Printf("[%s] CONEXÃO de %s\n", time.Now().Format("15:04:05"), remote)

	reader := bufio.NewReader(conn)
	
	var headers []string
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
		headers = append(headers, line)
		fmt.Printf("[%s] > %s\n", time.Now().Format("15:04:05"), line)
		
		if strings.HasPrefix(line, "GET ") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 {
				path = parts[1]
			}
		}
	}

	// Verificar upgrade websocket
	isUpgrade := false
	for _, h := range headers {
		if strings.Contains(strings.ToLower(h), "upgrade: websocket") {
			isUpgrade = true
		}
	}

	if isUpgrade {
		fmt.Printf("[%s] ✅ WebSocket!\n", time.Now().Format("15:04:05"))
		response := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
		conn.Write([]byte(response))
		
		// Manter túnel aberto
		buf := make([]byte, 65536)
		for {
			conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Printf("[%s] Túnel fechado\n", time.Now().Format("15:04:05"))
				return
			}
			fmt.Printf("[%s] Recebido %d bytes no túnel\n", time.Now().Format("15:04:05"), n)
			conn.Write(buf[:n]) // Echo
		}
	} else {
		// Resposta HTTP baseada no path
		var body string
		
		if strings.Contains(path, "bytes=") {
			// Extrair tamanho
			parts := strings.Split(path, "bytes=")
			if len(parts) >= 2 {
				size := parts[1]
				switch size {
				case "100":
					body = "OK100:" + strings.Repeat("A", 94)
				case "500":
					body = "OK500:" + strings.Repeat("B", 494)
				case "1000":
					body = "OK1K:" + strings.Repeat("C", 995)
				case "5000":
					body = "OK5K:" + strings.Repeat("D", 4995)
				case "10000":
					body = "OK10K:" + strings.Repeat("E", 9995)
				case "50000":
					body = "OK50K:" + strings.Repeat("F", 49995)
				case "100000":
					body = "OK100K:" + strings.Repeat("G", 99993)
				default:
					body = "USE: bytes=100|500|1000|5000|10000|50000|100000"
				}
			}
		} else if path == "/ping" {
			body = "PONG"
		} else {
			body = "GRATISBET-DIRECT-OK"
		}

		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		conn.Write([]byte(response))
		fmt.Printf("[%s] Enviado %d bytes\n", time.Now().Format("15:04:05"), len(body))
	}
}
