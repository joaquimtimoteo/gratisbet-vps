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
	fmt.Println("  TEST MODO DIRETO - PORTA 80")
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  Payload esperado:")
	fmt.Println("  GET / HTTP/1.1")
	fmt.Println("  Host: saldo.unitel.ao")
	fmt.Println("  Upgrade: websocket")
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
	
	// Ler headers
	var headers []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("[%s] Erro lendo: %v\n", time.Now().Format("15:04:05"), err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		headers = append(headers, line)
		fmt.Printf("[%s] > %s\n", time.Now().Format("15:04:05"), line)
	}

	// Verificar se é upgrade websocket
	isUpgrade := false
	for _, h := range headers {
		if strings.Contains(strings.ToLower(h), "upgrade: websocket") {
			isUpgrade = true
		}
	}

	if isUpgrade {
		fmt.Printf("[%s] ✅ WebSocket upgrade detectado!\n", time.Now().Format("15:04:05"))
		
		// Responder com upgrade aceite
		response := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		conn.Write([]byte(response))
		
		fmt.Printf("[%s] ✅ Túnel estabelecido!\n", time.Now().Format("15:04:05"))
		
		// Manter conexão aberta e ecoar dados
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := reader.Read(buf)
			if err != nil {
				fmt.Printf("[%s] Conexão fechada: %v\n", time.Now().Format("15:04:05"), err)
				return
			}
			fmt.Printf("[%s] Recebido %d bytes\n", time.Now().Format("15:04:05"), n)
			
			// Echo de volta
			conn.Write(buf[:n])
		}
	} else {
		// Resposta HTTP normal
		response := "HTTP/1.1 200 OK\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Length: 17\r\n\r\n" +
			"GRATISBET-DIRECT!"
		conn.Write([]byte(response))
		fmt.Printf("[%s] Resposta HTTP enviada\n", time.Now().Format("15:04:05"))
	}
}
