package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const SERVER_VERSION = "5.0-kaiho-style"

// ════════════════════════════════════════════════════════════════════
//                    CONFIGURAÇÕES
// ════════════════════════════════════════════════════════════════════

const (
	LISTEN_PORT    = ":82"
	BUFFER_SIZE    = 64 * 1024
	CONN_TIMEOUT   = 30 * time.Second
	RELAY_TIMEOUT  = 5 * time.Minute
)

var (
	activeConns   int64
	totalConns    int64
	totalBytes    int64
	startTime     = time.Now()
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  GRATISBET PROXY v" + SERVER_VERSION)
	fmt.Println("  HTTP CONNECT + SNI Style")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", LISTEN_PORT)
	if err != nil {
		fmt.Printf("Erro ao iniciar: %v\n", err)
		return
	}

	fmt.Printf("  ✓ Porta %s ativa\n", LISTEN_PORT)
	fmt.Println("  ✓ Método: HTTP CONNECT Proxy")
	fmt.Println("  ✓ SNI: Preservado do cliente")
	fmt.Println("══════════════════════════════════════════════")

	// Stats
	go func() {
		for {
			time.Sleep(30 * time.Second)
			mb := float64(atomic.LoadInt64(&totalBytes)) / 1024 / 1024
			active := atomic.LoadInt64(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			fmt.Printf("[STATS] Active: %d | Total: %d | %.2f MB\n", active, total, mb)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	// Configurar TCP
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
	}

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(CONN_TIMEOUT))

	// Ler primeira linha (ex: CONNECT google.com:443 HTTP/1.1)
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Parse da requisição
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	method := strings.ToUpper(parts[0])
	target := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(strings.ToLower(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	clientConn.SetReadDeadline(time.Time{})

	// Log
	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

	switch method {
	case "CONNECT":
		// Método CONNECT - túnel direto
		handleConnect(clientConn, target, clientIP)

	default:
		// Outros métodos (GET, POST, etc) - proxy HTTP
		handleHTTPProxy(clientConn, reader, method, target, headers, clientIP)
	}
}

// ════════════════════════════════════════════════════════════════════
//                    CONNECT TUNNEL
// ════════════════════════════════════════════════════════════════════

func handleConnect(clientConn net.Conn, target string, clientIP string) {
	// Garantir que tem porta
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	fmt.Printf("[CONNECT] %s -> %s\n", clientIP, target)

	// Conectar ao destino
	serverConn, err := net.DialTimeout("tcp", target, CONN_TIMEOUT)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	// Configurar TCP
	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
	}

	// Responder 200 OK
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay bidirecional
	relay(clientConn, serverConn)
}

// ════════════════════════════════════════════════════════════════════
//                    HTTP PROXY
// ════════════════════════════════════════════════════════════════════

func handleHTTPProxy(clientConn net.Conn, reader *bufio.Reader, method, target string, headers map[string]string, clientIP string) {
	// Extrair host do target ou header
	host := headers["host"]
	if host == "" {
		// Tentar extrair do URL
		if strings.HasPrefix(target, "http://") {
			target = target[7:]
			if idx := strings.Index(target, "/"); idx > 0 {
				host = target[:idx]
				target = target[idx:]
			} else {
				host = target
				target = "/"
			}
		}
	}

	if host == "" {
		return
	}

	// Adicionar porta se não tiver
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	fmt.Printf("[HTTP] %s -> %s%s\n", clientIP, host, target)

	// Conectar ao servidor
	serverConn, err := net.DialTimeout("tcp", host, CONN_TIMEOUT)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	// Reenviar request
	request := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, target)
	for k, v := range headers {
		request += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	request += "\r\n"

	serverConn.Write([]byte(request))

	// Relay
	relay(clientConn, serverConn)
}

// ════════════════════════════════════════════════════════════════════
//                    RELAY
// ════════════════════════════════════════════════════════════════════

func relay(client, server net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Server
	go func() {
		defer wg.Done()
		n, _ := copyBuffer(server, client)
		atomic.AddInt64(&totalBytes, n)
		server.(*net.TCPConn).CloseWrite()
	}()

	// Server -> Client
	go func() {
		defer wg.Done()
		n, _ := copyBuffer(client, server)
		atomic.AddInt64(&totalBytes, n)
		client.(*net.TCPConn).CloseWrite()
	}()

	wg.Wait()
}

func copyBuffer(dst, src net.Conn) (int64, error) {
	buf := make([]byte, BUFFER_SIZE)
	var total int64

	for {
		src.SetReadDeadline(time.Now().Add(RELAY_TIMEOUT))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}
