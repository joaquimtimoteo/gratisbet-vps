package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const SERVER_VERSION = "5.0-direct-xor"

// ════════════════════════════════════════════════════════════════════
//                    CONFIGURAÇÕES
// ════════════════════════════════════════════════════════════════════

const (
	BUFFER_SIZE = 64 * 1024 // 64KB - máxima performance
)

// XOR Key - mesma do app Android
var XOR_KEY = []byte{0x47, 0x72, 0x61, 0x74, 0x69, 0x73, 0x42, 0x65, 0x74, 0x41, 0x6E, 0x67, 0x6F, 0x6C, 0x61, 0x21}

func xorData(data []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XOR_KEY[i%len(XOR_KEY)]
	}
	return result
}

// ════════════════════════════════════════════════════════════════════
//                    ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

var (
	activeConns   int64
	totalBytesIn  int64
	totalBytesOut int64
	totalTunnels  int64
	totalDNS      int64
)

// ════════════════════════════════════════════════════════════════════
//                         MAIN
// ════════════════════════════════════════════════════════════════════

func main() {
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  GRATISBET VPN SERVER v" + SERVER_VERSION)
	fmt.Println("  Túnel Direto + XOR Obfuscation")
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  TESTE: Se funcionar = máxima velocidade!")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		fmt.Printf("Erro: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 443 ativa")
	fmt.Println("  ✓ POST /tunnel    (DNS)")
	fmt.Println("  ✓ GET  /vpn-xor   (Túnel bidirecional + XOR)")
	fmt.Println("  ✓ GET  /stats")
	fmt.Println("══════════════════════════════════════════════")

	// Stats goroutine
	go func() {
		for {
			time.Sleep(30 * time.Second)
			in := atomic.LoadInt64(&totalBytesIn)
			out := atomic.LoadInt64(&totalBytesOut)
			conns := atomic.LoadInt64(&activeConns)
			tunnels := atomic.LoadInt64(&totalTunnels)
			dns := atomic.LoadInt64(&totalDNS)
			fmt.Printf("[STATS] Conns: %d | Tunnels: %d | DNS: %d | In: %.2f MB | Out: %.2f MB\n",
				conns, tunnels, dns, float64(in)/1024/1024, float64(out)/1024/1024)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}

		// Otimização TCP
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
			tc.SetReadBuffer(BUFFER_SIZE)
			tc.SetWriteBuffer(BUFFER_SIZE)
		}

		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	reader := bufio.NewReaderSize(conn, BUFFER_SIZE)

	// Ler primeira linha
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	path := parts[1]

	// Ler headers
	headers := make(map[string]string)
	contentLength := 0

	for {
		h, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(h) == "" {
			break
		}
		if idx := strings.Index(h, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(h[:idx]))
			val := strings.TrimSpace(h[idx+1:])
			headers[key] = val
			if key == "content-length" {
				fmt.Sscanf(val, "%d", &contentLength)
			}
		}
	}

	timestamp := time.Now().Format("15:04:05")

	switch {
	case path == "/vpn-xor" && method == "GET":
		// Túnel bidirecional com XOR!
		fmt.Printf("[%s] TUNNEL %s from %s\n", timestamp, path, remoteIP)
		handleVPNXor(conn, headers, remoteIP)

	case path == "/tunnel" && method == "POST":
		handleTunnel(conn, reader, contentLength, remoteIP)

	case path == "/stats":
		sendStats(conn)

	case path == "/ping" || path == "/":
		sendResponse(conn, 200, "text/plain", []byte("GratisBet VPN v"+SERVER_VERSION+" OK"))

	default:
		sendResponse(conn, 404, "text/plain", []byte("Not Found"))
	}
}

// ════════════════════════════════════════════════════════════════════
//                    TÚNEL BIDIRECIONAL COM XOR
// ════════════════════════════════════════════════════════════════════

func handleVPNXor(clientConn net.Conn, headers map[string]string, remoteIP string) {
	dest := headers["x-dest"]
	if dest == "" {
		sendResponse(clientConn, 400, "text/plain", []byte("Missing X-Dest"))
		return
	}

	fmt.Printf("[VPN-XOR] %s -> %s\n", remoteIP, dest)

	// Conectar ao destino
	serverConn, err := net.DialTimeout("tcp", dest, 15*time.Second)
	if err != nil {
		fmt.Printf("[VPN-XOR] Falha conexão: %v\n", err)
		sendResponse(clientConn, 502, "text/plain", []byte("Connection failed"))
		return
	}

	// Otimização TCP no servidor destino
	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
		tc.SetReadBuffer(BUFFER_SIZE)
		tc.SetWriteBuffer(BUFFER_SIZE)
	}

	// Enviar resposta OK - túnel estabelecido
	clientConn.Write([]byte("HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nX-XOR: 1\r\n\r\n"))

	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalTunnels, 1)
	fmt.Printf("[VPN-XOR] ✓ Túnel ativo: %s <-> %s\n", remoteIP, dest)

	var bytesIn, bytesOut int64
	var wg sync.WaitGroup
	wg.Add(2)

	// Cliente -> Servidor (XOR decode antes de enviar)
	go func() {
		defer wg.Done()
		buf := make([]byte, BUFFER_SIZE)
		for {
			clientConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := clientConn.Read(buf)
			if n > 0 {
				// Decodificar XOR
				decoded := xorData(buf[:n])
				
				serverConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				written, werr := serverConn.Write(decoded)
				if werr != nil {
					break
				}
				bytesOut += int64(written)
			}
			if err != nil {
				break
			}
		}
		serverConn.Close()
	}()

	// Servidor -> Cliente (XOR encode antes de enviar)
	go func() {
		defer wg.Done()
		buf := make([]byte, BUFFER_SIZE)
		for {
			serverConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := serverConn.Read(buf)
			if n > 0 {
				// Codificar XOR
				encoded := xorData(buf[:n])
				
				clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				written, werr := clientConn.Write(encoded)
				if werr != nil {
					break
				}
				bytesIn += int64(written)
			}
			if err != nil {
				break
			}
		}
		clientConn.Close()
	}()

	wg.Wait()

	atomic.AddInt64(&activeConns, -1)
	atomic.AddInt64(&totalBytesIn, bytesIn)
	atomic.AddInt64(&totalBytesOut, bytesOut)

	status := "✓"
	if bytesIn == 0 && bytesOut == 0 {
		status = "✗ BLOQUEADO?"
	}

	fmt.Printf("[VPN-XOR] %s Túnel fechado: %s (in:%d out:%d)\n", status, remoteIP, bytesIn, bytesOut)
}

// ════════════════════════════════════════════════════════════════════
//                    DNS TUNNEL
// ════════════════════════════════════════════════════════════════════

func handleTunnel(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	if contentLength <= 0 || contentLength > 65535 {
		sendResponse(conn, 400, "text/plain", []byte("Invalid content length"))
		return
	}

	body := make([]byte, contentLength)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.ReadFull(reader, body)
	if err != nil {
		return
	}

	if len(body) < 2 {
		return
	}

	destLen := int(body[0])<<8 | int(body[1])
	if destLen <= 0 || 2+destLen > len(body) {
		return
	}

	dest := string(body[2 : 2+destLen])
	data := body[2+destLen:]

	// DNS query
	if strings.HasSuffix(dest, ":53") {
		atomic.AddInt64(&totalDNS, 1)
		response := forwardUDP(dest, data)
		sendResponse(conn, 200, "application/octet-stream", response)
		return
	}

	sendResponse(conn, 400, "text/plain", []byte("Use /vpn-xor for TCP"))
}

func forwardUDP(dest string, data []byte) []byte {
	conn, err := net.DialTimeout("udp", dest, 5*time.Second)
	if err != nil {
		return []byte{}
	}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(data)
	if err != nil {
		return []byte{}
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 4096)
	n, err := conn.Read(response)
	if err != nil {
		return []byte{}
	}

	return response[:n]
}

// ════════════════════════════════════════════════════════════════════
//                    UTILS
// ════════════════════════════════════════════════════════════════════

func sendResponse(conn net.Conn, code int, contentType string, body []byte) {
	status := "OK"
	switch code {
	case 400:
		status = "Bad Request"
	case 404:
		status = "Not Found"
	case 502:
		status = "Bad Gateway"
	}

	header := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		code, status, contentType, len(body))

	conn.Write([]byte(header))
	if len(body) > 0 {
		conn.Write(body)
	}
}

func sendStats(conn net.Conn) {
	in := atomic.LoadInt64(&totalBytesIn)
	out := atomic.LoadInt64(&totalBytesOut)
	conns := atomic.LoadInt64(&activeConns)
	tunnels := atomic.LoadInt64(&totalTunnels)
	dns := atomic.LoadInt64(&totalDNS)

	stats := fmt.Sprintf(`{
  "version": "%s",
  "active_conns": %d,
  "total_tunnels": %d,
  "total_dns": %d,
  "bytes_in_mb": %.2f,
  "bytes_out_mb": %.2f,
  "goroutines": %d
}`, SERVER_VERSION, conns, tunnels, dns, float64(in)/1024/1024, float64(out)/1024/1024, runtime.NumGoroutine())

	sendResponse(conn, 200, "application/json", []byte(stats))
}
