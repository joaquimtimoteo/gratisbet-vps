package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

/*
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v7.0 - HÍBRIDO                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Suporta AMBOS os protocolos:                                                 ║
║                                                                               ║
║  1. WebSocket /vpn    → App GratisBet (protocolo atual)                      ║
║  2. HTTP CONNECT      → HTTP Injector / SI Connect (SSH)                     ║
║                                                                               ║
║  Assim podemos testar os dois ao mesmo tempo!                                ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/

var config = struct {
	IP  string
	SNI string
}{
	IP:  "216.106.176.133",
	SNI: "www.signup.ao",
}

var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

var stats = struct {
	connections  int64
	wsConnections int64
	sshBridges   int64
	bytesIn      int64
	bytesOut     int64
}{}

// ============================================
// VPN WebSocket (para app GratisBet)
// ============================================
const (
	VPN_SEND_DELAY = 50 * time.Millisecond
	VPN_MAX_CHUNK  = 200
)

type VPNSession struct {
	conn     net.Conn
	streams  map[uint16]net.Conn
	mu       sync.RWMutex
	writeMu  sync.Mutex
	lastSend time.Time
}

func (s *VPNSession) sendFrame(id uint16, data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	elapsed := time.Since(s.lastSend)
	if elapsed < VPN_SEND_DELAY {
		time.Sleep(VPN_SEND_DELAY - elapsed)
	}

	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)

	writeWSFrame(s.conn, frame)
	s.lastSend = time.Now()
	logger.Printf("[VPN-TX] id=%d len=%d", id, len(data))
}

func handleVPNWebSocket(conn net.Conn, wsKey string) {
	atomic.AddInt64(&stats.wsConnections, 1)
	
	// WebSocket handshake
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(wsKey + magic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

	conn.Write([]byte(response))
	logger.Printf("[VPN] ✅ WebSocket upgrade OK")

	s := &VPNSession{
		conn:     conn,
		streams:  make(map[uint16]net.Conn),
		lastSend: time.Now(),
	}

	for {
		frame, err := readWSFrame(conn)
		if err != nil {
			break
		}
		if len(frame) < 4 {
			continue
		}

		id := binary.BigEndian.Uint16(frame[0:2])
		length := binary.BigEndian.Uint16(frame[2:4])
		data := frame[4 : 4+length]

		logger.Printf("[VPN-RX] id=%d len=%d", id, length)

		s.mu.RLock()
		target := s.streams[id]
		s.mu.RUnlock()

		// CONNECT
		if target == nil && len(data) >= 4 {
			port := binary.BigEndian.Uint16(data[1:3])
			hostLen := data[3]
			host := string(data[4 : 4+hostLen])
			logger.Printf("[VPN-CONNECT] %s:%d", host, port)

			target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
			if err != nil {
				s.sendFrame(id, []byte{0x01})
				continue
			}

			s.mu.Lock()
			s.streams[id] = target
			s.mu.Unlock()

			s.sendFrame(id, []byte{0x00})

			go func(id uint16, t net.Conn) {
				defer func() {
					s.sendFrame(id, []byte{})
					s.mu.Lock()
					delete(s.streams, id)
					s.mu.Unlock()
					t.Close()
				}()

				buf := make([]byte, VPN_MAX_CHUNK)
				for {
					t.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := t.Read(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						break
					}
					if n > 0 {
						s.sendFrame(id, buf[:n])
					}
				}
			}(id, target)

		} else if target != nil {
			if len(data) == 0 {
				target.Close()
				s.mu.Lock()
				delete(s.streams, id)
				s.mu.Unlock()
			} else {
				target.Write(data)
			}
		}
	}

	s.mu.Lock()
	for _, t := range s.streams {
		t.Close()
	}
	s.mu.Unlock()
	logger.Printf("[VPN] Desconectado")
}

// ============================================
// WebSocket helpers
// ============================================
func readWSFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	if length == 126 {
		ext := make([]byte, 2)
		io.ReadFull(conn, ext)
		length = int(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		io.ReadFull(conn, ext)
		length = int(binary.BigEndian.Uint64(ext))
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		io.ReadFull(conn, mask)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return payload, nil
}

func writeWSFrame(conn net.Conn, data []byte) error {
	length := len(data)
	var header []byte

	if length < 126 {
		header = []byte{0x82, byte(length)}
	} else if length < 65536 {
		header = []byte{0x82, 126, byte(length >> 8), byte(length)}
	} else {
		header = make([]byte, 10)
		header[0] = 0x82
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	conn.Write(header)
	_, err := conn.Write(data)
	return err
}

// ============================================
// SSH Bridge (para HTTP Injector)
// ============================================
func handleCONNECT(conn net.Conn, reader *bufio.Reader, target string) {
	logger.Printf("[CONNECT] Target: %s", target)
	
	atomic.AddInt64(&stats.sshBridges, 1)
	
	destHost := "127.0.0.1"
	destPort := "22"
	
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) == 2 {
			if parts[0] != "" && parts[0] != config.IP {
				destHost = parts[0]
			}
			destPort = parts[1]
		}
	}
	
	// Se for nosso IP, redirecionar para SSH local
	if destHost == config.IP {
		destHost = "127.0.0.1"
	}
	
	destination := fmt.Sprintf("%s:%s", destHost, destPort)
	logger.Printf("[CONNECT] Conectando a %s", destination)
	
	destConn, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		logger.Printf("[CONNECT] ❌ Falha: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()
	
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	logger.Printf("[CONNECT] ✅ Túnel estabelecido para %s", destination)
	
	conn.SetDeadline(time.Now().Add(10 * time.Minute))
	destConn.SetDeadline(time.Now().Add(10 * time.Minute))
	
	// Dados buffered
	buffered := reader.Buffered()
	if buffered > 0 {
		data := make([]byte, buffered)
		n, _ := reader.Read(data)
		if n > 0 {
			destConn.Write(data[:n])
			logger.Printf("[CONNECT] Enviou %d bytes buffered", n)
		}
	}
	
	done := make(chan struct{}, 2)
	
	go func() {
		n, _ := io.Copy(destConn, reader)
		atomic.AddInt64(&stats.bytesIn, n)
		logger.Printf("[CONNECT] Cliente→Destino: %d bytes", n)
		done <- struct{}{}
	}()
	
	go func() {
		n, _ := io.Copy(conn, destConn)
		atomic.AddInt64(&stats.bytesOut, n)
		logger.Printf("[CONNECT] Destino→Cliente: %d bytes", n)
		done <- struct{}{}
	}()
	
	<-done
	logger.Printf("[CONNECT] Túnel encerrado")
}

// ============================================
// Handler Principal
// ============================================
func handleConnection(conn net.Conn) {
	defer conn.Close()
	
	clientIP := conn.RemoteAddr().String()
	atomic.AddInt64(&stats.connections, 1)
	logger.Printf("[CONN] Nova conexão de %s", clientIP)

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)

	line, err := reader.ReadString('\n')
	if err != nil {
		logger.Printf("[ERR] Erro lendo request: %v", err)
		return
	}

	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	
	if len(parts) < 2 {
		logger.Printf("[ERR] Request inválido: %s", line)
		return
	}

	method := strings.ToUpper(parts[0])
	target := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil || headerLine == "\r\n" || headerLine == "\n" {
			break
		}
		if idx := strings.Index(headerLine, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(headerLine[:idx]))
			val := strings.TrimSpace(headerLine[idx+1:])
			headers[key] = val
		}
	}

	logger.Printf("[REQ] %s %s", method, target)

	conn.SetReadDeadline(time.Time{})

	// ============================================
	// ROTEAMENTO
	// ============================================
	
	// 1. HTTP CONNECT (HTTP Injector / SI Connect)
	if method == "CONNECT" {
		handleCONNECT(conn, reader, target)
		return
	}
	
	// 2. WebSocket upgrade para /vpn (App GratisBet)
	if strings.ToLower(headers["upgrade"]) == "websocket" {
		wsKey := headers["sec-websocket-key"]
		if wsKey == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}
		
		// Verificar auth
		auth := headers["x-auth"]
		if auth != "sung:123.456" {
			logger.Printf("[VPN] ❌ Auth falhou: %s", auth)
			conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
			return
		}
		
		handleVPNWebSocket(conn, wsKey)
		return
	}
	
	// 3. Health check
	if target == "/" || target == "/health" || target == "/status" {
		status := fmt.Sprintf(`{
  "status": "ok",
  "version": "7.0-hybrid",
  "protocols": ["websocket-vpn", "http-connect-ssh"],
  "stats": {
    "connections": %d,
    "websocket": %d,
    "ssh_bridges": %d,
    "bytes_in": %d,
    "bytes_out": %d
  }
}`,
			atomic.LoadInt64(&stats.connections),
			atomic.LoadInt64(&stats.wsConnections),
			atomic.LoadInt64(&stats.sshBridges),
			atomic.LoadInt64(&stats.bytesIn),
			atomic.LoadInt64(&stats.bytesOut))
		
		conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
		conn.Write([]byte("Content-Type: application/json\r\n"))
		conn.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", len(status))))
		conn.Write([]byte("\r\n"))
		conn.Write([]byte(status))
		return
	}
	
	// 4. Fallback - SSH bridge
	logger.Printf("[HTTP] Path desconhecido, tentando SSH bridge...")
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	
	ssh, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		logger.Printf("[SSH] ❌ Falha: %v", err)
		return
	}
	defer ssh.Close()
	
	atomic.AddInt64(&stats.sshBridges, 1)
	
	done := make(chan struct{}, 2)
	go func() { io.Copy(ssh, reader); done <- struct{}{} }()
	go func() { io.Copy(conn, ssh); done <- struct{}{} }()
	<-done
}

func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: config.SNI},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{config.SNI, "www." + config.SNI},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(config.IP)},
	}
	
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v7.0 - HÍBRIDO                           ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  MODO 1: App GratisBet (WebSocket)                                           ║
║    URL: wss://216.106.176.133:443/vpn                                        ║
║    Header: X-Auth: sung:123.456                                              ║
║                                                                               ║
║  MODO 2: HTTP Injector / SI Connect (SSH)                                    ║
║    Payload: CONNECT [host]:22 HTTP/1.1[crlf]Host: www.signup.ao[crlf][crlf]  ║
║    SSH: gratisbet / gratisbet123                                             ║
║    SSL: ON | SNI: www.signup.ao                                              ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝`)

	// Verificar SSH
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second); err != nil {
		logger.Println("[WARN] ⚠️  SSH não detectado em 127.0.0.1:22")
	} else {
		conn.Close()
		logger.Println("[OK] ✅ SSH detectado em 127.0.0.1:22")
	}

	cert, err := generateCert()
	if err != nil {
		logger.Fatal("Erro certificado:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s ← aceito", info.ServerName)
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		logger.Fatal("Erro listener:", err)
	}
	defer listener.Close()

	logger.Println("[OK] ✅ Servidor TLS iniciado na porta 443")
	logger.Println("[OK] ✅ Aguardando conexões...")
	logger.Println("")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleConnection(conn)
		}
	}()

	// HTTP :80
	go func() {
		listener80, _ := net.Listen("tcp", ":80")
		if listener80 != nil {
			logger.Println("[OK] ✅ HTTP health check na porta 80")
			for {
				conn, _ := listener80.Accept()
				if conn != nil {
					conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nGratisBet v7.0 Hybrid"))
					conn.Close()
				}
			}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n[!] Encerrando...")
}
