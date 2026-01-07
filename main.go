package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"
)

const SERVER_VERSION = "4.1-websocket"

// ════════════════════════════════════════════════════════════════════
//                    CONFIGURAÇÕES OTIMIZADAS
// ════════════════════════════════════════════════════════════════════

const (
	BUFFER_SIZE      = 64 * 1024         // 64KB
	CONN_TIMEOUT     = 30 * time.Second  // Timeout para conectar
	READ_TIMEOUT     = 5 * time.Minute   // 5 min - manter conexões ativas
	WRITE_TIMEOUT    = 30 * time.Second
	IDLE_TIMEOUT     = 10 * time.Minute  // Conexão ociosa por 10 min
	CLEANUP_INTERVAL = 2 * time.Minute
	SESSION_TIMEOUT  = 30 * time.Minute
)

// XOR Key - mesma do app Android
var XOR_KEY = []byte("GratisBetAngola!")

func xorData(data []byte) []byte {
	result := make([]byte, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XOR_KEY[i%len(XOR_KEY)]
	}
	return result
}

// ════════════════════════════════════════════════════════════════════
//                    POOL DE CONEXÕES TCP
// ════════════════════════════════════════════════════════════════════

type TcpConn struct {
	conn     net.Conn
	dest     string
	created  time.Time
	lastUsed time.Time
	mu       sync.Mutex
	closed   bool
	reading  bool
}

func (tc *TcpConn) isValid() bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.closed {
		return false
	}
	if time.Since(tc.lastUsed) > IDLE_TIMEOUT {
		return false
	}
	return true
}

type UserSession struct {
	mu       sync.RWMutex
	conns    map[string]*TcpConn
	wsConn   net.Conn
	wsMu     sync.Mutex
	lastSeen time.Time
	userIP   string
}

var sessions = struct {
	sync.RWMutex
	m map[string]*UserSession
}{m: make(map[string]*UserSession)}

func getSession(userIP string) *UserSession {
	sessions.Lock()
	defer sessions.Unlock()

	if s, ok := sessions.m[userIP]; ok {
		s.lastSeen = time.Now()
		return s
	}

	s := &UserSession{
		conns:    make(map[string]*TcpConn),
		lastSeen: time.Now(),
		userIP:   userIP,
	}
	sessions.m[userIP] = s
	return s
}

func (s *UserSession) getOrCreateTcp(dest string) (*TcpConn, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Verificar conexão existente
	if tc, ok := s.conns[dest]; ok && tc.isValid() {
		tc.mu.Lock()
		tc.lastUsed = time.Now()
		tc.mu.Unlock()
		return tc, false, nil
	}

	// Remover conexão inválida
	if tc, ok := s.conns[dest]; ok {
		tc.mu.Lock()
		tc.closed = true
		if tc.conn != nil {
			tc.conn.Close()
		}
		tc.mu.Unlock()
		delete(s.conns, dest)
	}

	// Criar nova conexão
	dialer := &net.Dialer{
		Timeout:   CONN_TIMEOUT,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", dest)
	if err != nil {
		return nil, false, err
	}

	// Otimizações TCP
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetReadBuffer(BUFFER_SIZE)
		tcpConn.SetWriteBuffer(BUFFER_SIZE)
	}

	tc := &TcpConn{
		conn:     conn,
		dest:     dest,
		created:  time.Now(),
		lastUsed: time.Now(),
	}
	s.conns[dest] = tc

	// Iniciar goroutine de leitura
	go s.readFromTcp(tc, dest)

	return tc, true, nil
}

func (s *UserSession) readFromTcp(tc *TcpConn, dest string) {
	tc.mu.Lock()
	if tc.reading {
		tc.mu.Unlock()
		return
	}
	tc.reading = true
	tc.mu.Unlock()

	buf := make([]byte, BUFFER_SIZE)

	for {
		tc.mu.Lock()
		if tc.closed {
			tc.mu.Unlock()
			break
		}
		tc.mu.Unlock()

		tc.conn.SetReadDeadline(time.Now().Add(READ_TIMEOUT))
		n, err := tc.conn.Read(buf)

		if n > 0 {
			tc.mu.Lock()
			tc.lastUsed = time.Now()
			tc.mu.Unlock()

			// Enviar via WebSocket
			s.sendToWs(dest, buf[:n])
			addBytes(int64(n))
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				tc.mu.Lock()
				idle := time.Since(tc.lastUsed)
				tc.mu.Unlock()
				if idle < IDLE_TIMEOUT {
					continue
				}
			}
			break
		}
	}

	tc.mu.Lock()
	tc.closed = true
	tc.conn.Close()
	tc.mu.Unlock()
}

func (s *UserSession) sendToWs(dest string, data []byte) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	if s.wsConn == nil {
		return
	}

	// Formato: tipo(1) + destLen(2) + dest + XOR(data)
	msg := make([]byte, 0, 3+len(dest)+len(data))
	msg = append(msg, 0x02) // tipo: data from server
	msg = append(msg, byte(len(dest)>>8), byte(len(dest)))
	msg = append(msg, []byte(dest)...)
	msg = append(msg, xorData(data)...)

	writeWsFrame(s.wsConn, msg)
}

func (s *UserSession) writeTcp(dest string, data []byte) error {
	s.mu.RLock()
	tc, ok := s.conns[dest]
	s.mu.RUnlock()

	if !ok || !tc.isValid() {
		return fmt.Errorf("connection not found")
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return fmt.Errorf("connection closed")
	}

	tc.conn.SetWriteDeadline(time.Now().Add(WRITE_TIMEOUT))
	_, err := tc.conn.Write(data)
	if err != nil {
		tc.closed = true
		return err
	}

	tc.lastUsed = time.Now()
	return nil
}

func cleanupSessions() {
	for {
		time.Sleep(CLEANUP_INTERVAL)

		sessions.Lock()
		now := time.Now()

		for ip, s := range sessions.m {
			if now.Sub(s.lastSeen) > SESSION_TIMEOUT {
				s.mu.Lock()
				for _, tc := range s.conns {
					tc.mu.Lock()
					tc.closed = true
					if tc.conn != nil {
						tc.conn.Close()
					}
					tc.mu.Unlock()
				}
				s.mu.Unlock()
				delete(sessions.m, ip)
				fmt.Printf("[CLEANUP] Sessão removida: %s\n", ip)
			} else {
				s.mu.Lock()
				for dest, tc := range s.conns {
					if !tc.isValid() {
						tc.mu.Lock()
						tc.closed = true
						if tc.conn != nil {
							tc.conn.Close()
						}
						tc.mu.Unlock()
						delete(s.conns, dest)
					}
				}
				s.mu.Unlock()
			}
		}

		sessions.Unlock()
	}
}

// ════════════════════════════════════════════════════════════════════
//                    ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

var stats = struct {
	sync.RWMutex
	StartTime  time.Time
	TotalBytes int64
	TotalRelay int64
	TotalDNS   int64
	WsConns    int64
}{StartTime: time.Now()}

func addBytes(n int64) {
	stats.Lock()
	stats.TotalBytes += n
	stats.Unlock()
}

func addRelay() {
	stats.Lock()
	stats.TotalRelay++
	stats.Unlock()
}

func addDNS() {
	stats.Lock()
	stats.TotalDNS++
	stats.Unlock()
}

func addWs(delta int64) {
	stats.Lock()
	stats.WsConns += delta
	stats.Unlock()
}

func countTcpConns() int {
	sessions.RLock()
	defer sessions.RUnlock()
	count := 0
	for _, s := range sessions.m {
		s.mu.RLock()
		for _, tc := range s.conns {
			if tc.isValid() {
				count++
			}
		}
		s.mu.RUnlock()
	}
	return count
}

func getOnlineUsers() int {
	sessions.RLock()
	defer sessions.RUnlock()
	count := 0
	for _, s := range sessions.m {
		if time.Since(s.lastSeen) < 2*time.Minute {
			count++
		}
	}
	return count
}

// ════════════════════════════════════════════════════════════════════
//                         MAIN
// ════════════════════════════════════════════════════════════════════

func main() {
	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  GRATISBET VPN SERVER v" + SERVER_VERSION)
	fmt.Println("  WebSocket + XOR - OPTIMIZED")
	fmt.Println("══════════════════════════════════════════════")
	fmt.Printf("  Buffer: %dKB | Idle: %v\n", BUFFER_SIZE/1024, IDLE_TIMEOUT)
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":443")
	if err != nil {
		fmt.Printf("Erro: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 443 ativa")
	fmt.Println("  ✓ WebSocket: /ws")
	fmt.Println("  ✓ DNS:       /tunnel")
	fmt.Println("  ✓ Stats:     /stats")
	fmt.Println("══════════════════════════════════════════════")

	go cleanupSessions()

	go func() {
		for {
			time.Sleep(30 * time.Second)
			stats.RLock()
			mb := float64(stats.TotalBytes) / 1024 / 1024
			relay := stats.TotalRelay
			ws := stats.WsConns
			stats.RUnlock()
			tcpConns := countTcpConns()
			fmt.Printf("[STATS] Users: %d | WS: %d | TCP: %d | Pkts: %d | %.2f MB\n",
				getOnlineUsers(), ws, tcpConns, relay, mb)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(BUFFER_SIZE)
		tc.SetWriteBuffer(BUFFER_SIZE)
	}

	reader := bufio.NewReaderSize(conn, BUFFER_SIZE)
	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return
	}
	method, path := parts[0], parts[1]

	headers := make(map[string]string)
	contentLength := 0
	for {
		h, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(h) == "" {
			break
		}
		if idx := strings.Index(h, ":"); idx > 0 {
			k := strings.TrimSpace(strings.ToLower(h[:idx]))
			v := strings.TrimSpace(h[idx+1:])
			headers[k] = v
			if k == "content-length" {
				fmt.Sscanf(v, "%d", &contentLength)
			}
		}
	}

	// WebSocket upgrade
	if path == "/ws" && strings.ToLower(headers["upgrade"]) == "websocket" {
		handleWebSocket(conn, headers, remoteIP)
		return
	}

	switch {
	case path == "/tunnel" && method == "POST":
		handleTunnel(conn, reader, contentLength, remoteIP)

	case path == "/stats":
		sendStats(conn)

	case path == "/" || path == "/ping":
		send(conn, 200, "text/plain", []byte("GratisBet VPN v"+SERVER_VERSION+" OK"))

	default:
		send(conn, 404, "text/plain", []byte("Not Found"))
	}
}

// ════════════════════════════════════════════════════════════════════
//                    WEBSOCKET HANDLER
// ════════════════════════════════════════════════════════════════════

func handleWebSocket(conn net.Conn, headers map[string]string, remoteIP string) {
	key := headers["sec-websocket-key"]
	if key == "" {
		send(conn, 400, "text/plain", []byte("Missing Sec-WebSocket-Key"))
		return
	}

	acceptKey := computeAcceptKey(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	conn.Write([]byte(response))

	fmt.Printf("[WS] Conectado: %s\n", remoteIP)
	addWs(1)
	defer addWs(-1)

	session := getSession(remoteIP)
	session.wsMu.Lock()
	session.wsConn = conn
	session.wsMu.Unlock()

	for {
		conn.SetReadDeadline(time.Now().Add(READ_TIMEOUT))
		frame, err := readWsFrame(conn)
		if err != nil {
			break
		}

		if len(frame) < 1 {
			continue
		}

		msgType := frame[0]
		payload := frame[1:]

		switch msgType {
		case 0x01: // DNS request
			handleWsDns(session, payload)

		case 0x02: // TCP data
			handleWsTcp(session, payload, remoteIP)

		case 0x03: // Close connection
			if len(payload) >= 2 {
				destLen := int(payload[0])<<8 | int(payload[1])
				if 2+destLen <= len(payload) {
					dest := string(payload[2 : 2+destLen])
					session.mu.Lock()
					if tc, ok := session.conns[dest]; ok {
						tc.mu.Lock()
						tc.closed = true
						tc.conn.Close()
						tc.mu.Unlock()
						delete(session.conns, dest)
					}
					session.mu.Unlock()
				}
			}

		case 0x09: // Ping
			writeWsFrame(conn, append([]byte{0x0A}, payload...))
		}

		session.lastSeen = time.Now()
	}

	fmt.Printf("[WS] Desconectado: %s\n", remoteIP)
	session.wsMu.Lock()
	session.wsConn = nil
	session.wsMu.Unlock()
}

func handleWsDns(session *UserSession, payload []byte) {
	if len(payload) < 2 {
		return
	}

	destLen := int(payload[0])<<8 | int(payload[1])
	if 2+destLen > len(payload) {
		return
	}

	dest := string(payload[2 : 2+destLen])
	data := payload[2+destLen:]

	if !strings.HasSuffix(dest, ":53") {
		return
	}

	addDNS()

	response := resolveDNS(dest, data)

	msg := make([]byte, 0, 3+len(dest)+len(response))
	msg = append(msg, 0x01)
	msg = append(msg, byte(len(dest)>>8), byte(len(dest)))
	msg = append(msg, []byte(dest)...)
	msg = append(msg, response...)

	session.wsMu.Lock()
	if session.wsConn != nil {
		writeWsFrame(session.wsConn, msg)
	}
	session.wsMu.Unlock()
}

func handleWsTcp(session *UserSession, payload []byte, remoteIP string) {
	if len(payload) < 2 {
		return
	}

	destLen := int(payload[0])<<8 | int(payload[1])
	if 2+destLen > len(payload) {
		return
	}

	dest := string(payload[2 : 2+destLen])
	data := xorData(payload[2+destLen:])

	addRelay()
	addBytes(int64(len(data)))

	// Obter ou criar conexão
	tc, isNew, err := session.getOrCreateTcp(dest)
	if err != nil {
		return
	}

	if isNew {
		fmt.Printf("[TCP+] %s\n", dest)
	}

	// Escrever dados
	if len(data) > 0 {
		if err := session.writeTcp(dest, data); err != nil {
			session.mu.Lock()
			delete(session.conns, dest)
			session.mu.Unlock()

			tc, _, err = session.getOrCreateTcp(dest)
			if err != nil {
				return
			}
			session.writeTcp(dest, data)
		}
	}

	_ = tc
}

func resolveDNS(dest string, query []byte) []byte {
	dnsServer := "8.8.8.8:53"
	if dest != "8.8.8.8:53" && dest != "8.8.4.4:53" {
		dnsServer = dest
	}

	conn, err := net.DialTimeout("udp", dnsServer, 5*time.Second)
	if err != nil {
		return []byte{}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write(query)

	resp := make([]byte, 512)
	n, _ := conn.Read(resp)
	return resp[:n]
}

// ════════════════════════════════════════════════════════════════════
//                    WEBSOCKET FRAMES
// ════════════════════════════════════════════════════════════════════

func computeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func readWsFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	if length == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint64(ext))
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(conn, mask); err != nil {
			return nil, err
		}
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

func writeWsFrame(conn net.Conn, data []byte) error {
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

	conn.SetWriteDeadline(time.Now().Add(WRITE_TIMEOUT))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// ════════════════════════════════════════════════════════════════════
//                    DNS FALLBACK
// ════════════════════════════════════════════════════════════════════

func handleTunnel(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	if contentLength < 3 {
		send(conn, 400, "text/plain", []byte("Invalid"))
		return
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		send(conn, 400, "text/plain", []byte("Read error"))
		return
	}

	destLen := int(binary.BigEndian.Uint16(body[:2]))
	if destLen <= 0 || destLen > 255 || 2+destLen > len(body) {
		send(conn, 400, "text/plain", []byte("Invalid dest"))
		return
	}

	dest := string(body[2 : 2+destLen])
	data := body[2+destLen:]

	if strings.HasSuffix(dest, ":53") {
		addDNS()
		resp := resolveDNS(dest, data)
		send(conn, 200, "application/octet-stream", resp)
		return
	}

	send(conn, 400, "text/plain", []byte("Use WebSocket for TCP"))
}

func sendStats(conn net.Conn) {
	stats.RLock()
	s := map[string]interface{}{
		"version":    SERVER_VERSION,
		"online":     getOnlineUsers(),
		"websockets": stats.WsConns,
		"tcp_conns":  countTcpConns(),
		"relay":      stats.TotalRelay,
		"dns":        stats.TotalDNS,
		"mb":         float64(stats.TotalBytes) / 1024 / 1024,
		"uptime":     time.Since(stats.StartTime).String(),
		"goroutines": runtime.NumGoroutine(),
		"buffer_kb":  BUFFER_SIZE / 1024,
	}
	stats.RUnlock()
	j, _ := json.MarshalIndent(s, "", "  ")
	send(conn, 200, "application/json", j)
}

func send(conn net.Conn, code int, ct string, body []byte) {
	st := map[int]string{200: "OK", 400: "Bad Request", 404: "Not Found", 502: "Bad Gateway"}[code]
	h := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", code, st, ct, len(body))
	conn.Write([]byte(h))
	conn.Write(body)
}
