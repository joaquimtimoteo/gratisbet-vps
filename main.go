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

const SERVER_VERSION = "4.0-websocket"

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
//                    POOL DE CONEXÕES TCP
// ════════════════════════════════════════════════════════════════════

type TcpConn struct {
	conn     net.Conn
	dest     string
	lastUsed time.Time
	mu       sync.Mutex
	closed   bool
}

type UserSession struct {
	mu       sync.RWMutex
	conns    map[string]*TcpConn // dest -> connection
	wsConn   net.Conn
	wsMu     sync.Mutex
	lastSeen time.Time
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
	}
	sessions.m[userIP] = s
	return s
}

func (s *UserSession) getOrCreateTcp(dest string) (*TcpConn, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tc, ok := s.conns[dest]; ok && !tc.closed {
		tc.lastUsed = time.Now()
		return tc, false, nil
	}

	conn, err := net.DialTimeout("tcp", dest, 15*time.Second)
	if err != nil {
		return nil, false, err
	}

	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	tc := &TcpConn{
		conn:     conn,
		dest:     dest,
		lastUsed: time.Now(),
	}
	s.conns[dest] = tc

	// Iniciar goroutine para ler respostas
	go s.readFromTcp(tc, dest)

	return tc, true, nil
}

func (s *UserSession) readFromTcp(tc *TcpConn, dest string) {
	buf := make([]byte, 32768)
	for !tc.closed {
		tc.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := tc.conn.Read(buf)
		if n > 0 {
			// Enviar dados de volta via WebSocket
			s.sendToWs(dest, buf[:n])
		}
		if err != nil {
			break
		}
	}
	tc.closed = true
	tc.conn.Close()
}

func (s *UserSession) sendToWs(dest string, data []byte) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()

	if s.wsConn == nil {
		return
	}

	// Formato: tipo(1) + destLen(2) + dest + data (XOR encoded)
	msg := make([]byte, 0, 3+len(dest)+len(data))
	msg = append(msg, 0x02) // tipo: data from server
	msg = append(msg, byte(len(dest)>>8), byte(len(dest)))
	msg = append(msg, []byte(dest)...)
	msg = append(msg, xorData(data)...)

	writeWsFrame(s.wsConn, msg)
}

func (s *UserSession) closeTcp(dest string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tc, ok := s.conns[dest]; ok {
		tc.closed = true
		tc.conn.Close()
		delete(s.conns, dest)
	}
}

func cleanupSessions() {
	for {
		time.Sleep(60 * time.Second)
		sessions.Lock()
		now := time.Now()
		for ip, s := range sessions.m {
			if now.Sub(s.lastSeen) > 10*time.Minute {
				s.mu.Lock()
				for _, tc := range s.conns {
					tc.closed = true
					tc.conn.Close()
				}
				s.mu.Unlock()
				delete(sessions.m, ip)
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
	fmt.Println("  WebSocket + XOR - High Performance")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Erro: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 80 ativa")
	fmt.Println("  ✓ WebSocket: /ws")
	fmt.Println("  ✓ DNS:       /tunnel")
	fmt.Println("  ✓ Relay:     /relay (fallback)")
	fmt.Println("  ✓ Stats:     /stats")
	fmt.Println("══════════════════════════════════════════════")

	go cleanupSessions()
	go func() {
		for {
			time.Sleep(60 * time.Second)
			stats.RLock()
			mb := float64(stats.TotalBytes) / 1024 / 1024
			relay := stats.TotalRelay
			ws := stats.WsConns
			stats.RUnlock()
			fmt.Printf("[STATS] Online: %d | WS: %d | Relay: %d | %.2f MB\n",
				getOnlineUsers(), ws, relay, mb)
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
	reader := bufio.NewReader(conn)
	remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

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

	// Check for WebSocket upgrade
	if path == "/ws" && strings.ToLower(headers["upgrade"]) == "websocket" {
		handleWebSocket(conn, headers, remoteIP)
		return
	}

	fmt.Printf("[%s] %s %s de %s\n", time.Now().Format("15:04:05"), method, path, remoteIP)

	switch {
	case path == "/ws" && method == "GET":
		// WebSocket sem upgrade header - enviar erro
		send(conn, 400, "text/plain", []byte("WebSocket upgrade required"))

	case path == "/relay" && method == "POST":
		handleRelay(conn, reader, contentLength, remoteIP, headers)

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
	// WebSocket handshake
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

	fmt.Printf("[WS] Conexão estabelecida: %s\n", remoteIP)
	addWs(1)
	defer addWs(-1)

	session := getSession(remoteIP)
	session.wsMu.Lock()
	session.wsConn = conn
	session.wsMu.Unlock()

	// Loop de leitura WebSocket
	for {
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
			handleWsDns(session, payload, remoteIP)

		case 0x02: // TCP data
			handleWsTcp(session, payload, remoteIP)

		case 0x03: // Close connection
			if len(payload) >= 2 {
				destLen := int(payload[0])<<8 | int(payload[1])
				if 2+destLen <= len(payload) {
					dest := string(payload[2 : 2+destLen])
					session.closeTcp(dest)
				}
			}

		case 0x09: // Ping
			writeWsFrame(conn, append([]byte{0x0A}, payload...)) // Pong
		}

		session.lastSeen = time.Now()
	}

	fmt.Printf("[WS] Conexão fechada: %s\n", remoteIP)
	session.wsMu.Lock()
	session.wsConn = nil
	session.wsMu.Unlock()
}

func handleWsDns(session *UserSession, payload []byte, remoteIP string) {
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

	// Resolver DNS
	response := resolveDNS(dest, data)

	// Enviar resposta via WebSocket
	msg := make([]byte, 0, 3+len(dest)+len(response))
	msg = append(msg, 0x01) // tipo: DNS response
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
	data := xorData(payload[2+destLen:]) // Decodificar XOR

	addRelay()
	addBytes(int64(len(data)))

	tc, isNew, err := session.getOrCreateTcp(dest)
	if err != nil {
		fmt.Printf("[WS-TCP] Erro conectando %s: %v\n", dest, err)
		return
	}

	if isNew {
		fmt.Printf("[WS-TCP] Nova conexão: %s\n", dest)
	}

	tc.mu.Lock()
	if len(data) > 0 {
		tc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tc.conn.Write(data)
	}
	tc.mu.Unlock()
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

	// opcode := header[0] & 0x0F
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
		header = []byte{0x82, byte(length)} // Binary frame
	} else if length < 65536 {
		header = []byte{0x82, 126, byte(length >> 8), byte(length)}
	} else {
		header = make([]byte, 10)
		header[0] = 0x82
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

// ════════════════════════════════════════════════════════════════════
//                    HTTP FALLBACK (relay/tunnel)
// ════════════════════════════════════════════════════════════════════

func handleRelay(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string, headers map[string]string) {
	body := make([]byte, contentLength)
	if contentLength > 0 {
		if _, err := io.ReadFull(reader, body); err != nil {
			send(conn, 400, "application/json", []byte(`{"error":"read"}`))
			return
		}
	}

	useXOR := headers["x-xor"] == "1"
	var req struct {
		Dest string `json:"dest"`
		Data string `json:"data"`
	}
	json.Unmarshal(body, &req)

	if req.Dest == "" {
		send(conn, 400, "application/json", []byte(`{"error":"missing dest"}`))
		return
	}

	dataBytes, _ := base64.StdEncoding.DecodeString(req.Data)
	if useXOR && len(dataBytes) > 0 {
		dataBytes = xorData(dataBytes)
	}

	session := getSession(remoteIP)
	tc, isNew, err := session.getOrCreateTcp(req.Dest)
	if err != nil {
		send(conn, 502, "application/json", []byte(`{"error":"connect failed"}`))
		return
	}

	if isNew {
		fmt.Printf("[RELAY] Nova conexão: %s\n", req.Dest)
	}

	addRelay()
	addBytes(int64(len(dataBytes)))

	tc.mu.Lock()
	if len(dataBytes) > 0 {
		tc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		tc.conn.Write(dataBytes)
	}

	// Ler resposta
	tc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 0, 65536)
	buf := make([]byte, 8192)
	for {
		n, err := tc.conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			tc.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
		if err != nil {
			break
		}
		if len(response) > 1024*1024 {
			break
		}
	}
	tc.mu.Unlock()

	addBytes(int64(len(response)))

	respData := response
	if useXOR && len(response) > 0 {
		respData = xorData(response)
	}

	respJSON, _ := json.Marshal(map[string]interface{}{
		"status": "ok",
		"data":   base64.StdEncoding.EncodeToString(respData),
		"size":   len(response),
	})
	send(conn, 200, "application/json", respJSON)
}

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

	send(conn, 400, "text/plain", []byte("Use /relay for TCP"))
}

func sendStats(conn net.Conn) {
	stats.RLock()
	s := map[string]interface{}{
		"version":    SERVER_VERSION,
		"online":     getOnlineUsers(),
		"websockets": stats.WsConns,
		"relay":      stats.TotalRelay,
		"dns":        stats.TotalDNS,
		"mb":         float64(stats.TotalBytes) / 1024 / 1024,
		"uptime":     time.Since(stats.StartTime).String(),
		"goroutines": runtime.NumGoroutine(),
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
