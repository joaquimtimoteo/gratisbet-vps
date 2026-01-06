package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const SERVER_VERSION = "3.2-xor"

// ════════════════════════════════════════════════════════════════════
//                    XOR OBFUSCATION KEY
// ════════════════════════════════════════════════════════════════════

// Chave XOR - deve ser a mesma no app Android!
var XOR_KEY = []byte{0x47, 0x72, 0x61, 0x74, 0x69, 0x73, 0x42, 0x65, 0x74, 0x41, 0x6E, 0x67, 0x6F, 0x6C, 0x61, 0x21}

// "GratisBetAngola!"

func xorData(data []byte) []byte {
	result := make([]byte, len(data))
	keyLen := len(XOR_KEY)
	for i := 0; i < len(data); i++ {
		result[i] = data[i] ^ XOR_KEY[i%keyLen]
	}
	return result
}

// ════════════════════════════════════════════════════════════════════
//                    POOL DE CONEXÕES PERSISTENTES
// ════════════════════════════════════════════════════════════════════

type PersistentConn struct {
	conn      net.Conn
	dest      string
	userIP    string
	createdAt time.Time
	lastUsed  time.Time
	mu        sync.Mutex
	closed    bool
}

var connPool = struct {
	sync.RWMutex
	conns map[string]map[string]*PersistentConn
}{
	conns: make(map[string]map[string]*PersistentConn),
}

func getOrCreateConn(userIP, dest string) (*PersistentConn, bool, error) {
	connPool.Lock()
	defer connPool.Unlock()

	if connPool.conns[userIP] == nil {
		connPool.conns[userIP] = make(map[string]*PersistentConn)
	}

	if pc, exists := connPool.conns[userIP][dest]; exists {
		if !pc.closed && time.Since(pc.lastUsed) < 60*time.Second {
			pc.lastUsed = time.Now()
			return pc, false, nil
		}
		if pc.conn != nil {
			pc.conn.Close()
		}
		delete(connPool.conns[userIP], dest)
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

	pc := &PersistentConn{
		conn:      conn,
		dest:      dest,
		userIP:    userIP,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		closed:    false,
	}

	connPool.conns[userIP][dest] = pc
	return pc, true, nil
}

func closeConn(userIP, dest string) {
	connPool.Lock()
	defer connPool.Unlock()

	if userConns, exists := connPool.conns[userIP]; exists {
		if pc, exists := userConns[dest]; exists {
			pc.closed = true
			if pc.conn != nil {
				pc.conn.Close()
			}
			delete(userConns, dest)
		}
	}
}

func cleanupConnPool() {
	for {
		time.Sleep(30 * time.Second)
		connPool.Lock()
		now := time.Now()
		for userIP, userConns := range connPool.conns {
			for dest, pc := range userConns {
				if pc.closed || now.Sub(pc.lastUsed) > 60*time.Second {
					if pc.conn != nil {
						pc.conn.Close()
					}
					delete(userConns, dest)
				}
			}
			if len(userConns) == 0 {
				delete(connPool.conns, userIP)
			}
		}
		connPool.Unlock()
	}
}

func countActiveConns() int {
	connPool.RLock()
	defer connPool.RUnlock()
	count := 0
	for _, userConns := range connPool.conns {
		count += len(userConns)
	}
	return count
}

var jar, _ = cookiejar.New(nil)
var client = &http.Client{
	Timeout: 30 * time.Second,
	Jar:     jar,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

var lastBase = make(map[string]string)
var lastBaseMu sync.RWMutex

// ════════════════════════════════════════════════════════════════════
//                    ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

type UserInfo struct {
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
	Requests  int64
}

var serverStats = struct {
	sync.RWMutex
	StartTime     time.Time
	TotalBytes    int64
	TotalBytesIn  int64
	TotalBytesOut int64
	TotalRequests int64
	TotalDNS      int64
	TotalRelay    int64
	Users         map[string]*UserInfo
	PeakUsers     int
}{
	Users: make(map[string]*UserInfo),
}

func trackUser(ip string) {
	serverStats.Lock()
	defer serverStats.Unlock()
	serverStats.TotalRequests++
	if user, exists := serverStats.Users[ip]; exists {
		user.LastSeen = time.Now()
		user.Requests++
	} else {
		serverStats.Users[ip] = &UserInfo{
			IP:        ip,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Requests:  1,
		}
		if len(serverStats.Users) > serverStats.PeakUsers {
			serverStats.PeakUsers = len(serverStats.Users)
		}
	}
}

func trackRelay(bytesIn, bytesOut int64) {
	serverStats.Lock()
	serverStats.TotalRelay++
	serverStats.TotalBytesIn += bytesIn
	serverStats.TotalBytesOut += bytesOut
	serverStats.TotalBytes += bytesIn + bytesOut
	serverStats.Unlock()
}

func trackDNS() {
	serverStats.Lock()
	serverStats.TotalDNS++
	serverStats.Unlock()
}

func cleanupInactiveUsers() {
	for {
		time.Sleep(5 * time.Minute)
		serverStats.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for ip, user := range serverStats.Users {
			if user.LastSeen.Before(cutoff) {
				delete(serverStats.Users, ip)
			}
		}
		serverStats.Unlock()
	}
}

func getOnlineUsers() int {
	serverStats.RLock()
	defer serverStats.RUnlock()
	count := 0
	for _, user := range serverStats.Users {
		if time.Since(user.LastSeen) < 2*time.Minute {
			count++
		}
	}
	return count
}

// ════════════════════════════════════════════════════════════════════
//                         MAIN
// ════════════════════════════════════════════════════════════════════

func main() {
	serverStats.StartTime = time.Now()

	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  GRATISBET VPN SERVER v" + SERVER_VERSION)
	fmt.Println("  XOR Obfuscation Enabled")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Erro ao iniciar servidor: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 80 ativa")
	fmt.Println("  ✓ DNS:   /tunnel (POST)")
	fmt.Println("  ✓ Relay: /relay (POST + XOR)")
	fmt.Println("  ✓ Stats: /stats")
	fmt.Printf("  ✓ XOR Key: %d bytes\n", len(XOR_KEY))
	fmt.Println("══════════════════════════════════════════════")

	go cleanupInactiveUsers()
	go cleanupConnPool()

	go func() {
		for {
			time.Sleep(60 * time.Second)
			online := getOnlineUsers()
			conns := countActiveConns()
			serverStats.RLock()
			totalMB := float64(serverStats.TotalBytes) / 1024 / 1024
			relayCount := serverStats.TotalRelay
			serverStats.RUnlock()
			fmt.Printf("[STATS] Online: %d | Conns: %d | Relay: %d | Total: %.2f MB\n",
				online, conns, relayCount, totalMB)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	remote := conn.RemoteAddr().String()
	remoteIP := strings.Split(remote, ":")[0]

	trackUser(remoteIP)

	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return
	}
	method := parts[0]
	path := parts[1]

	headers := make(map[string]string)
	contentLength := 0
	for {
		h, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(h) == "" {
			break
		}
		idx := strings.Index(h, ":")
		if idx > 0 {
			key := strings.TrimSpace(strings.ToLower(h[:idx]))
			val := strings.TrimSpace(h[idx+1:])
			headers[key] = val
			if key == "content-length" {
				fmt.Sscanf(val, "%d", &contentLength)
			}
		}
	}

	fmt.Printf("[%s] %s %s de %s\n", time.Now().Format("15:04:05"), method, path, remoteIP)

	switch {
	case path == "/relay" && method == "POST":
		handleRelayXOR(conn, reader, contentLength, remoteIP, headers)

	case path == "/tunnel" && method == "POST":
		handleTunnel(conn, reader, contentLength, remoteIP)

	case path == "/stats":
		sendStats(conn)

	case path == "/vpn-status":
		sendVPNStatus(conn)

	case path == "/":
		sendHome(conn)

	case path == "/ping":
		send(conn, 200, "text/plain", []byte("OK"))

	case strings.HasPrefix(path, "/proxy?url="):
		doProxy(conn, path, remoteIP)

	default:
		if isResource(path) {
			lastBaseMu.RLock()
			base := lastBase[remoteIP]
			lastBaseMu.RUnlock()
			if base != "" {
				fullURL := base + path
				doProxyURL(conn, fullURL, remoteIP)
				return
			}
		}
		send(conn, 404, "text/plain", []byte("Not Found"))
	}
}

// ════════════════════════════════════════════════════════════════════
//              RELAY COM XOR OBFUSCATION
// ════════════════════════════════════════════════════════════════════

func handleRelayXOR(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string, headers map[string]string) {
	body := make([]byte, contentLength)
	if contentLength > 0 {
		_, err := io.ReadFull(reader, body)
		if err != nil {
			send(conn, 400, "application/json", []byte(`{"error":"read error"}`))
			return
		}
	}

	// Verificar se usa XOR
	useXOR := headers["x-xor"] == "1"

	var req struct {
		Dest   string `json:"dest"`
		Action string `json:"action"`
		Data   string `json:"data"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		if len(body) >= 2 {
			destLen := int(binary.BigEndian.Uint16(body[:2]))
			if destLen > 0 && destLen < 256 && 2+destLen <= len(body) {
				req.Dest = string(body[2 : 2+destLen])
				req.Action = "send"
				req.Data = base64.StdEncoding.EncodeToString(body[2+destLen:])
			}
		}
	}

	if req.Dest == "" {
		send(conn, 400, "application/json", []byte(`{"error":"missing dest"}`))
		return
	}

	if req.Action == "close" {
		closeConn(remoteIP, req.Dest)
		send(conn, 200, "application/json", []byte(`{"status":"closed"}`))
		return
	}

	// Decodificar dados
	dataBytes, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		dataBytes = []byte{}
	}

	// Se usa XOR, decodificar (dados vêm ofuscados do app)
	if useXOR && len(dataBytes) > 0 {
		dataBytes = xorData(dataBytes)
		fmt.Printf("[RELAY-XOR] Decodificado %d bytes\n", len(dataBytes))
	}

	fmt.Printf("[RELAY] %s -> %s (%d bytes, xor=%v)\n", remoteIP, req.Dest, len(dataBytes), useXOR)

	// Obter ou criar conexão
	pc, isNew, err := getOrCreateConn(remoteIP, req.Dest)
	if err != nil {
		fmt.Printf("[RELAY] Erro conexão: %v\n", err)
		send(conn, 502, "application/json", []byte(fmt.Sprintf(`{"error":"connect failed: %s"}`, err.Error())))
		return
	}

	if isNew {
		fmt.Printf("[RELAY] Nova conexão para %s\n", req.Dest)
	}

	pc.mu.Lock()
	defer pc.mu.Unlock()

	// Enviar dados
	if len(dataBytes) > 0 {
		pc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = pc.conn.Write(dataBytes)
		if err != nil {
			fmt.Printf("[RELAY] Erro write: %v\n", err)
			pc.closed = true
			closeConn(remoteIP, req.Dest)
			send(conn, 502, "application/json", []byte(`{"error":"write failed"}`))
			return
		}
	}

	// Ler resposta
	pc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 0, 65536)
	buf := make([]byte, 8192)

	for {
		n, err := pc.conn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			pc.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			if err == io.EOF {
				pc.closed = true
				break
			}
			break
		}
		if len(response) > 1024*1024 {
			break
		}
	}

	pc.lastUsed = time.Now()
	trackRelay(int64(len(dataBytes)), int64(len(response)))

	fmt.Printf("[RELAY] Resposta: %d bytes\n", len(response))

	// Se usa XOR, ofuscar resposta
	responseToSend := response
	if useXOR && len(response) > 0 {
		responseToSend = xorData(response)
		fmt.Printf("[RELAY-XOR] Codificado %d bytes\n", len(responseToSend))
	}

	// Responder
	respJSON := map[string]interface{}{
		"status": "ok",
		"data":   base64.StdEncoding.EncodeToString(responseToSend),
		"size":   len(response),
		"xor":    useXOR,
	}
	jsonBytes, _ := json.Marshal(respJSON)
	send(conn, 200, "application/json", jsonBytes)
}

// ════════════════════════════════════════════════════════════════════
//                         DNS TUNNEL
// ════════════════════════════════════════════════════════════════════

func handleTunnel(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	if contentLength < 3 {
		send(conn, 400, "text/plain", []byte("Invalid tunnel request"))
		return
	}

	body := make([]byte, contentLength)
	_, err := io.ReadFull(reader, body)
	if err != nil {
		send(conn, 400, "text/plain", []byte("Read error"))
		return
	}

	var destLen int
	var dataOffset int

	if len(body) >= 4 {
		destLen4 := int(binary.BigEndian.Uint32(body[:4]))
		destLen2 := int(binary.BigEndian.Uint16(body[:2]))

		if destLen4 > 0 && destLen4 < 256 && 4+destLen4 <= len(body) {
			destLen = destLen4
			dataOffset = 4
		} else if destLen2 > 0 && destLen2 < 256 && 2+destLen2 <= len(body) {
			destLen = destLen2
			dataOffset = 2
		} else {
			send(conn, 400, "text/plain", []byte("Invalid destination length"))
			return
		}
	} else if len(body) >= 2 {
		destLen = int(binary.BigEndian.Uint16(body[:2]))
		dataOffset = 2
	} else {
		send(conn, 400, "text/plain", []byte("Body too short"))
		return
	}

	if destLen <= 0 || destLen > 255 || dataOffset+destLen > len(body) {
		send(conn, 400, "text/plain", []byte("Invalid destination"))
		return
	}

	dest := string(body[dataOffset : dataOffset+destLen])
	data := body[dataOffset+destLen:]

	fmt.Printf("[TUNNEL] %s -> %s (%d bytes)\n", remoteIP, dest, len(data))

	if strings.HasSuffix(dest, ":53") {
		trackDNS()
		response := handleDNS(dest, data)
		fmt.Printf("[TUNNEL-DNS] Resposta: %d bytes\n", len(response))
		send(conn, 200, "application/octet-stream", response)
		return
	}

	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}
	defer targetConn.Close()

	if len(data) > 0 {
		targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = targetConn.Write(data)
		if err != nil {
			send(conn, 502, "text/plain", []byte("Write error"))
			return
		}
	}

	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response, err := io.ReadAll(targetConn)
	if err != nil && len(response) == 0 {
		send(conn, 502, "text/plain", []byte("Read error"))
		return
	}

	fmt.Printf("[TUNNEL] Resposta: %d bytes\n", len(response))
	send(conn, 200, "application/octet-stream", response)
}

func handleDNS(dest string, query []byte) []byte {
	dnsServer := "8.8.8.8:53"
	if dest != "8.8.8.8:53" && dest != "8.8.4.4:53" && !strings.HasPrefix(dest, "10.") && !strings.HasPrefix(dest, "192.168.") {
		dnsServer = dest
	}

	udpConn, err := net.DialTimeout("udp", dnsServer, 5*time.Second)
	if err != nil {
		return []byte{}
	}
	defer udpConn.Close()

	udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = udpConn.Write(query)
	if err != nil {
		return []byte{}
	}

	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 512)
	n, err := udpConn.Read(response)
	if err != nil {
		return []byte{}
	}

	return response[:n]
}

// ════════════════════════════════════════════════════════════════════
//                         ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

func sendStats(conn net.Conn) {
	serverStats.RLock()
	uptime := time.Since(serverStats.StartTime)

	stats := map[string]interface{}{
		"status":      "online",
		"version":     SERVER_VERSION,
		"uptime":      uptime.String(),
		"online":      getOnlineUsers(),
		"connections": countActiveConns(),
		"relay":       serverStats.TotalRelay,
		"dns":         serverStats.TotalDNS,
		"total_mb":    float64(serverStats.TotalBytes) / 1024 / 1024,
		"xor_enabled": true,
		"goroutines":  runtime.NumGoroutine(),
	}
	serverStats.RUnlock()

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	send(conn, 200, "application/json", jsonData)
}

func sendVPNStatus(conn net.Conn) {
	serverStats.RLock()
	total := serverStats.TotalBytes
	relay := serverStats.TotalRelay
	serverStats.RUnlock()

	json := fmt.Sprintf(`{"status":"online","version":"%s","online":%d,"conns":%d,"bytes":%d,"relay":%d,"xor":true}`,
		SERVER_VERSION, getOnlineUsers(), countActiveConns(), total, relay)
	send(conn, 200, "application/json", []byte(json))
}

// ════════════════════════════════════════════════════════════════════
//                         PROXY
// ════════════════════════════════════════════════════════════════════

func isResource(path string) bool {
	exts := []string{".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".json", ".map"}
	for _, ext := range exts {
		if strings.Contains(strings.ToLower(path), ext) {
			return true
		}
	}
	return false
}

func doProxy(conn net.Conn, path string, remoteIP string) {
	idx := strings.Index(path, "url=")
	if idx < 0 {
		send(conn, 400, "text/plain", []byte("Missing url"))
		return
	}
	targetURL, _ := url.QueryUnescape(path[idx+4:])
	doProxyURL(conn, targetURL, remoteIP)
}

func doProxyURL(conn net.Conn, targetURL string, remoteIP string) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		send(conn, 400, "text/plain", []byte("Invalid URL"))
		return
	}

	base := parsed.Scheme + "://" + parsed.Host
	lastBaseMu.Lock()
	lastBase[remoteIP] = base
	lastBaseMu.Unlock()

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		send(conn, 502, "text/plain", []byte("Error"))
		return
	}
	defer resp.Body.Close()

	var body []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(resp.Body)
		if err == nil {
			body, _ = io.ReadAll(gr)
			gr.Close()
		} else {
			body, _ = io.ReadAll(resp.Body)
		}
	} else {
		body, _ = io.ReadAll(resp.Body)
	}

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		body = rewriteHTML(body, base)
	}
	if strings.Contains(ct, "text/css") {
		body = rewriteCSS(body, base)
	}

	send(conn, resp.StatusCode, ct, body)
}

func rewriteHTML(body []byte, base string) []byte {
	html := string(body)
	encodedBase := url.QueryEscape(base)

	re1 := regexp.MustCompile(`(src|href)="(https?://[^"]+)"`)
	html = re1.ReplaceAllStringFunc(html, func(match string) string {
		parts := re1.FindStringSubmatch(match)
		if len(parts) == 3 {
			attr := parts[1]
			urlStr := parts[2]
			if strings.Contains(urlStr, "facebook.com") || strings.Contains(urlStr, "google") || strings.Contains(urlStr, "analytics") {
				return fmt.Sprintf(`%s=""`, attr)
			}
			return fmt.Sprintf(`%s="/proxy?url=%s"`, attr, url.QueryEscape(urlStr))
		}
		return match
	})

	html = strings.ReplaceAll(html, `src="/`, `src="/proxy?url=`+encodedBase+`%2F`)
	html = strings.ReplaceAll(html, `href="/`, `href="/proxy?url=`+encodedBase+`%2F`)

	return []byte(html)
}

func rewriteCSS(body []byte, base string) []byte {
	css := string(body)
	encodedBase := url.QueryEscape(base)
	re := regexp.MustCompile(`url\(['"]?(/[^'")]+)['"]?\)`)
	css = re.ReplaceAllString(css, `url(/proxy?url=`+encodedBase+`$1)`)
	return []byte(css)
}

func sendHome(conn net.Conn) {
	online := getOnlineUsers()
	conns := countActiveConns()
	serverStats.RLock()
	totalMB := float64(serverStats.TotalBytes) / 1024 / 1024
	relay := serverStats.TotalRelay
	uptime := time.Since(serverStats.StartTime)
	serverStats.RUnlock()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px}
h1{color:#00c853;text-align:center;margin:20px 0}
.badge{background:#00c853;color:#000;padding:5px 15px;border-radius:20px;font-size:12px;display:inline-block;margin:10px auto;text-align:center}
.status{background:#2d2d44;border-radius:15px;padding:20px;text-align:center;margin:20px auto;max-width:400px}
.online{color:#00c853;font-size:24px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:15px}
.stat{background:#1a1a2e;padding:10px;border-radius:8px}
.label{color:#888;font-size:12px}
.value{color:#fff;font-size:18px;font-weight:bold}
</style></head><body>
<h1> GratisBet VPN</h1>
<center><div class="badge">v%s - XOR Obfuscation</div></center>
<div class="status">
<p class="online">● %d Online</p>
<div class="grid">
<div class="stat"><div class="label">Conexões</div><div class="value">%d</div></div>
<div class="stat"><div class="label">Relay</div><div class="value">%d</div></div>
<div class="stat"><div class="label">Tráfego</div><div class="value">%.1f MB</div></div>
<div class="stat"><div class="label">Uptime</div><div class="value">%s</div></div>
</div>
</div>
</body></html>`, SERVER_VERSION, online, conns, relay, totalMB, formatDuration(uptime))
	send(conn, 200, "text/html; charset=utf-8", []byte(html))
}

func formatDuration(d time.Duration) string {
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func send(conn net.Conn, code int, ct string, body []byte) {
	status := map[int]string{200: "OK", 400: "Bad Request", 404: "Not Found", 502: "Bad Gateway"}[code]
	if status == "" {
		status = "OK"
	}
	h := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n", code, status, ct, len(body))
	conn.Write([]byte(h))
	conn.Write(body)
}
