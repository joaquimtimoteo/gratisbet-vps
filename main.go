package main

import (
	"bufio"
	"bytes"
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

// API Keys
const FOOTBALL_API_KEY = "416ad7217f99978b716b399ea3d08edc"
const YOUTUBE_API_KEY = "AIzaSyCxFo3x8k0BCQEEfNQLFS-6HWux4--0sjY"

// Versão do servidor
const SERVER_VERSION = "3.0-relay"

// ════════════════════════════════════════════════════════════════════
//                    POOL DE CONEXÕES PERSISTENTES
// ════════════════════════════════════════════════════════════════════

// Conexão persistente com destino
type PersistentConn struct {
	conn      net.Conn
	dest      string
	createdAt time.Time
	lastUsed  time.Time
	mu        sync.Mutex
}

// Pool de conexões por usuário
var connPool = struct {
	sync.RWMutex
	conns map[string]map[string]*PersistentConn // userIP -> dest -> conn
}{
	conns: make(map[string]map[string]*PersistentConn),
}

// Obter ou criar conexão persistente
func getOrCreateConn(userIP, dest string) (*PersistentConn, error) {
	connPool.Lock()
	defer connPool.Unlock()

	if connPool.conns[userIP] == nil {
		connPool.conns[userIP] = make(map[string]*PersistentConn)
	}

	// Verificar se já existe conexão válida
	if pc, exists := connPool.conns[userIP][dest]; exists {
		// Verificar se ainda está ativa (menos de 30s)
		if time.Since(pc.lastUsed) < 30*time.Second {
			pc.lastUsed = time.Now()
			return pc, nil
		}
		// Conexão expirada, fechar
		pc.conn.Close()
		delete(connPool.conns[userIP], dest)
	}

	// Criar nova conexão
	conn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		return nil, err
	}

	pc := &PersistentConn{
		conn:      conn,
		dest:      dest,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}

	connPool.conns[userIP][dest] = pc
	return pc, nil
}

// Fechar conexão
func closeConn(userIP, dest string) {
	connPool.Lock()
	defer connPool.Unlock()

	if userConns, exists := connPool.conns[userIP]; exists {
		if pc, exists := userConns[dest]; exists {
			pc.conn.Close()
			delete(userConns, dest)
		}
	}
}

// Limpar conexões expiradas
func cleanupConnPool() {
	for {
		time.Sleep(30 * time.Second)

		connPool.Lock()
		now := time.Now()
		for userIP, userConns := range connPool.conns {
			for dest, pc := range userConns {
				if now.Sub(pc.lastUsed) > 60*time.Second {
					pc.conn.Close()
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
//                    SISTEMA DE ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

type UserInfo struct {
	IP            string
	FirstSeen     time.Time
	LastSeen      time.Time
	ActiveTunnels int
	BytesIn       int64
	BytesOut      int64
	Requests      int64
}

var serverStats = struct {
	sync.RWMutex
	StartTime      time.Time
	ActiveTunnels  int
	TotalTunnels   int64
	TotalBytes     int64
	TotalBytesIn   int64
	TotalBytesOut  int64
	TotalRequests  int64
	TotalDNS       int64
	TotalRelay     int64
	Users          map[string]*UserInfo
	PeakUsers      int
	PeakTunnels    int
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

func trackTunnelStart(ip string) {
	serverStats.Lock()
	defer serverStats.Unlock()
	serverStats.ActiveTunnels++
	serverStats.TotalTunnels++
	if serverStats.ActiveTunnels > serverStats.PeakTunnels {
		serverStats.PeakTunnels = serverStats.ActiveTunnels
	}
	if user, exists := serverStats.Users[ip]; exists {
		user.ActiveTunnels++
	}
}

func trackTunnelEnd(ip string, bytesIn, bytesOut int64) {
	serverStats.Lock()
	defer serverStats.Unlock()
	serverStats.ActiveTunnels--
	serverStats.TotalBytesIn += bytesIn
	serverStats.TotalBytesOut += bytesOut
	serverStats.TotalBytes += bytesIn + bytesOut
	if user, exists := serverStats.Users[ip]; exists {
		user.ActiveTunnels--
		user.BytesIn += bytesIn
		user.BytesOut += bytesOut
		user.LastSeen = time.Now()
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
			if user.ActiveTunnels == 0 && user.LastSeen.Before(cutoff) {
				delete(serverStats.Users, ip)
			}
		}
		serverStats.Unlock()
	}
}

func getActiveUsers() int {
	serverStats.RLock()
	defer serverStats.RUnlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	count := 0
	for _, user := range serverStats.Users {
		if user.ActiveTunnels > 0 || user.LastSeen.After(cutoff) {
			count++
		}
	}
	return count
}

func getOnlineUsers() int {
	serverStats.RLock()
	defer serverStats.RUnlock()
	count := 0
	for _, user := range serverStats.Users {
		if user.ActiveTunnels > 0 || time.Since(user.LastSeen) < 2*time.Minute {
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
	fmt.Println("  Porta 80 - Relay Mode (Anti-DPI)")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Erro ao iniciar servidor: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 80 ativa")
	fmt.Println("  ✓ DNS:         /tunnel (POST)")
	fmt.Println("  ✓ Relay:       /relay (POST) - NOVO!")
	fmt.Println("  ✓ HTTP Fetch:  /fetch (POST) - NOVO!")
	fmt.Println("  ✓ VPN Connect: /vpn-connect (legado)")
	fmt.Println("  ✓ Stats:       /stats")
	fmt.Println("══════════════════════════════════════════════")

	go cleanupInactiveUsers()
	go cleanupConnPool()

	go func() {
		for {
			time.Sleep(60 * time.Second)
			online := getOnlineUsers()
			active := getActiveUsers()
			serverStats.RLock()
			tunnels := serverStats.ActiveTunnels
			totalMB := float64(serverStats.TotalBytes) / 1024 / 1024
			relayCount := serverStats.TotalRelay
			serverStats.RUnlock()
			fmt.Printf("[STATS] Online: %d | Ativos: %d | Túneis: %d | Relay: %d | Total: %.2f MB\n",
				online, active, tunnels, relayCount, totalMB)
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
	// ════════════════════════════════════════════════════════════════════
	//              NOVO: /relay - TCP Relay via POST
	// ════════════════════════════════════════════════════════════════════
	case path == "/relay" && method == "POST":
		handleRelay(conn, reader, contentLength, remoteIP)

	// ════════════════════════════════════════════════════════════════════
	//              NOVO: /fetch - HTTP Fetch via POST
	// ════════════════════════════════════════════════════════════════════
	case path == "/fetch" && method == "POST":
		handleFetch(conn, reader, contentLength, remoteIP)

	case path == "/tunnel" && method == "POST":
		handleTunnel(conn, reader, contentLength, remoteIP)

	case path == "/vpn-connect" || strings.HasPrefix(path, "/vpn-connect"):
		dest := headers["x-dest"]
		if dest == "" {
			send(conn, 400, "text/plain", []byte("Missing X-Dest header"))
			return
		}
		handleVpnConnect(conn, reader, dest, remoteIP)

	case path == "/stats":
		sendStats(conn)

	case path == "/stats/users":
		sendUserStats(conn)

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
//              NOVO: RELAY - TCP via POST (Anti-DPI)
// ════════════════════════════════════════════════════════════════════

// Formato do request:
// POST /relay
// Content-Type: application/octet-stream
// X-Dest: host:port
// X-Action: connect|send|close
// Body: dados a enviar (base64 se necessário)

func handleRelay(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	// Ler headers já foram lidos, precisamos pegar do body

	body := make([]byte, contentLength)
	if contentLength > 0 {
		_, err := io.ReadFull(reader, body)
		if err != nil {
			send(conn, 400, "application/json", []byte(`{"error":"read error"}`))
			return
		}
	}

	// Parse JSON request
	var req struct {
		Dest   string `json:"dest"`
		Action string `json:"action"` // connect, send, recv, close
		Data   string `json:"data"`   // base64 encoded
	}

	if err := json.Unmarshal(body, &req); err != nil {
		// Fallback: formato binário simples
		// [2 bytes dest len][dest][data]
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

	fmt.Printf("[RELAY] %s -> %s (%s)\n", remoteIP, req.Dest, req.Action)

	switch req.Action {
	case "connect":
		// Apenas estabelecer conexão
		pc, err := getOrCreateConn(remoteIP, req.Dest)
		if err != nil {
			fmt.Printf("[RELAY] Erro connect: %v\n", err)
			send(conn, 502, "application/json", []byte(fmt.Sprintf(`{"error":"connect failed: %s"}`, err.Error())))
			return
		}
		_ = pc
		send(conn, 200, "application/json", []byte(`{"status":"connected"}`))

	case "send", "":
		// Enviar dados e receber resposta
		dataBytes, _ := base64.StdEncoding.DecodeString(req.Data)

		// Criar conexão temporária (não reutilizar)
		targetConn, err := net.DialTimeout("tcp", req.Dest, 10*time.Second)
		if err != nil {
			fmt.Printf("[RELAY] Erro dial: %v\n", err)
			send(conn, 502, "application/json", []byte(fmt.Sprintf(`{"error":"dial failed: %s"}`, err.Error())))
			return
		}
		defer targetConn.Close()

		// Enviar dados
		if len(dataBytes) > 0 {
			targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err = targetConn.Write(dataBytes)
			if err != nil {
				fmt.Printf("[RELAY] Erro write: %v\n", err)
				send(conn, 502, "application/json", []byte(`{"error":"write failed"}`))
				return
			}
		}

		// Ler resposta com timeout
		targetConn.SetReadDeadline(time.Now().Add(15 * time.Second))
		response := make([]byte, 0, 65536)
		buf := make([]byte, 4096)

		for {
			n, err := targetConn.Read(buf)
			if n > 0 {
				response = append(response, buf[:n]...)
				// Se recebemos dados, continuar lendo até timeout curto
				targetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
			}
			if err != nil {
				break
			}
			// Limite de 1MB
			if len(response) > 1024*1024 {
				break
			}
		}

		trackRelay(int64(len(dataBytes)), int64(len(response)))

		fmt.Printf("[RELAY] Resposta: %d bytes\n", len(response))

		// Responder com dados em base64
		respJSON := map[string]interface{}{
			"status": "ok",
			"data":   base64.StdEncoding.EncodeToString(response),
			"size":   len(response),
		}
		jsonBytes, _ := json.Marshal(respJSON)
		send(conn, 200, "application/json", jsonBytes)

	case "close":
		closeConn(remoteIP, req.Dest)
		send(conn, 200, "application/json", []byte(`{"status":"closed"}`))

	default:
		send(conn, 400, "application/json", []byte(`{"error":"invalid action"}`))
	}
}

// ════════════════════════════════════════════════════════════════════
//              NOVO: FETCH - HTTP Request via POST
// ════════════════════════════════════════════════════════════════════

// Formato:
// POST /fetch
// Body: {"url":"https://...", "method":"GET", "headers":{}, "body":""}

func handleFetch(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	body := make([]byte, contentLength)
	if contentLength > 0 {
		_, err := io.ReadFull(reader, body)
		if err != nil {
			send(conn, 400, "application/json", []byte(`{"error":"read error"}`))
			return
		}
	}

	var req struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}

	if err := json.Unmarshal(body, &req); err != nil {
		send(conn, 400, "application/json", []byte(`{"error":"invalid json"}`))
		return
	}

	if req.URL == "" {
		send(conn, 400, "application/json", []byte(`{"error":"missing url"}`))
		return
	}

	if req.Method == "" {
		req.Method = "GET"
	}

	fmt.Printf("[FETCH] %s %s\n", req.Method, req.URL)

	// Criar request
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		send(conn, 400, "application/json", []byte(fmt.Sprintf(`{"error":"invalid request: %s"}`, err.Error())))
		return
	}

	// Adicionar headers
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Fazer request
	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Printf("[FETCH] Erro: %v\n", err)
		send(conn, 502, "application/json", []byte(fmt.Sprintf(`{"error":"request failed: %s"}`, err.Error())))
		return
	}
	defer resp.Body.Close()

	// Ler resposta
	respBody, _ := io.ReadAll(resp.Body)

	// Coletar headers de resposta
	respHeaders := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	trackRelay(int64(len(body)), int64(len(respBody)))

	fmt.Printf("[FETCH] Resposta: %d bytes (status %d)\n", len(respBody), resp.StatusCode)

	// Responder
	response := map[string]interface{}{
		"status":  resp.StatusCode,
		"headers": respHeaders,
		"body":    base64.StdEncoding.EncodeToString(respBody),
		"size":    len(respBody),
	}
	jsonBytes, _ := json.Marshal(response)
	send(conn, 200, "application/json", jsonBytes)
}

// ════════════════════════════════════════════════════════════════════
//                         VPN TUNNEL HANDLERS (Original)
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

	trackRelay(int64(len(data)), int64(len(response)))

	fmt.Printf("[TUNNEL] Resposta: %d bytes\n", len(response))
	send(conn, 200, "application/octet-stream", response)
}

func handleDNS(dest string, query []byte) []byte {
	dnsServer := "8.8.8.8:53"

	if strings.HasPrefix(dest, "10.") || strings.HasPrefix(dest, "192.168.") || strings.HasPrefix(dest, "172.") {
		dnsServer = "8.8.8.8:53"
	} else if dest != "8.8.8.8:53" && dest != "8.8.4.4:53" {
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

func handleVpnConnect(conn net.Conn, reader *bufio.Reader, dest string, remoteIP string) {
	fmt.Printf("[VPN-CONNECT] %s -> %s\n", remoteIP, dest)

	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Connection: keep-alive\r\n\r\n"
	conn.Write([]byte(response))

	trackTunnelStart(remoteIP)
	fmt.Printf("[VPN-CONNECT] ✓ Túnel ativo: %s <-> %s\n", remoteIP, dest)

	var wg sync.WaitGroup
	wg.Add(2)

	var bytesUp, bytesDown int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, reader)
		bytesUp = n
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		bytesDown = n
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	targetConn.Close()

	trackTunnelEnd(remoteIP, bytesDown, bytesUp)
	fmt.Printf("[VPN-CONNECT] ✗ Túnel fechado: %s (↑%d ↓%d bytes)\n", remoteIP, bytesUp, bytesDown)
}

// ════════════════════════════════════════════════════════════════════
//                         ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

func sendStats(conn net.Conn) {
	serverStats.RLock()
	uptime := time.Since(serverStats.StartTime)

	onlineUsers := getOnlineUsers()
	activeUsers := getActiveUsers()

	stats := map[string]interface{}{
		"status":         "online",
		"version":        SERVER_VERSION,
		"uptime":         uptime.String(),
		"uptime_seconds": int64(uptime.Seconds()),
		"users": map[string]int{
			"online": onlineUsers,
			"active": activeUsers,
			"total":  len(serverStats.Users),
			"peak":   serverStats.PeakUsers,
		},
		"tunnels": map[string]interface{}{
			"active": serverStats.ActiveTunnels,
			"total":  serverStats.TotalTunnels,
			"peak":   serverStats.PeakTunnels,
		},
		"relay": serverStats.TotalRelay,
		"traffic": map[string]interface{}{
			"total_bytes": serverStats.TotalBytes,
			"total_mb":    float64(serverStats.TotalBytes) / 1024 / 1024,
			"bytes_in":    serverStats.TotalBytesIn,
			"bytes_out":   serverStats.TotalBytesOut,
		},
		"requests": map[string]int64{
			"total": serverStats.TotalRequests,
			"dns":   serverStats.TotalDNS,
		},
		"system": map[string]interface{}{
			"goroutines": runtime.NumGoroutine(),
			"cpus":       runtime.NumCPU(),
		},
	}
	serverStats.RUnlock()

	jsonData, _ := json.MarshalIndent(stats, "", "  ")
	send(conn, 200, "application/json", jsonData)
}

func sendUserStats(conn net.Conn) {
	serverStats.RLock()
	users := make([]map[string]interface{}, 0)

	for _, user := range serverStats.Users {
		users = append(users, map[string]interface{}{
			"ip":             user.IP,
			"active_tunnels": user.ActiveTunnels,
			"bytes_in":       user.BytesIn,
			"bytes_out":      user.BytesOut,
			"requests":       user.Requests,
			"first_seen":     user.FirstSeen.Format("15:04:05"),
			"last_seen":      user.LastSeen.Format("15:04:05"),
			"online":         user.ActiveTunnels > 0,
		})
	}
	serverStats.RUnlock()

	response := map[string]interface{}{
		"total_users": len(users),
		"users":       users,
	}

	jsonData, _ := json.MarshalIndent(response, "", "  ")
	send(conn, 200, "application/json", jsonData)
}

func sendVPNStatus(conn net.Conn) {
	serverStats.RLock()
	active := serverStats.ActiveTunnels
	total := serverStats.TotalBytes
	relay := serverStats.TotalRelay
	serverStats.RUnlock()

	online := getOnlineUsers()

	json := fmt.Sprintf(`{"status":"online","version":"%s","online_users":%d,"active_tunnels":%d,"total_bytes":%d,"relay_count":%d}`,
		SERVER_VERSION, online, active, total, relay)
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
	fmt.Printf("[PROXY] %s\n", targetURL)

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
	req.Header.Set("Accept-Language", "pt-PT,pt;q=0.9")
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
			if strings.Contains(urlStr, "facebook.com") ||
				strings.Contains(urlStr, "google") ||
				strings.Contains(urlStr, "analytics") {
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
	active := getActiveUsers()

	serverStats.RLock()
	tunnels := serverStats.ActiveTunnels
	totalMB := float64(serverStats.TotalBytes) / 1024 / 1024
	relay := serverStats.TotalRelay
	uptime := time.Since(serverStats.StartTime)
	serverStats.RUnlock()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet VPN v3</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px;min-height:100vh}
h1{color:#00c853;text-align:center;margin:20px 0}
.status{background:#2d2d44;border-radius:15px;padding:20px;text-align:center;margin:20px auto;max-width:400px}
.online{color:#00c853;font-size:24px;margin-bottom:15px}
.stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.stat{background:#1a1a2e;padding:10px;border-radius:8px}
.stat-label{color:#888;font-size:12px}
.stat-value{color:#fff;font-size:18px;font-weight:bold}
.badge{background:#00c853;color:#000;padding:5px 15px;border-radius:20px;font-size:12px;display:inline-block;margin:10px 0}
</style></head><body>
<h1>🛡️ GratisBet VPN</h1>
<div class="badge">v%s - Relay Mode</div>
<div class="status">
<p class="online">● %d Online</p>
<div class="stats-grid">
<div class="stat"><div class="stat-label">Ativos</div><div class="stat-value">%d</div></div>
<div class="stat"><div class="stat-label">Túneis</div><div class="stat-value">%d</div></div>
<div class="stat"><div class="stat-label">Relay</div><div class="stat-value">%d</div></div>
<div class="stat"><div class="stat-label">Tráfego</div><div class="stat-value">%.1f MB</div></div>
<div class="stat"><div class="stat-label">Uptime</div><div class="stat-value">%s</div></div>
</div>
</div>
</body></html>`, SERVER_VERSION, online, active, tunnels, relay, totalMB, formatDuration(uptime))
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
