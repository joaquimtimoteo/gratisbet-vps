package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
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
const SERVER_VERSION = "2.1"

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

// Informação de cada usuário conectado
type UserInfo struct {
	IP            string
	FirstSeen     time.Time
	LastSeen      time.Time
	ActiveTunnels int
	BytesIn       int64
	BytesOut      int64
	Requests      int64
}

// Estatísticas globais do servidor
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
	Users          map[string]*UserInfo // IP -> UserInfo
	PeakUsers      int
	PeakTunnels    int
}{
	Users: make(map[string]*UserInfo),
}

// Registrar atividade de usuário
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
		// Verificar pico de usuários
		if len(serverStats.Users) > serverStats.PeakUsers {
			serverStats.PeakUsers = len(serverStats.Users)
		}
	}
}

// Registrar início de túnel
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

// Registrar fim de túnel
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

// Registrar DNS
func trackDNS() {
	serverStats.Lock()
	serverStats.TotalDNS++
	serverStats.Unlock()
}

// Limpar usuários inativos (mais de 30 minutos sem atividade)
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

// Contar usuários ativos (com túnel ou atividade nos últimos 5 min)
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

// Contar usuários online (com túnel ativo)
func getOnlineUsers() int {
	serverStats.RLock()
	defer serverStats.RUnlock()

	count := 0
	for _, user := range serverStats.Users {
		if user.ActiveTunnels > 0 {
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
	fmt.Println("  GRATISBET VPN SERVER version" + SERVER_VERSION)
	fmt.Println("  Porta 80 - Proxy + VPN Tunnel + Stats")
	fmt.Println("══════════════════════════════════════════════")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Erro ao iniciar servidor: %v\n", err)
		return
	}

	fmt.Println("  ✓ Porta 80 ativa")
	fmt.Println("  ✓ Proxy:       /proxy?url=...")
	fmt.Println("  ✓ Túnel:       /tunnel")
	fmt.Println("  ✓ VPN Connect: /vpn-connect")
	fmt.Println("  ✓ Stats:       /stats")
	fmt.Println("  ✓ Status:      /vpn-status")
	fmt.Println("══════════════════════════════════════════════")

	// Goroutine para limpar usuários inativos
	go cleanupInactiveUsers()

	// Goroutine para log periódico
	go func() {
		for {
			time.Sleep(60 * time.Second)
			online := getOnlineUsers()
			active := getActiveUsers()
			serverStats.RLock()
			tunnels := serverStats.ActiveTunnels
			totalMB := float64(serverStats.TotalBytes) / 1024 / 1024
			serverStats.RUnlock()
			fmt.Printf("[STATS] Online: %d | Ativos: %d | Túneis: %d | Total: %.2f MB\n",
				online, active, tunnels, totalMB)
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

	// Registrar usuário
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

	// Ler headers
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

	fmt.Printf("[%s] %s %s from %s\n", time.Now().Format("15:04:05"), method, path, remoteIP)

	// ============ ROTAS ============

	switch {
	case path == "/tunnel" && method == "POST":
		handleTunnel(conn, reader, contentLength, remoteIP)

	case path == "/vpn-connect" || strings.HasPrefix(path, "/vpn-connect"):
		dest := headers["x-dest"]
		if dest == "" {
			send(conn, 400, "text/plain", []byte("Missing X-Dest header"))
			return
		}
		handleVpnConnect(conn, reader, dest, remoteIP)

	case strings.HasPrefix(path, "/connect"):
		handleConnect(conn, reader, path, headers, remoteIP)

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
				fmt.Printf("[RES] %s\n", fullURL)
				doProxyURL(conn, fullURL, remoteIP)
				return
			}
		}
		send(conn, 404, "text/plain", []byte("Not Found"))
	}
}

// ════════════════════════════════════════════════════════════════════
//                         ENDPOINTS DE ESTATÍSTICAS
// ════════════════════════════════════════════════════════════════════

func sendStats(conn net.Conn) {
	serverStats.RLock()
	uptime := time.Since(serverStats.StartTime)
	
	onlineUsers := 0
	activeUsers := 0
	cutoff := time.Now().Add(-5 * time.Minute)
	for _, user := range serverStats.Users {
		if user.ActiveTunnels > 0 {
			onlineUsers++
		}
		if user.ActiveTunnels > 0 || user.LastSeen.After(cutoff) {
			activeUsers++
		}
	}
	
	stats := map[string]interface{}{
		"status":  "online",
		"version": SERVER_VERSION,
		"uptime":  uptime.String(),
		"uptime_seconds": int64(uptime.Seconds()),
		"users": map[string]int{
			"online":     onlineUsers,
			"active":     activeUsers,
			"total":      len(serverStats.Users),
			"peak":       serverStats.PeakUsers,
		},
		"tunnels": map[string]interface{}{
			"active": serverStats.ActiveTunnels,
			"total":  serverStats.TotalTunnels,
			"peak":   serverStats.PeakTunnels,
		},
		"traffic": map[string]interface{}{
			"total_bytes":    serverStats.TotalBytes,
			"total_mb":       float64(serverStats.TotalBytes) / 1024 / 1024,
			"bytes_in":       serverStats.TotalBytesIn,
			"bytes_out":      serverStats.TotalBytesOut,
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
	serverStats.RUnlock()

	online := getOnlineUsers()

	json := fmt.Sprintf(`{"status":"online","version":"%s","online_users":%d,"active_tunnels":%d,"total_bytes":%d}`,
		SERVER_VERSION, online, active, total)
	send(conn, 200, "application/json", []byte(json))
}

// ════════════════════════════════════════════════════════════════════
//                         VPN TUNNEL HANDLERS
// ════════════════════════════════════════════════════════════════════

func handleTunnel(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	if contentLength < 3 {
		send(conn, 400, "text/plain", []byte("Invalid tunnel request"))
		return
	}

	body := make([]byte, contentLength)
	_, err := io.ReadFull(reader, body)
	if err != nil {
		fmt.Printf("[TUNNEL] Erro ao ler body: %v\n", err)
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
		fmt.Printf("[TUNNEL] Erro ao conectar %s: %v\n", dest, err)
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}
	defer targetConn.Close()

	if len(data) > 0 {
		targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = targetConn.Write(data)
		if err != nil {
			fmt.Printf("[TUNNEL] Erro ao enviar: %v\n", err)
			send(conn, 502, "text/plain", []byte("Write error"))
			return
		}
	}

	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response, err := io.ReadAll(targetConn)
	if err != nil && len(response) == 0 {
		fmt.Printf("[TUNNEL] Erro ao ler resposta: %v\n", err)
		send(conn, 502, "text/plain", []byte("Read error"))
		return
	}

	// Registrar tráfego
	trackTunnelStart(remoteIP)
	trackTunnelEnd(remoteIP, int64(len(data)), int64(len(response)))

	fmt.Printf("[TUNNEL] Resposta: %d bytes\n", len(response))
	send(conn, 200, "application/octet-stream", response)
}

func handleDNS(dest string, query []byte) []byte {
	dnsServer := "8.8.8.8:53"

	if strings.HasPrefix(dest, "10.") || strings.HasPrefix(dest, "192.168.") || strings.HasPrefix(dest, "172.") {
		fmt.Printf("[DNS] Ignorando IP privado %s, usando %s\n", dest, dnsServer)
	} else if dest != "8.8.8.8:53" && dest != "8.8.4.4:53" {
		dnsServer = dest
	}

	udpConn, err := net.DialTimeout("udp", dnsServer, 5*time.Second)
	if err != nil {
		fmt.Printf("[DNS] Erro ao conectar %s: %v\n", dnsServer, err)
		return []byte{}
	}
	defer udpConn.Close()

	udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = udpConn.Write(query)
	if err != nil {
		fmt.Printf("[DNS] Erro ao enviar: %v\n", err)
		return []byte{}
	}

	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 512)
	n, err := udpConn.Read(response)
	if err != nil {
		fmt.Printf("[DNS] Erro ao ler: %v\n", err)
		return []byte{}
	}

	return response[:n]
}

func handleVpnConnect(conn net.Conn, reader *bufio.Reader, dest string, remoteIP string) {
	fmt.Printf("[VPN-CONNECT] %s -> %s\n", remoteIP, dest)

	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		fmt.Printf("[VPN-CONNECT] Erro ao conectar: %v\n", err)
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}

	response := "HTTP/1.1 200 Connection Established\r\n" +
		"Connection: keep-alive\r\n" +
		"X-VPN: GratisBet\r\n\r\n"
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

func handleConnect(conn net.Conn, reader *bufio.Reader, path string, headers map[string]string, remoteIP string) {
	dest := headers["x-dest"]

	if dest == "" {
		idx := strings.Index(path, "dest=")
		if idx >= 0 {
			dest, _ = url.QueryUnescape(path[idx+5:])
			if ampIdx := strings.Index(dest, "&"); ampIdx > 0 {
				dest = dest[:ampIdx]
			}
		}
	}

	if dest == "" {
		send(conn, 400, "text/plain", []byte("Missing dest parameter or X-Dest header"))
		return
	}

	fmt.Printf("[CONNECT] %s -> %s\n", remoteIP, dest)

	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		fmt.Printf("[CONNECT] Erro ao conectar: %v\n", err)
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}

	response := "HTTP/1.1 200 Connection Established\r\n" +
		"Connection: keep-alive\r\n" +
		"X-VPN: GratisBet\r\n\r\n"
	conn.Write([]byte(response))

	trackTunnelStart(remoteIP)

	fmt.Printf("[CONNECT] ✓ Túnel ativo: %s <-> %s\n", remoteIP, dest)

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

	fmt.Printf("[CONNECT] ✗ Túnel fechado: %s (↑%d ↓%d bytes)\n", remoteIP, bytesUp, bytesDown)
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
	prefixes := []string{"/assets/", "/static/", "/css/", "/js/", "/fonts/", "/images/", "/img/", "/api/", "/_next/", "/favicon"}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
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

	isFootballAPI := strings.Contains(targetURL, "api-sports.io") || strings.Contains(targetURL, "api-football")
	isYouTubeAPI := strings.Contains(targetURL, "googleapis.com/youtube")
	isBeSoccer := strings.Contains(targetURL, "besoccer.com")

	if isFootballAPI {
		req.Header.Set("x-rapidapi-key", FOOTBALL_API_KEY)
		req.Header.Set("x-rapidapi-host", "v3.football.api-sports.io")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "GratisBet/1.0")
	} else if isYouTubeAPI {
		if !strings.Contains(targetURL, "key=") {
			if strings.Contains(targetURL, "?") {
				targetURL = targetURL + "&key=" + YOUTUBE_API_KEY
			} else {
				targetURL = targetURL + "?key=" + YOUTUBE_API_KEY
			}
			req, _ = http.NewRequest("GET", targetURL, nil)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "GratisBet/1.0")
	} else if isBeSoccer {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7")
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Cache-Control", "no-cache")
		req.Header.Set("Pragma", "no-cache")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Referer", "https://pt.besoccer.com/")
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "pt-PT,pt;q=0.9,en;q=0.8")
		req.Header.Set("Accept-Encoding", "gzip")
		req.Header.Set("Referer", base+"/")
		req.Header.Set("Origin", base)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ERR] %v\n", err)
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

	if strings.Contains(ct, "text/html") && !isFootballAPI && !isYouTubeAPI && !isBeSoccer {
		body = rewriteHTML(body, base)
	}

	if strings.Contains(ct, "text/css") {
		body = rewriteCSS(body, base)
	}

	fmt.Printf("[SENT] %d bytes (status %d)\n", len(body), resp.StatusCode)
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
				strings.Contains(urlStr, "analytics") ||
				strings.Contains(urlStr, "gtm") {
				return fmt.Sprintf(`%s=""`, attr)
			}
			return fmt.Sprintf(`%s="/proxy?url=%s"`, attr, url.QueryEscape(urlStr))
		}
		return match
	})

	html = strings.ReplaceAll(html, `src="/`, `src="/proxy?url=`+encodedBase+`%2F`)
	html = strings.ReplaceAll(html, `href="/`, `href="/proxy?url=`+encodedBase+`%2F`)

	html = regexp.MustCompile(`<script[^>]*facebook[^>]*>.*?</script>`).ReplaceAllString(html, "")
	html = regexp.MustCompile(`<script[^>]*gtm[^>]*>.*?</script>`).ReplaceAllString(html, "")

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
	uptime := time.Since(serverStats.StartTime)
	serverStats.RUnlock()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px;min-height:100vh}
h1{color:#00c853;text-align:center;margin:20px 0;font-size:28px}
p{text-align:center;color:#888;margin-bottom:20px}
.status{background:#2d2d44;border-radius:15px;padding:20px;text-align:center;margin:20px auto;max-width:350px}
.online{color:#00c853;font-size:24px;margin-bottom:15px}
.stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:left}
.stat{background:#1a1a2e;padding:10px;border-radius:8px}
.stat-label{color:#888;font-size:12px}
.stat-value{color:#fff;font-size:18px;font-weight:bold}
.card{background:#2d2d44;border-radius:15px;padding:30px;text-align:center;text-decoration:none;color:#fff;display:block;margin:20px auto;max-width:300px}
.card:active{transform:scale(0.95)}
.icon{font-size:60px;margin-bottom:15px}
.name{font-weight:bold;font-size:20px}
.sub{color:#888;font-size:14px;margin-top:5px}
.version{color:#666;font-size:12px;text-align:center;margin-top:20px}
</style></head><body>
<h1>🛡️ GratisBet VPN</h1>
<p>Internet Grátis em Angola</p>
<div class="status">
<p class="online">● %d Usuários Online</p>
<div class="stats-grid">
<div class="stat"><div class="stat-label">Ativos (5min)</div><div class="stat-value">%d</div></div>
<div class="stat"><div class="stat-label">Túneis</div><div class="stat-value">%d</div></div>
<div class="stat"><div class="stat-label">Tráfego</div><div class="stat-value">%.1f MB</div></div>
<div class="stat"><div class="stat-label">Uptime</div><div class="stat-value">%s</div></div>
</div>
</div>
<a href="/proxy?url=https%%3A%%2F%%2Fwww.premierbet.co.ao%%2F" class="card">
<div class="icon">👑</div>
<div class="name">PremierBet</div>
<div class="sub">Toque para abrir</div>
</a>
<p class="version">GratisBet VPN Server v%s</p>
</body></html>`, online, active, tunnels, totalMB, formatDuration(uptime), SERVER_VERSION)
	send(conn, 200, "text/html; charset=utf-8", []byte(html))
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	if h > 0 {
		return fmt.Sprintf("%dh%dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
}

func send(conn net.Conn, code int, ct string, body []byte) {
	status := map[int]string{200: "OK", 304: "Not Modified", 400: "Bad Request", 404: "Not Found", 502: "Bad Gateway"}[code]
	if status == "" {
		status = "OK"
	}
	h := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n", code, status, ct, len(body))
	conn.Write([]byte(h))
	conn.Write(body)
}
