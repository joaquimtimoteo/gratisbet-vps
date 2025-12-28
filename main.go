package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// API Keys
const FOOTBALL_API_KEY = "416ad7217f99978b716b399ea3d08edc"
const YOUTUBE_API_KEY = "AIzaSyCxFo3x8k0BCQEEfNQLFS-6HWux4--0sjY"

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

// Estatísticas VPN
var vpnStats = struct {
	sync.RWMutex
	ActiveTunnels int
	TotalBytes    int64
}{}

func main() {
	fmt.Println("══════════════════════════════════════")
	fmt.Println("  GRATISBET VPN SERVER v1.0")
	fmt.Println("  Porta 80 - Proxy + VPN Tunnel")
	fmt.Println("══════════════════════════════════════")

	ln, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Printf("Erro ao iniciar servidor: %v\n", err)
		return
	}
	fmt.Println("  ✓ Porta 80 ativa")
	fmt.Println("  ✓ Proxy:   /proxy?url=...")
	fmt.Println("  ✓ Túnel:   /tunnel")
	fmt.Println("  ✓ Connect: /connect?dest=...")
	fmt.Println("══════════════════════════════════════")

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

	// ============ VPN TUNNEL (POST) ============
	if path == "/tunnel" && method == "POST" {
		handleTunnel(conn, reader, contentLength, remoteIP)
		return
	}

	// ============ VPN CONNECT (GET - conexão persistente) ============
	if strings.HasPrefix(path, "/connect") {
		handleConnect(conn, reader, path, remoteIP)
		return
	}

	// ============ STATUS ============
	if path == "/vpn-status" {
		sendVPNStatus(conn)
		return
	}

	// ============ PROXY EXISTENTE ============
	if path == "/" {
		sendHome(conn)
		return
	}

	if path == "/ping" {
		send(conn, 200, "text/plain", []byte("OK"))
		return
	}

	if strings.HasPrefix(path, "/proxy?url=") {
		doProxy(conn, path, remoteIP)
		return
	}

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

// ════════════════════════════════════════════════════════════════════
//                         VPN TUNNEL HANDLERS
// ════════════════════════════════════════════════════════════════════

/*
Protocolo /tunnel (request-response):

REQUEST:
POST /tunnel HTTP/1.1
Host: saldo.unitel.ao
Content-Length: <len>

[4 bytes: tamanho do destino][destino string][dados]

RESPONSE:
HTTP/1.1 200 OK
Content-Length: <len>

[dados de resposta]
*/

func handleTunnel(conn net.Conn, reader *bufio.Reader, contentLength int, remoteIP string) {
	if contentLength < 5 {
		send(conn, 400, "text/plain", []byte("Invalid tunnel request"))
		return
	}

	// Ler corpo da requisição
	body := make([]byte, contentLength)
	_, err := io.ReadFull(reader, body)
	if err != nil {
		fmt.Printf("[TUNNEL] Erro ao ler body: %v\n", err)
		send(conn, 400, "text/plain", []byte("Read error"))
		return
	}

	// Extrair destino (formato: [4 bytes len][destino][dados])
	if len(body) < 4 {
		send(conn, 400, "text/plain", []byte("Invalid format"))
		return
	}

	destLen := int(binary.BigEndian.Uint32(body[:4]))
	if destLen <= 0 || destLen > 255 || 4+destLen > len(body) {
		send(conn, 400, "text/plain", []byte("Invalid destination"))
		return
	}

	dest := string(body[4 : 4+destLen])
	data := body[4+destLen:]

	fmt.Printf("[TUNNEL] %s -> %s (%d bytes)\n", remoteIP, dest, len(data))

	// Conectar ao destino
	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		fmt.Printf("[TUNNEL] Erro ao conectar %s: %v\n", dest, err)
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}
	defer targetConn.Close()

	// Enviar dados
	if len(data) > 0 {
		targetConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = targetConn.Write(data)
		if err != nil {
			fmt.Printf("[TUNNEL] Erro ao enviar: %v\n", err)
			send(conn, 502, "text/plain", []byte("Write error"))
			return
		}
	}

	// Ler resposta
	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	response, err := io.ReadAll(targetConn)
	if err != nil && len(response) == 0 {
		fmt.Printf("[TUNNEL] Erro ao ler resposta: %v\n", err)
		send(conn, 502, "text/plain", []byte("Read error"))
		return
	}

	// Atualizar estatísticas
	vpnStats.Lock()
	vpnStats.TotalBytes += int64(len(data) + len(response))
	vpnStats.Unlock()

	fmt.Printf("[TUNNEL] Resposta: %d bytes\n", len(response))
	send(conn, 200, "application/octet-stream", response)
}

/*
Protocolo /connect (conexão persistente bidirecional):

REQUEST:
GET /connect?dest=host:port HTTP/1.1
Host: saldo.unitel.ao

RESPONSE (sucesso):
HTTP/1.1 200 Connection Established

[conexão bidirecional mantida aberta]
*/

func handleConnect(conn net.Conn, reader *bufio.Reader, path string, remoteIP string) {
	// Extrair destino da query string
	idx := strings.Index(path, "dest=")
	if idx < 0 {
		send(conn, 400, "text/plain", []byte("Missing dest parameter"))
		return
	}
	dest, _ := url.QueryUnescape(path[idx+5:])

	// Remover qualquer coisa depois do destino (ex: &outros=params)
	if ampIdx := strings.Index(dest, "&"); ampIdx > 0 {
		dest = dest[:ampIdx]
	}

	if dest == "" {
		send(conn, 400, "text/plain", []byte("Empty destination"))
		return
	}

	fmt.Printf("[CONNECT] %s -> %s\n", remoteIP, dest)

	// Conectar ao destino
	targetConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		fmt.Printf("[CONNECT] Erro ao conectar: %v\n", err)
		send(conn, 502, "text/plain", []byte("Connection failed: "+err.Error()))
		return
	}

	// Enviar resposta de sucesso
	response := "HTTP/1.1 200 Connection Established\r\n" +
		"Connection: keep-alive\r\n" +
		"X-VPN: GratisBet\r\n\r\n"
	conn.Write([]byte(response))

	// Atualizar estatísticas
	vpnStats.Lock()
	vpnStats.ActiveTunnels++
	vpnStats.Unlock()

	fmt.Printf("[CONNECT] ✓ Túnel ativo: %s <-> %s\n", remoteIP, dest)

	// Bidirecional - copiar dados em ambas direções
	var wg sync.WaitGroup
	wg.Add(2)

	var bytesUp, bytesDown int64

	// Cliente -> Destino
	go func() {
		defer wg.Done()
		n, _ := io.Copy(targetConn, reader)
		bytesUp = n
		// Fechar escrita no destino quando cliente terminar
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Destino -> Cliente
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, targetConn)
		bytesDown = n
		// Fechar escrita no cliente quando destino terminar
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	targetConn.Close()

	// Atualizar estatísticas
	vpnStats.Lock()
	vpnStats.ActiveTunnels--
	vpnStats.TotalBytes += bytesUp + bytesDown
	vpnStats.Unlock()

	fmt.Printf("[CONNECT] ✗ Túnel fechado: %s (↑%d ↓%d bytes)\n", remoteIP, bytesUp, bytesDown)
}

func sendVPNStatus(conn net.Conn) {
	vpnStats.RLock()
	active := vpnStats.ActiveTunnels
	total := vpnStats.TotalBytes
	vpnStats.RUnlock()

	json := fmt.Sprintf(`{"status":"online","active_tunnels":%d,"total_bytes":%d,"version":"1.0"}`, active, total)
	send(conn, 200, "application/json", []byte(json))
}

// ════════════════════════════════════════════════════════════════════
//                         PROXY EXISTENTE
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
	vpnStats.RLock()
	active := vpnStats.ActiveTunnels
	vpnStats.RUnlock()

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px;min-height:100vh}
h1{color:#00c853;text-align:center;margin:20px 0;font-size:28px}
p{text-align:center;color:#888;margin-bottom:20px}
.status{background:#2d2d44;border-radius:15px;padding:20px;text-align:center;margin:20px auto;max-width:300px}
.online{color:#00c853;font-size:18px}
.stat{color:#888;font-size:14px;margin-top:10px}
.card{background:#2d2d44;border-radius:15px;padding:30px;text-align:center;text-decoration:none;color:#fff;display:block;margin:20px auto;max-width:300px}
.card:active{transform:scale(0.95)}
.icon{font-size:60px;margin-bottom:15px}
.name{font-weight:bold;font-size:20px}
.sub{color:#888;font-size:14px;margin-top:5px}
</style></head><body>
<h1>🛡️ GratisBet VPN</h1>
<p>Internet Grátis em Angola</p>
<div class="status">
<p class="online">● Servidor Online</p>
<p class="stat">Túneis ativos: %d</p>
<p class="stat">Proxy + VPN Tunnel</p>
</div>
<a href="/proxy?url=https%%3A%%2F%%2Fwww.premierbet.co.ao%%2F" class="card">
<div class="icon">👑</div>
<div class="name">PremierBet</div>
<div class="sub">Toque para abrir</div>
</a>
</body></html>`, active)
	send(conn, 200, "text/html; charset=utf-8", []byte(html))
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
