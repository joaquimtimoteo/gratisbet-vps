package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Guardar última base URL por IP
var lastBase = make(map[string]string)
var lastBaseMu sync.RWMutex

func main() {
	fmt.Println("══════════════════════════════════════")
	fmt.Println("  GRATISBET PROXY v2.0")
	fmt.Println("══════════════════════════════════════")

	ln, _ := net.Listen("tcp", ":80")
	fmt.Println("  Porta 80 ativa...")

	for {
		conn, _ := ln.Accept()
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	
	remote := conn.RemoteAddr().String()
	remoteIP := strings.Split(remote, ":")[0]

	line, _ := reader.ReadString('\n')
	parts := strings.Split(strings.TrimSpace(line), " ")
	if len(parts) < 2 {
		return
	}
	path := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		h, _ := reader.ReadString('\n')
		h = strings.TrimSpace(h)
		if h == "" {
			break
		}
		if idx := strings.Index(h, ":"); idx > 0 {
			key := strings.ToLower(h[:idx])
			val := strings.TrimSpace(h[idx+1:])
			headers[key] = val
		}
	}

	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), path)

	// Página inicial
	if path == "/" {
		sendHome(conn)
		return
	}

	// Ping
	if path == "/ping" {
		send(conn, 200, "text/plain", []byte("OK"))
		return
	}

	// Proxy explícito
	if strings.HasPrefix(path, "/proxy?url=") {
		doProxy(conn, path, remoteIP)
		return
	}

	// Recursos (CSS, JS, fonts, images) - usar última base
	if isResource(path) {
		lastBaseMu.RLock()
		base := lastBase[remoteIP]
		lastBaseMu.RUnlock()
		
		if base != "" {
			// Construir URL completa
			fullURL := base + path
			fmt.Printf("[RESOURCE] %s -> %s\n", path, fullURL)
			doProxyURL(conn, fullURL, remoteIP)
			return
		}
	}

	// 404
	send(conn, 404, "text/plain", []byte("Not Found: "+path))
}

func isResource(path string) bool {
	exts := []string{".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp"}
	for _, ext := range exts {
		if strings.HasSuffix(strings.ToLower(path), ext) {
			return true
		}
	}
	// Também paths comuns de assets
	if strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/static/") || 
	   strings.HasPrefix(path, "/css/") || strings.HasPrefix(path, "/js/") ||
	   strings.HasPrefix(path, "/fonts/") || strings.HasPrefix(path, "/images/") ||
	   strings.HasPrefix(path, "/img/") {
		return true
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

	// Guardar base URL
	if parsed, err := url.Parse(targetURL); err == nil {
		base := parsed.Scheme + "://" + parsed.Host
		lastBaseMu.Lock()
		lastBase[remoteIP] = base
		lastBaseMu.Unlock()
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10) Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[ERROR] %v\n", err)
		send(conn, 502, "text/plain", []byte("Error: "+err.Error()))
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
	
	// Rewrite HTML para usar proxy
	if strings.Contains(ct, "text/html") {
		body = rewriteHTML(body, targetURL)
	}

	fmt.Printf("[SENT] %d bytes (%s)\n", len(body), ct)
	send(conn, resp.StatusCode, ct, body)
}

func rewriteHTML(body []byte, baseURL string) []byte {
	base, _ := url.Parse(baseURL)
	host := base.Scheme + "://" + base.Host
	html := string(body)

	// Rewrite absolute URLs
	html = strings.ReplaceAll(html, `href="`+host, `href="/proxy?url=`+url.QueryEscape(host))
	html = strings.ReplaceAll(html, `src="`+host, `src="/proxy?url=`+url.QueryEscape(host))
	
	// Rewrite relative URLs - deixar como estão para serem interceptados
	// O servidor vai usar lastBase para resolver

	return []byte(html)
}

func sendHome(conn net.Conn) {
	html := `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px;min-height:100vh}
h1{color:#00c853;text-align:center;margin:20px 0;font-size:28px}
p{text-align:center;color:#888;margin-bottom:20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:15px;max-width:400px;margin:0 auto}
.card{background:#2d2d44;border-radius:15px;padding:25px;text-align:center;text-decoration:none;color:#fff;transition:transform 0.2s}
.card:active{transform:scale(0.95)}
.icon{font-size:50px;margin-bottom:10px}
.name{font-weight:bold;font-size:16px}
.footer{text-align:center;margin-top:30px;color:#666;font-size:12px}
</style></head><body>
<h1>🎰 GratisBet</h1>
<p>Apostas Grátis em Angola</p>
<div class="grid">
<a href="/proxy?url=https%3A%2F%2Fwww.elephantbet.co.ao%2F" class="card"><div class="icon">🐘</div><div class="name">ElephantBet</div></a>
<a href="/proxy?url=https%3A%2F%2Fwww.premierbet.co.ao%2F" class="card"><div class="icon">👑</div><div class="name">PremierBet</div></a>
<a href="/proxy?url=http%3A%2F%2Fbantubet.co.ao%2F" class="card"><div class="icon">⚽</div><div class="name">BantuBet</div></a>
<a href="/proxy?url=https%3A%2F%2Fwww.kwanzabet.ao%2F" class="card"><div class="icon">💰</div><div class="name">KwanzaBet</div></a>
</div>
<div class="footer">Internet Grátis via saldo.unitel.ao</div>
</body></html>`
	send(conn, 200, "text/html; charset=utf-8", []byte(html))
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
