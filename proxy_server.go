
package main

import (
	"bufio"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

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

func main() {
	fmt.Println("══════════════════════════════════════")
	fmt.Println("  GRATISBET PROXY v3.0")
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
	for {
		h, _ := reader.ReadString('\n')
		if strings.TrimSpace(h) == "" {
			break
		}
	}

	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), path)

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
			fmt.Printf("[RESOURCE] %s\n", fullURL)
			doProxyURL(conn, fullURL, remoteIP)
			return
		}
	}

	send(conn, 404, "text/plain", []byte("Not Found"))
}

func isResource(path string) bool {
	exts := []string{".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".json"}
	for _, ext := range exts {
		if strings.Contains(strings.ToLower(path), ext) {
			return true
		}
	}
	prefixes := []string{"/assets/", "/static/", "/css/", "/js/", "/fonts/", "/images/", "/img/", "/api/", "/_next/"}
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

	if parsed, err := url.Parse(targetURL); err == nil {
		base := parsed.Scheme + "://" + parsed.Host
		lastBaseMu.Lock()
		lastBase[remoteIP] = base
		lastBaseMu.Unlock()
	}

	req, _ := http.NewRequest("GET", targetURL, nil)
	
	// Headers para parecer browser real
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Sec-Ch-Ua", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?1")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Android"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	// Referer do mesmo domínio
	if parsed, err := url.Parse(targetURL); err == nil {
		req.Header.Set("Referer", parsed.Scheme+"://"+parsed.Host+"/")
		req.Header.Set("Origin", parsed.Scheme+"://"+parsed.Host)
	}

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
	
	if strings.Contains(ct, "text/html") {
		body = rewriteHTML(body, targetURL)
	}

	fmt.Printf("[SENT] %d bytes (status %d)\n", len(body), resp.StatusCode)
	send(conn, resp.StatusCode, ct, body)
}

func rewriteHTML(body []byte, baseURL string) []byte {
	base, _ := url.Parse(baseURL)
	host := base.Scheme + "://" + base.Host
	html := string(body)

	html = strings.ReplaceAll(html, `href="`+host, `href="/proxy?url=`+url.QueryEscape(host))
	html = strings.ReplaceAll(html, `src="`+host, `src="/proxy?url=`+url.QueryEscape(host))

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
</style></head><body>
<h1>🎰 GratisBet</h1>
<p>Apostas Grátis em Angola</p>
<div class="grid">
<a href="/proxy?url=https%3A%2F%2Fwww.elephantbet.co.ao%2F" class="card"><div class="icon">🐘</div><div class="name">ElephantBet</div></a>
<a href="/proxy?url=https%3A%2F%2Fwww.premierbet.co.ao%2F" class="card"><div class="icon">👑</div><div class="name">PremierBet</div></a>
<a href="/proxy?url=http%3A%2F%2Fbantubet.co.ao%2F" class="card"><div class="icon">⚽</div><div class="name">BantuBet</div></a>
<a href="/proxy?url=https%3A%2F%2Fwww.kwanzabet.ao%2F" class="card"><div class="icon">💰</div><div class="name">KwanzaBet</div></a>
</div>
</body></html>`
	send(conn, 200, "text/html; charset=utf-8", []byte(html))
}

func send(conn net.Conn, code int, ct string, body []byte) {
	status := map[int]string{200: "OK", 304: "Not Modified", 400: "Bad Request", 403: "Forbidden", 404: "Not Found", 502: "Bad Gateway"}[code]
	if status == "" {
		status = "OK"
	}
	h := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n", code, status, ct, len(body))
	conn.Write([]byte(h))
	conn.Write(body)
}
