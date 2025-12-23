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
	"regexp"
	"strings"
	"sync"
	"time"
)


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

func main() {
	fmt.Println("══════════════════════════════════════")
	fmt.Println("  GRATISBET PROXY v6.0")
	fmt.Println("  + Football API + YouTube API")
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

	// Recursos com base guardada
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
	
	// Detectar API Football
	isFootballAPI := strings.Contains(targetURL, "api-sports.io") || strings.Contains(targetURL, "api-football")
	
	// Detectar YouTube API
	isYouTubeAPI := strings.Contains(targetURL, "googleapis.com/youtube")
	
	if isFootballAPI {
		// Headers para API Football
		req.Header.Set("x-rapidapi-key", FOOTBALL_API_KEY)
		req.Header.Set("x-rapidapi-host", "v3.football.api-sports.io")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "GratisBet/1.0")
		fmt.Printf("[API-FOOTBALL] Com API key\n")
	} else if isYouTubeAPI {
		// YouTube API - adicionar key se não tiver
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
		fmt.Printf("[YOUTUBE-API] Request\n")
	} else {
		// Headers normais de browser
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
	
	// Reescrever HTML para usar proxy em TODOS os URLs (não para APIs)
	if strings.Contains(ct, "text/html") && !isFootballAPI && !isYouTubeAPI {
		body = rewriteHTML(body, base)
	}
	
	// Reescrever CSS para URLs de fonts/images
	if strings.Contains(ct, "text/css") {
		body = rewriteCSS(body, base)
	}

	fmt.Printf("[SENT] %d bytes (status %d)\n", len(body), resp.StatusCode)
	send(conn, resp.StatusCode, ct, body)
}

func rewriteHTML(body []byte, base string) []byte {
	html := string(body)
	encodedBase := url.QueryEscape(base)

	// Converter URLs absolutas HTTPS para proxy
	re1 := regexp.MustCompile(`(src|href)="(https?://[^"]+)"`)
	html = re1.ReplaceAllStringFunc(html, func(match string) string {
		parts := re1.FindStringSubmatch(match)
		if len(parts) == 3 {
			attr := parts[1]
			urlStr := parts[2]
			// Ignorar tracking pixels, analytics
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

	// Converter URLs relativas para absolutas via proxy
	html = strings.ReplaceAll(html, `src="/`, `src="/proxy?url=`+encodedBase+`%2F`)
	html = strings.ReplaceAll(html, `href="/`, `href="/proxy?url=`+encodedBase+`%2F`)
	
	// Remover scripts de tracking
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
	html := `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>GratisBet</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:sans-serif;background:#1a1a2e;color:#fff;padding:20px;min-height:100vh}
h1{color:#00c853;text-align:center;margin:20px 0;font-size:28px}
p{text-align:center;color:#888;margin-bottom:20px}
.card{background:#2d2d44;border-radius:15px;padding:30px;text-align:center;text-decoration:none;color:#fff;display:block;margin:20px auto;max-width:300px}
.card:active{transform:scale(0.95)}
.icon{font-size:60px;margin-bottom:15px}
.name{font-weight:bold;font-size:20px}
.sub{color:#888;font-size:14px;margin-top:5px}
</style></head><body>
<h1>🎰 GratisBet</h1>
<p>Internet Grátis em Angola</p>
<a href="/proxy?url=https%3A%2F%2Fwww.premierbet.co.ao%2F" class="card">
<div class="icon">👑</div>
<div class="name">PremierBet</div>
<div class="sub">Toque para abrir</div>
</a>
</body></html>`
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
