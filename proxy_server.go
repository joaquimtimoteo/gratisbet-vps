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
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║          GRATISBET PROXY SERVER v1.0                      ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Println("║  HTTP:80 + Host: saldo.unitel.ao                          ║")
	fmt.Println("║                                                           ║")
	fmt.Println("║  Casas de Apostas:                                        ║")
	fmt.Println("║  • elephantbet.co.ao                                      ║")
	fmt.Println("║  • premierbet.co.ao                                       ║")
	fmt.Println("║  • bantubet.co.ao                                         ║")
	fmt.Println("║  • kwanzabet.ao                                           ║")
	fmt.Println("║  • elephantbetzone.com                                    ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")

	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		fmt.Println("Erro:", err)
		return
	}
	fmt.Println("\n✅ Porta 80 ativa - Aguardando conexões...\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	
	// Ler primeira linha
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	requestLine = strings.TrimSpace(requestLine)

	// Parse request
	parts := strings.Split(requestLine, " ")
	if len(parts) < 2 {
		return
	}
	method := parts[0]
	path := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}

	remote := conn.RemoteAddr().String()
	fmt.Printf("[%s] %s %s\n", time.Now().Format("15:04:05"), method, path)

	// Rotas
	if path == "/ping" {
		sendResponse(conn, 200, "text/plain", []byte("GRATISBET-PROXY-OK"))
		return
	}

	if path == "/" || path == "/home" {
		sendHomePage(conn)
		return
	}

	if strings.HasPrefix(path, "/proxy") {
		handleProxy(conn, path, headers, remote)
		return
	}

	// 404
	sendResponse(conn, 404, "text/plain", []byte("Not Found"))
}

func handleProxy(conn net.Conn, path string, headers map[string]string, remote string) {
	// Extrair URL do query param
	// /proxy?url=https://www.elephantbet.co.ao/
	
	var targetURL string
	if idx := strings.Index(path, "url="); idx > 0 {
		targetURL = path[idx+4:]
		// Decodificar URL
		if decoded, err := url.QueryUnescape(targetURL); err == nil {
			targetURL = decoded
		}
	}

	if targetURL == "" {
		sendResponse(conn, 400, "text/plain", []byte("Missing url parameter"))
		return
	}

	fmt.Printf("[%s] PROXY: %s\n", time.Now().Format("15:04:05"), targetURL)

	// Fazer request para o site real
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		sendResponse(conn, 500, "text/plain", []byte("Error creating request"))
		return
	}

	// Headers para parecer browser real
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pt-PT,pt;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("[%s] ERRO: %v\n", time.Now().Format("15:04:05"), err)
		sendResponse(conn, 502, "text/plain", []byte("Error fetching URL: "+err.Error()))
		return
	}
	defer resp.Body.Close()

	// Ler body
	var body []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err == nil {
			body, _ = io.ReadAll(gzReader)
			gzReader.Close()
		}
	} else {
		body, _ = io.ReadAll(resp.Body)
	}

	// Reescrever URLs no HTML para passar pelo proxy
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		body = rewriteHTML(body, targetURL)
	}

	fmt.Printf("[%s] RESP: %d bytes\n", time.Now().Format("15:04:05"), len(body))

	// Enviar resposta
	sendResponse(conn, resp.StatusCode, contentType, body)
}

func rewriteHTML(body []byte, baseURL string) []byte {
	html := string(body)

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return body
	}
	baseHost := base.Scheme + "://" + base.Host

	// Reescrever links relativos e absolutos para passar pelo proxy
	// src="/path" -> src="/proxy?url=https://site.com/path"
	// href="/path" -> href="/proxy?url=https://site.com/path"
	
	replacements := []struct {
		old string
		new string
	}{
		{`src="/`, `src="/proxy?url=` + url.QueryEscape(baseHost+"/")},
		{`href="/`, `href="/proxy?url=` + url.QueryEscape(baseHost+"/")},
		{`src="./`, `src="/proxy?url=` + url.QueryEscape(baseHost+"/")},
		{`href="./`, `href="/proxy?url=` + url.QueryEscape(baseHost+"/")},
		{`src="` + baseHost, `src="/proxy?url=` + url.QueryEscape(baseHost)},
		{`href="` + baseHost, `href="/proxy?url=` + url.QueryEscape(baseHost)},
	}

	for _, r := range replacements {
		html = strings.ReplaceAll(html, r.old, r.new)
	}

	// Adicionar base tag para recursos relativos
	if !strings.Contains(html, "<base") {
		html = strings.Replace(html, "<head>", `<head><base href="`+baseHost+`/">`, 1)
	}

	return []byte(html)
}

func sendHomePage(conn net.Conn) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GratisBet - Apostas Grátis</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: white;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 20px 0;
        }
        .header h1 {
            color: #00c853;
            font-size: 28px;
            margin-bottom: 5px;
        }
        .header p {
            color: #888;
            font-size: 14px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            max-width: 500px;
            margin: 20px auto;
        }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 15px;
            padding: 20px;
            text-align: center;
            text-decoration: none;
            color: white;
            transition: transform 0.2s, background 0.2s;
        }
        .card:hover {
            transform: scale(1.02);
            background: rgba(255,255,255,0.15);
        }
        .card .icon {
            font-size: 40px;
            margin-bottom: 10px;
        }
        .card .name {
            font-weight: bold;
            font-size: 14px;
        }
        .elephant { border-left: 4px solid #ff6b35; }
        .premier { border-left: 4px solid #ffd700; }
        .bantu { border-left: 4px solid #00bcd4; }
        .kwanza { border-left: 4px solid #e91e63; }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🎰 GratisBet</h1>
        <p>Internet Grátis para Apostas</p>
    </div>
    
    <div class="grid">
        <a href="/proxy?url=https%3A%2F%2Fwww.elephantbet.co.ao%2F" class="card elephant">
            <div class="icon">🐘</div>
            <div class="name">ElephantBet</div>
        </a>
        
        <a href="/proxy?url=https%3A%2F%2Fwww.premierbet.co.ao%2F" class="card premier">
            <div class="icon">👑</div>
            <div class="name">PremierBet</div>
        </a>
        
        <a href="/proxy?url=http%3A%2F%2Fbantubet.co.ao%2F" class="card bantu">
            <div class="icon">⚽</div>
            <div class="name">BantuBet</div>
        </a>
        
        <a href="/proxy?url=https%3A%2F%2Fwww.kwanzabet.ao%2F" class="card kwanza">
            <div class="icon">💰</div>
            <div class="name">KwanzaBet</div>
        </a>
    </div>
    
    <div class="footer">
        <p>Powered by GratisBet • Internet Grátis Angola</p>
    </div>
</body>
</html>`

	sendResponse(conn, 200, "text/html; charset=utf-8", []byte(html))
}

func sendResponse(conn net.Conn, status int, contentType string, body []byte) {
	statusText := "OK"
	switch status {
	case 400:
		statusText = "Bad Request"
	case 404:
		statusText = "Not Found"
	case 500:
		statusText = "Internal Server Error"
	case 502:
		statusText = "Bad Gateway"
	}

	header := fmt.Sprintf("HTTP/1.1 %d %s\r\n", status, statusText)
	header += fmt.Sprintf("Content-Type: %s\r\n", contentType)
	header += fmt.Sprintf("Content-Length: %d\r\n", len(body))
	header += "Connection: close\r\n"
	header += "Access-Control-Allow-Origin: *\r\n"
	header += "\r\n"

	conn.Write([]byte(header))
	conn.Write(body)
}
