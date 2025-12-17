package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ============================================
// CONFIGURAÇÃO - ALTERE AQUI SE NECESSÁRIO
// ============================================
const (
	HTTP_PORT    = 8080
	TLS_PORT     = 443
	AUTH_USER    = "user_admin"
	AUTH_PASS    = "Q7!mA9#KpR2$VxL@eT6Z"
	VPS_IP       = "216.106.176.133"
	SNI_HOST     = "signup.ao"
	BUFFER_SIZE  = 32 * 1024
	DIAL_TIMEOUT = 10
)

// ============================================
// MÉTRICAS GLOBAIS
// ============================================
type Metrics struct {
	currentConns int64
	totalConns   int64
	tunnelConns  int64
	tlsConns     int64
	httpConns    int64
	fetchConns   int64
	bytesRx      int64
	bytesTx      int64
}

var (
	metrics = &Metrics{}
	logger  = log.New(os.Stdout, "[GRATISBET] ", log.LstdFlags|log.Lmsgprefix)
	bufPool = sync.Pool{
		New: func() interface{} {
			buf := make([]byte, BUFFER_SIZE)
			return &buf
		},
	}
	// Cliente HTTP para fazer requisições externas
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
)

// ============================================
// AUTENTICAÇÃO
// ============================================
func authenticate(user, password string) bool {
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(AUTH_USER)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(AUTH_PASS)) == 1
	return userOK && passOK
}

// ============================================
// RELAY DE DADOS
// ============================================
func relay(dst, src net.Conn, direction string, wg *sync.WaitGroup) {
	defer wg.Done()

	bufPtr := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufPtr)

	n, _ := io.CopyBuffer(dst, src, *bufPtr)

	if direction == "rx" {
		atomic.AddInt64(&metrics.bytesRx, n)
	} else {
		atomic.AddInt64(&metrics.bytesTx, n)
	}
}

// ============================================
// HANDLER DO TUNNEL (com suporte a FETCH)
// ============================================
func handleTunnel(conn net.Conn, clientIP string, isTLS bool) {
	atomic.AddInt64(&metrics.tunnelConns, 1)
	atomic.AddInt64(&metrics.currentConns, 1)
	defer atomic.AddInt64(&metrics.currentConns, -1)

	reader := bufio.NewReader(conn)

	tag := ""
	if isTLS {
		tag = "[TLS] "
	}

	for {
		// Ler comando
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		cmd := strings.TrimSpace(line)
		logger.Printf("📥 %s[TUNNEL] %s: %s", tag, clientIP, cmd)

		// ============================================
		// Comando: CONNECT host:port (TCP relay)
		// ============================================
		if strings.HasPrefix(cmd, "CONNECT ") {
			target := strings.TrimPrefix(cmd, "CONNECT ")
			target = strings.TrimSpace(target)
			if !strings.Contains(target, ":") {
				target = target + ":80"
			}

			dest, err := net.DialTimeout("tcp", target, DIAL_TIMEOUT*time.Second)
			if err != nil {
				logger.Printf("❌ %s[TUNNEL] Erro conectando a %s: %v", tag, target, err)
				conn.Write([]byte("ERROR: " + err.Error() + "\n"))
				return
			}
			defer dest.Close()

			conn.Write([]byte("OK\n"))
			logger.Printf("✅ %s[TUNNEL] CONNECT %s → %s", tag, clientIP, target)

			var wg sync.WaitGroup
			wg.Add(2)
			go relay(dest, conn, "rx", &wg)
			go relay(conn, dest, "tx", &wg)
			wg.Wait()

			logger.Printf("🔌 %s[TUNNEL] Fechado: %s → %s", tag, clientIP, target)
			return
		}

		// ============================================
		// Comando: FETCH url (HTTP Proxy)
		// ============================================
		if strings.HasPrefix(cmd, "FETCH ") {
			atomic.AddInt64(&metrics.fetchConns, 1)
			targetURL := strings.TrimPrefix(cmd, "FETCH ")
			targetURL = strings.TrimSpace(targetURL)

			logger.Printf("🌐 %s[FETCH] %s → %s", tag, clientIP, targetURL)

			// Fazer requisição HTTP
			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				errMsg := fmt.Sprintf("ERROR: invalid url: %s\n", err.Error())
				conn.Write([]byte(errMsg))
				logger.Printf("❌ %s[FETCH] URL inválida: %v", tag, err)
				continue
			}

			// Headers para parecer navegador real
			req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("Cache-Control", "no-cache")

			resp, err := httpClient.Do(req)
			if err != nil {
				errMsg := fmt.Sprintf("ERROR: fetch failed: %s\n", err.Error())
				conn.Write([]byte(errMsg))
				logger.Printf("❌ %s[FETCH] Erro: %v", tag, err)
				continue
			}

			// Enviar status line
			statusLine := fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, resp.Status)
			conn.Write([]byte(statusLine))

			// Enviar headers importantes
			contentType := resp.Header.Get("Content-Type")
			if contentType != "" {
				conn.Write([]byte(fmt.Sprintf("Content-Type: %s\r\n", contentType)))
			}
			contentLength := resp.Header.Get("Content-Length")
			if contentLength != "" {
				conn.Write([]byte(fmt.Sprintf("Content-Length: %s\r\n", contentLength)))
			}

			// Fim dos headers
			conn.Write([]byte("\r\n"))

			// Enviar body
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			n, _ := conn.Write(bodyBytes)
			atomic.AddInt64(&metrics.bytesTx, int64(n))

			logger.Printf("✅ %s[FETCH] %s → %d bytes (status: %d)", tag, targetURL, n, resp.StatusCode)

			// Continuar no loop para mais comandos
			continue
		}

		// ============================================
		// Comando: CLOSE (encerrar túnel)
		// ============================================
		if cmd == "CLOSE" {
			conn.Write([]byte("OK\n"))
			logger.Printf("🔌 %s[TUNNEL] Cliente fechou conexão: %s", tag, clientIP)
			return
		}

		// Comando desconhecido
		conn.Write([]byte("ERROR: unknown command. Use: CONNECT host:port | FETCH url | CLOSE\n"))
	}
}

// ============================================
// LER HEADERS HTTP
// ============================================
func readHTTPRequest(reader *bufio.Reader) (method, target string, headers map[string]string, err error) {
	headers = make(map[string]string)

	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", nil, err
	}

	parts := strings.Fields(line)
	if len(parts) >= 2 {
		method = parts[0]
		target = parts[1]
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return method, target, headers, err
		}

		if line == "\r\n" || line == "\n" {
			break
		}

		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	return method, target, headers, nil
}

// ============================================
// HANDLER PRINCIPAL
// ============================================
func handleClient(conn net.Conn, isTLS bool) {
	defer conn.Close()

	atomic.AddInt64(&metrics.totalConns, 1)
	if isTLS {
		atomic.AddInt64(&metrics.tlsConns, 1)
	} else {
		atomic.AddInt64(&metrics.httpConns, 1)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(conn)
	method, target, headers, err := readHTTPRequest(reader)
	if err != nil {
		return
	}

	conn.SetReadDeadline(time.Time{})

	clientIP := conn.RemoteAddr().String()
	if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
		clientIP = clientIP[:idx]
	}

	tag := "HTTP"
	if isTLS {
		tag = "TLS"
	}

	logger.Printf("📥 [%s] %s %s from %s", tag, method, target, clientIP)

	// ============================================
	// ROTA: /tunnel - Túnel proxy
	// ============================================
	if strings.ToUpper(method) == "GET" && strings.HasPrefix(target, "/tunnel") {
		var user, password string

		if idx := strings.Index(target, "?"); idx > 0 {
			params, _ := url.ParseQuery(target[idx+1:])
			user = params.Get("user")
			password = params.Get("password")
		}

		if !authenticate(user, password) {
			logger.Printf("🚫 [%s] Auth FAILED: %s", tag, clientIP)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nAuthentication failed"))
			return
		}

		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tunnel\r\nConnection: Upgrade\r\n\r\n"))
		logger.Printf("✅ [%s] Auth OK: %s", tag, clientIP)

		handleTunnel(conn, clientIP, isTLS)
		return
	}

	// ============================================
	// ROTA: /fetch?url=... - HTTP Proxy direto
	// ============================================
	if strings.ToUpper(method) == "GET" && strings.HasPrefix(target, "/fetch") {
		var user, password, targetURL string

		if idx := strings.Index(target, "?"); idx > 0 {
			params, _ := url.ParseQuery(target[idx+1:])
			user = params.Get("user")
			password = params.Get("password")
			targetURL = params.Get("url")
		}

		if !authenticate(user, password) {
			logger.Printf("🚫 [%s] Auth FAILED: %s", tag, clientIP)
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}

		if targetURL == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nMissing 'url' parameter"))
			return
		}

		// Decodificar URL
		decodedURL, err := url.QueryUnescape(targetURL)
		if err != nil {
			decodedURL = targetURL
		}

		atomic.AddInt64(&metrics.fetchConns, 1)
		logger.Printf("🌐 [%s] FETCH: %s → %s", tag, clientIP, decodedURL)

		// Fazer requisição
		req, err := http.NewRequest("GET", decodedURL, nil)
		if err != nil {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\nInvalid URL"))
			return
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")

		resp, err := httpClient.Do(req)
		if err != nil {
			errBody := fmt.Sprintf("Fetch error: %s", err.Error())
			conn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\n\r\n%s", len(errBody), errBody)))
			return
		}
		defer resp.Body.Close()

		// Enviar resposta
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))))

		for key, values := range resp.Header {
			for _, value := range values {
				conn.Write([]byte(fmt.Sprintf("%s: %s\r\n", key, value)))
			}
		}
		conn.Write([]byte("\r\n"))

		n, _ := io.Copy(conn, resp.Body)
		atomic.AddInt64(&metrics.bytesTx, n)

		logger.Printf("✅ [%s] FETCH OK: %d bytes", tag, n)
		return
	}

	// ============================================
	// ROTA: /health ou / - Health check
	// ============================================
	if strings.ToUpper(method) == "GET" && (target == "/" || target == "/health") {
		body := fmt.Sprintf(`GratisBet VPS Server v1.1
========================
Status: OK
IP: %s
TLS: %v
SNI: %s

Estatísticas:
- Conexões ativas: %d
- Total conexões: %d
- Túneis: %d
- Fetch: %d
- TLS: %d
- HTTP: %d
- RX: %.2f MB
- TX: %.2f MB

Comandos do Túnel:
- CONNECT host:port  (TCP relay)
- FETCH url          (HTTP proxy)
- CLOSE              (encerrar)
`,
			VPS_IP,
			isTLS,
			SNI_HOST,
			atomic.LoadInt64(&metrics.currentConns),
			atomic.LoadInt64(&metrics.totalConns),
			atomic.LoadInt64(&metrics.tunnelConns),
			atomic.LoadInt64(&metrics.fetchConns),
			atomic.LoadInt64(&metrics.tlsConns),
			atomic.LoadInt64(&metrics.httpConns),
			float64(atomic.LoadInt64(&metrics.bytesRx))/1024/1024,
			float64(atomic.LoadInt64(&metrics.bytesTx))/1024/1024,
		)

		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		conn.Write([]byte(response))
		return
	}

	// ============================================
	// ROTA: /status - JSON status
	// ============================================
	if strings.ToUpper(method) == "GET" && target == "/status" {
		body := fmt.Sprintf(`{"status":"ok","version":"1.1","ip":"%s","tls":%v,"sni":"%s","conns":%d,"total":%d,"tunnels":%d,"fetch":%d,"tls_conns":%d,"http_conns":%d,"rx_mb":%.2f,"tx_mb":%.2f}`,
			VPS_IP,
			isTLS,
			SNI_HOST,
			atomic.LoadInt64(&metrics.currentConns),
			atomic.LoadInt64(&metrics.totalConns),
			atomic.LoadInt64(&metrics.tunnelConns),
			atomic.LoadInt64(&metrics.fetchConns),
			atomic.LoadInt64(&metrics.tlsConns),
			atomic.LoadInt64(&metrics.httpConns),
			float64(atomic.LoadInt64(&metrics.bytesRx))/1024/1024,
			float64(atomic.LoadInt64(&metrics.bytesTx))/1024/1024,
		)

		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		conn.Write([]byte(response))
		return
	}

	// ============================================
	// 404 - Rota não encontrada
	// ============================================
	body := "404 Not Found - GratisBet VPS v1.1"
	response := fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	conn.Write([]byte(response))
}

// ============================================
// GERAR CERTIFICADO TLS AUTO-ASSINADO
// ============================================
func generateSelfSignedCert() (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("erro gerando chave: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   SNI_HOST,
			Organization: []string{"GratisBet VPS"},
			Country:      []string{"AO"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames: []string{
			SNI_HOST,
			"*." + SNI_HOST,
			"localhost",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP(VPS_IP),
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("erro criando certificado: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("erro serializando chave: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ============================================
// MAIN
// ============================================
func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║           🎰 GRATISBET VPS SERVER v1.1                   ║
║         HTTP (8080) + TLS (443) + FETCH                  ║
║                  SNI: signup.ao                           ║
╚═══════════════════════════════════════════════════════════╝`)

	// ============================================
	// INICIAR HTTP LISTENER (porta 8080)
	// ============================================
	httpAddr := fmt.Sprintf("0.0.0.0:%d", HTTP_PORT)
	httpListener, err := net.Listen("tcp", httpAddr)
	if err != nil {
		logger.Fatalf("❌ Erro HTTP listener: %v", err)
	}
	logger.Printf("🚀 HTTP: %s", httpAddr)

	go func() {
		for {
			conn, err := httpListener.Accept()
			if err != nil {
				continue
			}

			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(true)
				tcpConn.SetKeepAlivePeriod(30 * time.Second)
			}

			go handleClient(conn, false)
		}
	}()

	// ============================================
	// INICIAR TLS LISTENER (porta 443)
	// ============================================
	cert, err := generateSelfSignedCert()
	if err != nil {
		logger.Printf("⚠️ Erro gerando certificado TLS: %v", err)
		logger.Printf("⚠️ TLS desabilitado, apenas HTTP disponível")
	} else {
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		tlsAddr := fmt.Sprintf("0.0.0.0:%d", TLS_PORT)
		tlsListener, err := tls.Listen("tcp", tlsAddr, tlsConfig)
		if err != nil {
			logger.Printf("⚠️ Erro TLS listener: %v", err)
			logger.Printf("⚠️ TLS desabilitado (porta 443 pode estar em uso)")
		} else {
			logger.Printf("🔐 TLS: %s (SNI: %s)", tlsAddr, SNI_HOST)

			go func() {
				for {
					conn, err := tlsListener.Accept()
					if err != nil {
						continue
					}
					go handleClient(conn, true)
				}
			}()
		}
	}

	// ============================================
	// INFO
	// ============================================
	logger.Println("")
	logger.Printf("🌐 VPS IP: %s", VPS_IP)
	logger.Printf("🔐 Auth: %s / [hidden]", AUTH_USER)
	logger.Println("")
	logger.Println("📱 Endpoints:")
	logger.Printf("   • Tunnel: /tunnel?user=...&password=...")
	logger.Printf("   • Fetch:  /fetch?user=...&password=...&url=...")
	logger.Printf("   • Health: /health")
	logger.Printf("   • Status: /status")
	logger.Println("")
	logger.Println("📡 Comandos do Túnel:")
	logger.Println("   • CONNECT host:port  → TCP relay direto")
	logger.Println("   • FETCH url          → HTTP proxy (resolve SSL)")
	logger.Println("   • CLOSE              → Encerrar conexão")
	logger.Println("")
	logger.Println("✅ Servidor iniciado! Aguardando conexões...")
	logger.Println("")

	// ============================================
	// STATS TICKER
	// ============================================
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			logger.Printf("📊 Stats: Conns=%d | Tunnels=%d | Fetch=%d | RX=%.2fMB | TX=%.2fMB",
				atomic.LoadInt64(&metrics.currentConns),
				atomic.LoadInt64(&metrics.tunnelConns),
				atomic.LoadInt64(&metrics.fetchConns),
				float64(atomic.LoadInt64(&metrics.bytesRx))/1024/1024,
				float64(atomic.LoadInt64(&metrics.bytesTx))/1024/1024,
			)
		}
	}()

	// ============================================
	// GRACEFUL SHUTDOWN
	// ============================================
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Println("")
	logger.Println("🛑 Encerrando servidor...")
	httpListener.Close()
	logger.Println("👋 Servidor encerrado!")
}
