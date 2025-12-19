package main

import (
	"bufio"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

/*
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v5.0 - UNIFICADO                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Endpoints:                                                                   ║
║    /search  → Busca DuckDuckGo (< 500 bytes) ✅                               ║
║    /fetch   → HTTP Proxy                                                      ║
║    /vpn     → VPN Custom Protocol (WebSocket)                                 ║
║    /ssh     → SSH Bridge (WebSocket)                                          ║
║    /        → SSH Bridge (HTTP Injector payload)                              ║
║    /health  → Status JSON                                                     ║
║                                                                               ║
║  Auth:                                                                        ║
║    API: user=sung&password=123.456 ou X-Auth: sung:123.456                   ║
║    SSH: gratisbet / gratisbet123                                             ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/

// ============================================
// CONFIGURAÇÃO
// ============================================
var config = struct {
	IP       string
	SNI      string
	APIUsers map[string]string
}{
	IP:  "216.106.176.133",
	SNI: "www.signup.ao",
	APIUsers: map[string]string{
		"sung":       "123.456",
		"user_admin": "Q7!mA9#KpR2$VxL@eT6Z",
	},
}

// ============================================
// MÉTRICAS
// ============================================
type Metrics struct {
	SearchReqs  int64
	FetchReqs   int64
	VPNConns    int64
	SSHConns    int64
	BytesIn     int64
	BytesOut    int64
	AuthFailed  int64
	ActiveConns int64
}

var metrics = &Metrics{}
var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

// ============================================
// HTTP CLIENT
// ============================================
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	},
}

// ============================================
// AUTENTICAÇÃO
// ============================================
func authenticate(user, pass string) bool {
	if expected, ok := config.APIUsers[user]; ok {
		return expected == pass
	}
	return false
}

func authFromRequest(r *http.Request) bool {
	// Método 1: Header X-Auth
	if auth := r.Header.Get("X-Auth"); auth != "" {
		parts := strings.SplitN(auth, ":", 2)
		if len(parts) == 2 {
			return authenticate(parts[0], parts[1])
		}
	}

	// Método 2: Query params
	user := r.URL.Query().Get("user")
	pass := r.URL.Query().Get("password")
	return authenticate(user, pass)
}

// ============================================
// SEARCH - DuckDuckGo (< 500 bytes)
// ============================================
func handleSearch(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&metrics.SearchReqs, 1)

	query := r.URL.Query().Get("q")
	if query == "" {
		w.Write([]byte("ERRO|Query vazia"))
		return
	}

	logger.Printf("[SEARCH] q=%s", query)

	// DuckDuckGo HTML lite
	ddgURL := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(query))

	req, _ := http.NewRequest("GET", ddgURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")

	resp, err := httpClient.Do(req)
	if err != nil {
		w.Write([]byte("ERRO|Falha na busca"))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	// Extrair resultados
	results := extractDDGResults(html)

	// Formatar resposta compacta
	response := formatResults(query, results)

	logger.Printf("[SEARCH] results=%d size=%d", len(results), len(response))

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

type SearchResult struct {
	Title string
	URL   string
}

func extractDDGResults(html string) []SearchResult {
	var results []SearchResult

	// DuckDuckGo HTML: <a class="result__a" href="...">Title</a>
	re := regexp.MustCompile(`<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>([^<]+)</a>`)
	matches := re.FindAllStringSubmatch(html, 10)

	for i, m := range matches {
		if i >= 5 {
			break
		}
		title := cleanHTML(m[2])
		rawURL := m[1]

		// DuckDuckGo usa redirect, extrair URL real
		if strings.Contains(rawURL, "uddg=") {
			if u, err := url.Parse(rawURL); err == nil {
				if uddg := u.Query().Get("uddg"); uddg != "" {
					rawURL = uddg
				}
			}
		}

		if title != "" && len(title) > 5 {
			results = append(results, SearchResult{Title: title, URL: rawURL})
		}
	}

	return results
}

func cleanHTML(s string) string {
	re := regexp.MustCompile(`<[^>]*>`)
	s = re.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	return strings.TrimSpace(s)
}

func formatResults(query string, results []SearchResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("OK|%s|%d\n", query, len(results)))

	for i, r := range results {
		title := r.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, title))
	}

	if len(results) == 0 {
		sb.WriteString("Sem resultados.\n")
	}

	result := sb.String()
	if len(result) > 450 {
		result = result[:450]
	}

	return result
}

// ============================================
// FETCH - HTTP Proxy
// ============================================
func handleFetch(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&metrics.FetchReqs, 1)

	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing url", http.StatusBadRequest)
		return
	}

	decoded, _ := url.QueryUnescape(targetURL)
	if decoded != "" {
		targetURL = decoded
	}

	logger.Printf("[FETCH] %s", targetURL)

	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36")
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copiar headers relevantes
	for _, h := range []string{"Content-Type", "Content-Length"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}

	// Comprimir se não vier comprimido
	if resp.Header.Get("Content-Encoding") != "gzip" {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		io.Copy(gz, resp.Body)
		gz.Close()
	} else {
		io.Copy(w, resp.Body)
	}
}

// ============================================
// VPN - Custom Protocol (WebSocket)
// ============================================
const (
	VPN_SEND_DELAY = 50 * time.Millisecond
	VPN_MAX_CHUNK  = 200
)

type VPNSession struct {
	conn     net.Conn
	streams  map[uint16]net.Conn
	mu       sync.RWMutex
	writeMu  sync.Mutex
	lastSend time.Time
}

func (s *VPNSession) sendFrame(id uint16, data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	elapsed := time.Since(s.lastSend)
	if elapsed < VPN_SEND_DELAY {
		time.Sleep(VPN_SEND_DELAY - elapsed)
	}

	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)

	writeWSFrame(s.conn, frame)
	s.lastSend = time.Now()
	logger.Printf("[VPN-TX] id=%d len=%d", id, len(data))
}

func handleVPN(conn net.Conn) {
	atomic.AddInt64(&metrics.VPNConns, 1)
	atomic.AddInt64(&metrics.ActiveConns, 1)
	defer atomic.AddInt64(&metrics.ActiveConns, -1)

	s := &VPNSession{
		conn:     conn,
		streams:  make(map[uint16]net.Conn),
		lastSend: time.Now(),
	}

	logger.Printf("[VPN] Conectado")

	for {
		frame, err := readWSFrame(conn)
		if err != nil {
			break
		}
		if len(frame) < 4 {
			continue
		}

		id := binary.BigEndian.Uint16(frame[0:2])
		length := binary.BigEndian.Uint16(frame[2:4])
		data := frame[4 : 4+length]

		logger.Printf("[VPN-RX] id=%d len=%d", id, length)

		s.mu.RLock()
		target := s.streams[id]
		s.mu.RUnlock()

		// CONNECT
		if target == nil && len(data) >= 4 {
			port := binary.BigEndian.Uint16(data[1:3])
			hostLen := data[3]
			host := string(data[4 : 4+hostLen])
			logger.Printf("[VPN-CONNECT] %s:%d", host, port)

			target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
			if err != nil {
				s.sendFrame(id, []byte{0x01})
				continue
			}

			s.mu.Lock()
			s.streams[id] = target
			s.mu.Unlock()

			s.sendFrame(id, []byte{0x00})

			// Reader goroutine
			go func(id uint16, t net.Conn) {
				defer func() {
					s.sendFrame(id, []byte{})
					s.mu.Lock()
					delete(s.streams, id)
					s.mu.Unlock()
					t.Close()
				}()

				buf := make([]byte, VPN_MAX_CHUNK)
				for {
					t.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := t.Read(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						break
					}
					if n > 0 {
						s.sendFrame(id, buf[:n])
					}
				}
			}(id, target)

		} else if target != nil {
			if len(data) == 0 {
				target.Close()
				s.mu.Lock()
				delete(s.streams, id)
				s.mu.Unlock()
			} else {
				target.Write(data)
			}
		}
	}

	s.mu.Lock()
	for _, t := range s.streams {
		t.Close()
	}
	s.mu.Unlock()
	logger.Printf("[VPN] Desconectado")
}

// ============================================
// SSH BRIDGE
// ============================================
func handleSSHBridge(conn net.Conn, isWebSocket bool) {
	atomic.AddInt64(&metrics.SSHConns, 1)
	atomic.AddInt64(&metrics.ActiveConns, 1)
	defer atomic.AddInt64(&metrics.ActiveConns, -1)

	logger.Printf("[SSH] Bridge iniciando (ws=%v)", isWebSocket)

	// Conectar ao SSH local
	ssh, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		logger.Printf("[SSH] Conexão local falhou: %v", err)
		return
	}
	defer ssh.Close()

	logger.Printf("[SSH] Bridge estabelecida")

	done := make(chan struct{})

	if isWebSocket {
		// WebSocket mode
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				data, err := readWSFrame(conn)
				if err != nil {
					return
				}
				ssh.Write(data)
			}
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 4096)
			for {
				n, err := ssh.Read(buf)
				if err != nil {
					return
				}
				writeWSFrame(conn, buf[:n])
			}
		}()
	} else {
		// Raw TCP mode (HTTP Injector)
		go func() {
			defer func() { done <- struct{}{} }()
			io.Copy(ssh, conn)
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			io.Copy(conn, ssh)
		}()
	}

	<-done
	logger.Printf("[SSH] Bridge encerrada")
}

// ============================================
// WEBSOCKET HELPERS
// ============================================
func wsHandshake(conn net.Conn, key string) {
	magic := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"

	conn.Write([]byte(response))
}

func readWSFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	masked := (header[1] & 0x80) != 0
	length := int(header[1] & 0x7F)

	if length == 126 {
		ext := make([]byte, 2)
		io.ReadFull(conn, ext)
		length = int(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		io.ReadFull(conn, ext)
		length = int(binary.BigEndian.Uint64(ext))
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		io.ReadFull(conn, mask)
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

func writeWSFrame(conn net.Conn, data []byte) error {
	length := len(data)
	var header []byte

	if length < 126 {
		header = []byte{0x82, byte(length)}
	} else if length < 65536 {
		header = []byte{0x82, 126, byte(length >> 8), byte(length)}
	} else {
		header = make([]byte, 10)
		header[0] = 0x82
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:], uint64(length))
	}

	conn.Write(header)
	_, err := conn.Write(data)
	return err
}

// ============================================
// HANDLER PRINCIPAL
// ============================================
func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	reader := bufio.NewReader(conn)

	// Ler primeira linha
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	method := parts[0]
	path := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			headers[key] = val
		}
	}

	logger.Printf("[REQ] %s %s", method, path)

	// Reset deadline
	conn.SetDeadline(time.Time{})

	// Routing
	isWebSocket := strings.ToLower(headers["upgrade"]) == "websocket"

	switch {
	// VPN WebSocket
	case isWebSocket && (path == "/vpn" || strings.HasPrefix(path, "/vpn?")):
		// Verificar auth
		auth := headers["x-auth"]
		if auth == "" {
			// Tentar query param
			if idx := strings.Index(path, "?"); idx > 0 {
				if u, err := url.Parse(path); err == nil {
					auth = u.Query().Get("user") + ":" + u.Query().Get("password")
				}
			}
		}
		if auth != "sung:123.456" && auth != "user_admin:Q7!mA9#KpR2$VxL@eT6Z" {
			conn.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
			atomic.AddInt64(&metrics.AuthFailed, 1)
			return
		}
		wsHandshake(conn, headers["sec-websocket-key"])
		handleVPN(conn)

	// SSH WebSocket
	case isWebSocket && (path == "/ssh" || path == "/ws"):
		wsHandshake(conn, headers["sec-websocket-key"])
		handleSSHBridge(conn, true)

	// HTTP routes - criar fake request
	case path == "/search" || strings.HasPrefix(path, "/search?"):
		handleHTTPRoute(conn, method, path, headers, "search")

	case path == "/fetch" || strings.HasPrefix(path, "/fetch?"):
		handleHTTPRoute(conn, method, path, headers, "fetch")

	case path == "/health" || path == "/status":
		sendStatus(conn)

	// Default: SSH Bridge (HTTP Injector)
	default:
		// Responder 200 OK e iniciar bridge
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		handleSSHBridge(conn, false)
	}
}

func handleHTTPRoute(conn net.Conn, method, path string, headers map[string]string, route string) {
	// Parse URL
	u, _ := url.Parse("http://localhost" + path)

	// Verificar auth
	user := u.Query().Get("user")
	pass := u.Query().Get("password")
	if !authenticate(user, pass) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		atomic.AddInt64(&metrics.AuthFailed, 1)
		return
	}

	// Criar ResponseWriter fake
	rw := &fakeResponseWriter{conn: conn, headers: make(http.Header)}
	req := &http.Request{
		Method: method,
		URL:    u,
		Header: make(http.Header),
	}

	switch route {
	case "search":
		handleSearch(rw, req)
	case "fetch":
		handleFetch(rw, req)
	}

	rw.finish()
}

type fakeResponseWriter struct {
	conn       net.Conn
	headers    http.Header
	statusCode int
	buf        []byte
}

func (w *fakeResponseWriter) Header() http.Header {
	return w.headers
}

func (w *fakeResponseWriter) Write(data []byte) (int, error) {
	w.buf = append(w.buf, data...)
	return len(data), nil
}

func (w *fakeResponseWriter) WriteHeader(code int) {
	w.statusCode = code
}

func (w *fakeResponseWriter) finish() {
	if w.statusCode == 0 {
		w.statusCode = 200
	}

	// Escrever response
	fmt.Fprintf(w.conn, "HTTP/1.1 %d OK\r\n", w.statusCode)
	for k, v := range w.headers {
		fmt.Fprintf(w.conn, "%s: %s\r\n", k, strings.Join(v, ","))
	}
	fmt.Fprintf(w.conn, "Content-Length: %d\r\n", len(w.buf))
	fmt.Fprintf(w.conn, "Connection: close\r\n\r\n")
	w.conn.Write(w.buf)
}

func sendStatus(conn net.Conn) {
	status := fmt.Sprintf(`{
  "status": "ok",
  "version": "5.0",
  "features": ["search", "fetch", "vpn", "ssh-bridge"],
  "metrics": {
    "search_requests": %d,
    "fetch_requests": %d,
    "vpn_connections": %d,
    "ssh_connections": %d,
    "active_connections": %d,
    "auth_failed": %d
  }
}`,
		atomic.LoadInt64(&metrics.SearchReqs),
		atomic.LoadInt64(&metrics.FetchReqs),
		atomic.LoadInt64(&metrics.VPNConns),
		atomic.LoadInt64(&metrics.SSHConns),
		atomic.LoadInt64(&metrics.ActiveConns),
		atomic.LoadInt64(&metrics.AuthFailed),
	)

	conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
	conn.Write([]byte("Content-Type: application/json\r\n"))
	conn.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", len(status))))
	conn.Write([]byte("Connection: close\r\n\r\n"))
	conn.Write([]byte(status))
}

// ============================================
// CERTIFICADO TLS
// ============================================
func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: config.SNI},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{
			config.SNI,
			"www." + config.SNI,
			"m." + config.SNI,
			"web.whatsapp.com",
			"www.facebook.com",
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP(config.IP),
		},
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ============================================
// MAIN
// ============================================
func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v5.0 - UNIFICADO                         ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Endpoints:                                                                   ║
║    /search  → Busca DuckDuckGo (< 500 bytes)                                  ║
║    /fetch   → HTTP Proxy                                                      ║
║    /vpn     → VPN Custom (WebSocket)                                          ║
║    /ssh     → SSH Bridge (WebSocket)                                          ║
║    /        → SSH Bridge (HTTP Injector)                                      ║
║    /health  → Status JSON                                                     ║
║                                                                               ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  HTTP Injector Config:                                                        ║
║    SSH Host: 216.106.176.133:443                                              ║
║    Username: gratisbet | Password: gratisbet123                               ║
║    SSL: ON | SNI: www.signup.ao                                               ║
║    Payload: GET / HTTP/1.1[crlf]Host: www.signup.ao[crlf][crlf]              ║
╚═══════════════════════════════════════════════════════════════════════════════╝`)

	// Verificar SSH local
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second); err != nil {
		logger.Println("[WARN] SSH não detectado em 127.0.0.1:22")
		logger.Println("[WARN] SSH Bridge não vai funcionar!")
		logger.Println("[INFO] Execute: apt install openssh-server && systemctl start sshd")
	} else {
		conn.Close()
		logger.Println("[OK] SSH detectado em 127.0.0.1:22")
	}

	// Certificado TLS
	cert, err := generateCert()
	if err != nil {
		logger.Fatal("Erro certificado:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s ← OK", info.ServerName)
			return &cert, nil
		},
		MinVersion: tls.VersionTLS12,
	}

	// Listener TLS :443
	listener, err := tls.Listen("tcp", ":443", tlsConfig)
	if err != nil {
		logger.Fatal("Erro listener:", err)
	}
	defer listener.Close()

	logger.Println("[OK] Servidor iniciado na porta 443")
	logger.Printf("[OK] SNI: %s", config.SNI)

	// Accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleConnection(conn)
		}
	}()

	// HTTP :80 (opcional, para debug)
	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("GratisBet v5.0 - Use TLS:443"))
		})
		http.ListenAndServe(":80", nil)
	}()

	logger.Println("[OK] Servidor pronto!")

	// Wait for signal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	fmt.Println("\n[!] Encerrando...")
}
