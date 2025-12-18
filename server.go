package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/things-go/go-socks5"
	"github.com/xtaci/smux"
)

var (
	currentConnections int64 = 0
	maxConnections     int64 = 5000
	sniConnections     int64 = 0
	fetchConnections   int64 = 0
)

const (
	listenIP        = "0.0.0.0"
	listenPort      = 80
	listenPortTLS   = 443
	listenIPSocks   = "127.0.0.1"
	listenPortSocks = 8999
	bufferSize      = 16 * 1024
	readHeaderLimit = 8 * 1024
	connDialTimeout = 8 * time.Second

	user     = "sung"
	password = "123.456"
	sniHost  = "signup.ao"
	vpsIP    = "216.106.176.133"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, bufferSize)
		return &b
	},
}

var logger = log.New(os.Stdout, "", log.LstdFlags)
var globalCert *tls.Certificate

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true,
	},
}

func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.MaxReceiveBuffer = 64 * 1024
	cfg.MaxStreamBuffer = 64 * 1024
	cfg.KeepAliveTimeout = 2 * time.Minute
	return cfg
}

func generateCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   sniHost,
			Organization: []string{"GratisBet"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sniHost, "www." + sniHost, "*." + sniHost, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(vpsIP)},
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func readRequestHeaders(r *bufio.Reader, limit int) (string, string, map[string]string, error) {
	hdrs := make(map[string]string)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", "", nil, err
	}

	parts := strings.Fields(line)
	method, path := "", ""
	if len(parts) >= 2 {
		method = strings.ToUpper(parts[0])
		path = parts[1]
	}

	total := len(line)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return method, path, hdrs, err
		}
		total += len(line)
		if total > limit {
			return method, path, hdrs, errors.New("header too large")
		}
		if line == "\r\n" {
			break
		}
		if strings.Contains(line, ":") {
			p := strings.SplitN(line, ":", 2)
			k := strings.ToLower(strings.TrimSpace(p[0]))
			v := strings.TrimSpace(p[1])
			hdrs[k] = v
		}
	}
	return method, path, hdrs, nil
}

func proxyCopy(dst net.Conn, src net.Conn, cancel context.CancelFunc) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	_, _ = io.CopyBuffer(dst, src, *bufp)
	if cancel != nil {
		cancel()
	}
}

func handleSession(ctx context.Context, session *smux.Session) {
	defer session.Close()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go func(s *smux.Stream) {
				defer func() { recover() }()
				if s == nil {
					return
				}
				dialer := net.Dialer{Timeout: connDialTimeout, KeepAlive: 30 * time.Second}
				socksConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks))
				if err != nil {
					s.Close()
					return
				}
				ctxC, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() {
					proxyCopy(socksConn, s, cancel)
					socksConn.Close()
					s.Close()
				}()
				proxyCopy(s, socksConn, cancel)
				socksConn.Close()
				s.Close()
				<-ctxC.Done()
			}(stream)
		}
	}
}

func createBridge(conn net.Conn) {
	logger.Printf("[!] SMUX iniciado: %s\n", conn.RemoteAddr().String())
	atomic.AddInt64(&currentConnections, 1)
	defer func() {
		atomic.AddInt64(&currentConnections, -1)
		conn.Close()
	}()

	session, err := smux.Server(conn, newSmuxConfig())
	if err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-ctx.Done()
		session.Close()
	}()
	handleSession(ctx, session)
}

// ============================================
// HANDLE FETCH - VERSÃO 3.0 COM GZIP
// ============================================
func handleFetch(conn net.Conn, targetURL string, tag string) {
	atomic.AddInt64(&fetchConnections, 1)

	decoded, err := url.QueryUnescape(targetURL)
	if err != nil {
		decoded = targetURL
	}

	logger.Printf("[%s] ♦ FETCH: %s\n", tag, decoded)

	req, err := http.NewRequest("GET", decoded, nil)
	if err != nil {
		sendError(conn, 400, "URL inválida")
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("[%s] ♦ Fetch error: %v\n", tag, err)
		sendError(conn, 502, "Fetch failed")
		return
	}
	defer resp.Body.Close()

	// Ler body completo
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		sendError(conn, 502, "Read failed")
		return
	}

	logger.Printf("[%s] ♦ Original: %d bytes (status %d)\n", tag, len(body), resp.StatusCode)

	// ⭐⭐⭐ COMPRIMIR COM GZIP ⭐⭐⭐
	var compressedBody bytes.Buffer
	gzWriter := gzip.NewWriter(&compressedBody)
	gzWriter.Write(body)
	gzWriter.Close()

	compressed := compressedBody.Bytes()
	logger.Printf("[%s] ♦ Compressed: %d bytes (%.1f%% reduction)\n", tag, len(compressed), 100-float64(len(compressed))*100/float64(len(body)))

	// Content-Type
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html"
	}

	// Construir response com GZIP
	headers := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Encoding: gzip\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"X-Original-Size: %d\r\n"+
		"\r\n",
		resp.StatusCode, http.StatusText(resp.StatusCode),
		contentType,
		len(compressed),
		len(body))

	// Configurar socket
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetLinger(10) // Esperar até 10s para enviar dados pendentes
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetLinger(10)
		}
	}

	// Enviar headers
	_, err = conn.Write([]byte(headers))
	if err != nil {
		logger.Printf("[%s] ♦ Header write error: %v\n", tag, err)
		return
	}

	// Enviar body comprimido em chunks pequenos com delays
	chunkSize := 8192 // 8KB chunks
	for i := 0; i < len(compressed); i += chunkSize {
		end := i + chunkSize
		if end > len(compressed) {
			end = len(compressed)
		}

		_, err = conn.Write(compressed[i:end])
		if err != nil {
			logger.Printf("[%s] ♦ Body write error at %d: %v\n", tag, i, err)
			return
		}

		// Pequeno delay entre chunks para não sobrecarregar a rede
		if i+chunkSize < len(compressed) {
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Esperar antes de fechar
	time.Sleep(500 * time.Millisecond)

	logger.Printf("[%s] ♦ SENT OK: %d bytes compressed\n", tag, len(compressed))
}

func sendError(conn net.Conn, code int, msg string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	conn.Write([]byte(response))
	time.Sleep(50 * time.Millisecond)
}

func clientHandler(conn net.Conn, isTLS bool) {
	defer func() {
		if r := recover(); r != nil {
			conn.Close()
		}
	}()

	tag := "HTTP"
	if isTLS {
		tag = "TLS"
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	method, path, hdrs, err := readRequestHeaders(r, readHeaderLimit)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	logger.Printf("[%s] %s %s from %s\n", tag, method, path, conn.RemoteAddr())

	// /fetch
	if method == "GET" && strings.HasPrefix(path, "/fetch") {
		var reqUser, reqPass, targetURL string
		if idx := strings.Index(path, "?"); idx > 0 {
			params, _ := url.ParseQuery(path[idx+1:])
			reqUser = params.Get("user")
			reqPass = params.Get("password")
			targetURL = params.Get("url")
		}

		if reqUser != user || reqPass != password {
			sendError(conn, 403, "Auth failed")
			conn.Close()
			return
		}

		if targetURL == "" {
			sendError(conn, 400, "Missing url")
			conn.Close()
			return
		}

		handleFetch(conn, targetURL, tag)
		conn.Close()
		return
	}

	// /status
	if method == "GET" && (path == "/status" || path == "/users") {
		status := fmt.Sprintf(`{"status":"ok","version":"3.0-gzip","sni":"%s","conns":%d,"fetch":%d}`,
			sniHost, atomic.LoadInt64(&currentConnections), atomic.LoadInt64(&fetchConnections))
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(status), status)))
		conn.Close()
		return
	}

	// /health
	if method == "GET" && (path == "/" || path == "/health") {
		status := fmt.Sprintf("GratisBet Server v3.0-gzip\nStatus: OK\nGZIP: Enabled\nConns: %d",
			atomic.LoadInt64(&currentConnections))
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(status), status)))
		conn.Close()
		return
	}

	// WebSocket/SMUX
	if v, ok := hdrs["upgrade"]; ok && strings.Contains(strings.ToLower(v), "websocket") {
		if atomic.LoadInt64(&currentConnections) >= maxConnections {
			conn.Write([]byte("HTTP/1.1 503 Full\r\n\r\n"))
			conn.Close()
			return
		}
		reqUser := hdrs["user"]
		reqPass := hdrs["password"]
		if reqUser != user || reqPass != password {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			conn.Close()
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		createBridge(conn)
		return
	}

	sendError(conn, 404, "Not Found")
	conn.Close()
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🎰 GRATISBET VPS SERVER v3.0-gzip                 ║
║                                                           ║
║   ⭐ GZIP COMPRESSION ENABLED!                           ║
║   📦 191KB → ~30KB (redução de ~85%)                     ║
║                                                           ║
║   HTTP: 80  |  TLS: 443  |  SOCKS: 8999                  ║
╚═══════════════════════════════════════════════════════════╝
`)

	logger.Printf("[!] Inicializando servidor v3.0-gzip\n")

	// SOCKS5
	server := socks5.NewServer(socks5.WithLogger(socks5.NewLogger(logger)))
	go func() {
		logger.Printf("[!] SOCKS5 na porta %d\n", listenPortSocks)
		server.ListenAndServe("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks))
	}()

	if len(os.Args) > 1 {
		if val, err := strconv.ParseInt(os.Args[1], 10, 64); err == nil && val > 0 {
			maxConnections = val
		}
	}

	// HTTP
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPort))
	if err != nil {
		logger.Printf("[!] HTTP port %d error: %v\n", listenPort, err)
	} else {
		logger.Printf("[!] HTTP na porta %d\n", listenPort)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetNoDelay(true)
				}
				go clientHandler(conn, false)
			}
		}()
	}

	// TLS
	cert, err := generateCert()
	if err != nil {
		logger.Printf("[!] Cert error: %v\n", err)
	} else {
		globalCert = &cert
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni := info.ServerName
				if sni == "" {
					sni = "(empty)"
				}
				logger.Printf("[SNI] Recebido: %s ← ACEITO!\n", sni)
				atomic.AddInt64(&sniConnections, 1)
				return globalCert, nil
			},
		}

		tlsLn, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPortTLS), tlsConfig)
		if err != nil {
			logger.Printf("[!] TLS port %d error: %v\n", listenPortTLS, err)
		} else {
			logger.Printf("[!] TLS na porta %d (SNI Spoofing ATIVO!)\n", listenPortTLS)
			go func() {
				for {
					conn, err := tlsLn.Accept()
					if err != nil {
						continue
					}
					go clientHandler(conn, true)
				}
			}()
		}
	}

	logger.Println("")
	logger.Println("[!] ⭐ GZIP ENABLED - Compressão ativa!")
	logger.Println("[!] Servidor pronto!")
	logger.Println("")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Println("\n[!] Shutdown...")
}
