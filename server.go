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
	user            = "sung"
	password        = "123.456"
	sniHost         = "signup.ao"
	vpsIP           = "216.106.176.133"
)

var bufPool = sync.Pool{New: func() interface{} { b := make([]byte, bufferSize); return &b }}
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
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: sniHost, Organization: []string{"GratisBet"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sniHost, "www." + sniHost, "*." + sniHost},
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
			hdrs[strings.ToLower(strings.TrimSpace(p[0]))] = strings.TrimSpace(p[1])
		}
	}
	return method, path, hdrs, nil
}

func proxyCopy(dst net.Conn, src net.Conn, cancel context.CancelFunc) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	io.CopyBuffer(dst, src, *bufp)
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
// HANDLE FETCH v3.2 - SIMPLE WITH CONTENT-LENGTH
// Sem chunked, sem delays - o mais simples possível
// ============================================
func handleFetch(conn net.Conn, targetURL string, tag string) {
	atomic.AddInt64(&fetchConnections, 1)

	decoded, _ := url.QueryUnescape(targetURL)
	if decoded == "" {
		decoded = targetURL
	}

	logger.Printf("[%s] ♦ FETCH: %s\n", tag, decoded)

	req, err := http.NewRequest("GET", decoded, nil)
	if err != nil {
		sendError(conn, 400, "URL inválida")
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,*/*")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("[%s] ♦ Fetch error: %v\n", tag, err)
		sendError(conn, 502, "Fetch failed")
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logger.Printf("[%s] ♦ Original: %d bytes (status %d)\n", tag, len(body), resp.StatusCode)

	// GZIP com compressão máxima
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.Write(body)
	gz.Close()
	compressed := buf.Bytes()

	logger.Printf("[%s] ♦ Compressed: %d bytes (%.0f%% reduction)\n", tag, len(compressed), 100-float64(len(compressed))*100/float64(len(body)))

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/html; charset=utf-8"
	}

	// Response simples com Content-Length
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

	// Configurar TCP
	setTCPOptions := func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetWriteBuffer(65536)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(10 * time.Second)
		}
	}
	
	setTCPOptions(conn)
	if tlsConn, ok := conn.(*tls.Conn); ok {
		setTCPOptions(tlsConn.NetConn())
	}

	// Enviar headers
	_, err = conn.Write([]byte(headers))
	if err != nil {
		logger.Printf("[%s] ♦ Header write error: %v\n", tag, err)
		return
	}

	// Enviar body em chunks de 4KB
	sent := 0
	chunkSize := 4096
	for i := 0; i < len(compressed); i += chunkSize {
		end := i + chunkSize
		if end > len(compressed) {
			end = len(compressed)
		}
		n, err := conn.Write(compressed[i:end])
		if err != nil {
			logger.Printf("[%s] ♦ Write error at %d: %v\n", tag, sent, err)
			return
		}
		sent += n
	}

	// Aguardar um pouco antes de fechar
	time.Sleep(500 * time.Millisecond)

	logger.Printf("[%s] ♦ SENT OK: %d bytes\n", tag, sent)
}

func sendError(conn net.Conn, code int, msg string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	conn.Write([]byte(response))
}

func clientHandler(conn net.Conn, isTLS bool) {
	defer func() {
		recover()
		conn.Close()
	}()

	tag := "HTTP"
	if isTLS {
		tag = "TLS"
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	method, path, hdrs, err := readRequestHeaders(r, readHeaderLimit)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	logger.Printf("[%s] %s %s from %s\n", tag, method, path, conn.RemoteAddr())

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
			return
		}
		if targetURL == "" {
			sendError(conn, 400, "Missing url")
			return
		}
		handleFetch(conn, targetURL, tag)
		return
	}

	if method == "GET" && (path == "/status" || path == "/users" || path == "/" || path == "/health") {
		status := fmt.Sprintf(`{"status":"ok","version":"3.2","conns":%d}`, atomic.LoadInt64(&currentConnections))
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(status), status)))
		return
	}

	if v, ok := hdrs["upgrade"]; ok && strings.Contains(strings.ToLower(v), "websocket") {
		if atomic.LoadInt64(&currentConnections) >= maxConnections {
			conn.Write([]byte("HTTP/1.1 503 Full\r\n\r\n"))
			return
		}
		if hdrs["user"] != user || hdrs["password"] != password {
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		createBridge(conn)
		return
	}

	sendError(conn, 404, "Not Found")
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🎰 GRATISBET VPS SERVER v3.2                      ║
║   GZIP + Content-Length (mais simples)                   ║
╚═══════════════════════════════════════════════════════════╝`)

	server := socks5.NewServer(socks5.WithLogger(socks5.NewLogger(logger)))
	go server.ListenAndServe("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks))

	if len(os.Args) > 1 {
		if val, _ := strconv.ParseInt(os.Args[1], 10, 64); val > 0 {
			maxConnections = val
		}
	}

	ln, _ := net.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPort))
	if ln != nil {
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				go clientHandler(conn, false)
			}
		}()
	}

	cert, _ := generateCert()
	globalCert = &cert
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s ← OK\n", info.ServerName)
			atomic.AddInt64(&sniConnections, 1)
			return globalCert, nil
		},
	}

	tlsLn, _ := tls.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPortTLS), tlsConfig)
	if tlsLn != nil {
		go func() {
			for {
				conn, _ := tlsLn.Accept()
				if conn != nil {
					go clientHandler(conn, true)
				}
			}
		}()
	}

	logger.Println("[!] Servidor v3.2 pronto!")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
