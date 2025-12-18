package main

import (
	"bufio"
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

	// Autenticação
	user     = "sung"
	password = "123.456"

	// SNI Spoofing
	sniHost = "signup.ao"
	vpsIP   = "216.106.176.133"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, bufferSize)
		return &b
	},
}

var logger = log.New(os.Stdout, "", log.LstdFlags)
var globalCert *tls.Certificate

// Cliente HTTP para fazer fetch
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableCompression:  true, // ⭐ Sem compressão para enviar raw
	},
}

// ============================================
// SMUX CONFIG (original)
// ============================================
func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.MaxReceiveBuffer = 64 * 1024
	cfg.MaxStreamBuffer = 64 * 1024
	cfg.KeepAliveTimeout = 2 * time.Minute
	return cfg
}

// ============================================
// GERAR CERTIFICADO TLS
// ============================================
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
		DNSNames: []string{
			sniHost, "www." + sniHost, "*." + sniHost, "localhost",
			"web.whatsapp.com", "www.whatsapp.com", "mmg.whatsapp.net",
			"www.facebook.com", "m.facebook.com", "www.governo.gov.ao",
		},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(vpsIP)},
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ============================================
// LER HEADERS HTTP
// ============================================
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

// ============================================
// PROXY COPY
// ============================================
func proxyCopy(dst net.Conn, src net.Conn, cancel context.CancelFunc) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	_, _ = io.CopyBuffer(dst, src, *bufp)
	if cancel != nil {
		cancel()
	}
}

// ============================================
// HANDLE SMUX SESSION (original)
// ============================================
func handleSession(ctx context.Context, session *smux.Session) {
	defer session.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			stream, err := session.AcceptStream()
			if err != nil {
				if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "closed") {
					return
				}
				return
			}

			go func(s *smux.Stream) {
				defer func() {
					if r := recover(); r != nil {
						logger.Println("panic stream:", r)
					}
				}()
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
					_ = socksConn.Close()
					_ = s.Close()
				}()
				proxyCopy(s, socksConn, cancel)
				_ = socksConn.Close()
				_ = s.Close()
				<-ctxC.Done()
			}(stream)
		}
	}
}

// ============================================
// CREATE SMUX BRIDGE (original)
// ============================================
func createBridge(conn net.Conn) {
	logger.Printf("[!] SMUX iniciado: %s\n", conn.RemoteAddr().String())
	atomic.AddInt64(&currentConnections, 1)
	defer func() {
		atomic.AddInt64(&currentConnections, -1)
		logger.Printf("[!] SMUX fechado: %s\n", conn.RemoteAddr().String())
		conn.Close()
	}()

	session, err := smux.Server(conn, newSmuxConfig())
	if err != nil {
		msg := err.Error()
		resp := fmt.Sprintf("HTTP/1.1 403 Erro SMUX\r\nServer: GratisBet\r\nContent-Length: %d\r\n\r\n%s", len(msg), msg)
		conn.Write([]byte(resp))
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
// HANDLE FETCH REQUEST - VERSÃO 2.1 CORRIGIDA
// ⭐ FIX: Connection Reset
// ============================================
func handleFetch(conn net.Conn, targetURL string, tag string) {
	atomic.AddInt64(&fetchConnections, 1)

	// Decodificar URL
	decoded, err := url.QueryUnescape(targetURL)
	if err != nil {
		decoded = targetURL
	}

	logger.Printf("[%s] ♦ FETCH: %s\n", tag, decoded)

	// Fazer request HTTP
	req, err := http.NewRequest("GET", decoded, nil)
	if err != nil {
		errMsg := fmt.Sprintf("URL inválida: %s", err.Error())
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(errMsg), errMsg)))
		time.Sleep(50 * time.Millisecond)
		return
	}

	// Headers para parecer navegador
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	req.Header.Set("Accept-Encoding", "identity") // ⭐ Sem compressão!

	resp, err := httpClient.Do(req)
	if err != nil {
		errMsg := fmt.Sprintf("Erro fetch: %s", err.Error())
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(errMsg), errMsg)))
		time.Sleep(50 * time.Millisecond)
		return
	}
	defer resp.Body.Close()

	// ⭐ LER BODY COMPLETO PRIMEIRO (não usar io.Copy direto!)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		errMsg := fmt.Sprintf("Erro leitura: %s", err.Error())
		conn.Write([]byte(fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(errMsg), errMsg)))
		time.Sleep(50 * time.Millisecond)
		return
	}

	logger.Printf("[%s] ♦ FETCH OK: %d bytes (status %d)\n", tag, len(body), resp.StatusCode)

	// ⭐ ENVIAR COM CONTENT-LENGTH EXATO
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	headers := fmt.Sprintf("HTTP/1.1 %d %s\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: close\r\n"+
		"X-Proxy: GratisBet\r\n"+
		"\r\n",
		resp.StatusCode, http.StatusText(resp.StatusCode),
		contentType,
		len(body))

	// ⭐ DESABILITAR NAGLE PARA ENVIO IMEDIATO
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetWriteBuffer(65536)
	}
	// Para TLS connections
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if tcpConn, ok := tlsConn.NetConn().(*net.TCPConn); ok {
			tcpConn.SetNoDelay(true)
			tcpConn.SetWriteBuffer(65536)
		}
	}

	// Enviar headers
	_, err = conn.Write([]byte(headers))
	if err != nil {
		logger.Printf("[%s] ♦ Header write error: %v\n", tag, err)
		return
	}

	// Enviar body em chunks para garantir flush
	chunkSize := 32768
	for i := 0; i < len(body); i += chunkSize {
		end := i + chunkSize
		if end > len(body) {
			end = len(body)
		}
		_, err = conn.Write(body[i:end])
		if err != nil {
			logger.Printf("[%s] ♦ Body write error at %d: %v\n", tag, i, err)
			return
		}
	}

	// ⭐⭐⭐ CRÍTICO: ESPERAR ANTES DE FECHAR! ⭐⭐⭐
	// Isso permite que o cliente receba todos os dados
	// antes da conexão ser fechada
	time.Sleep(200 * time.Millisecond)
}

// ============================================
// CLIENT HANDLER (com suporte a /fetch)
// ============================================
func clientHandler(conn net.Conn, isTLS bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Println("panic clientHandler:", r)
			conn.Close()
		}
	}()

	tag := "HTTP"
	if isTLS {
		tag = "TLS"
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)

	method, path, hdrs, err := readRequestHeaders(r, readHeaderLimit)
	if err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	logger.Printf("[%s] %s %s from %s\n", tag, method, path, conn.RemoteAddr())

	// ============================================
	// ROTA: /fetch?user=...&password=...&url=...
	// ============================================
	if method == "GET" && strings.HasPrefix(path, "/fetch") {
		var reqUser, reqPass, targetURL string

		if idx := strings.Index(path, "?"); idx > 0 {
			params, _ := url.ParseQuery(path[idx+1:])
			reqUser = params.Get("user")
			reqPass = params.Get("password")
			targetURL = params.Get("url")
		}

		if reqUser != user || reqPass != password {
			logger.Printf("[%s] 🚫 Auth FAILED (fetch): %s\n", tag, conn.RemoteAddr())
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 13\r\nConnection: close\r\n\r\nAuth failed\n"))
			time.Sleep(50 * time.Millisecond)
			conn.Close()
			return
		}

		if targetURL == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 18\r\nConnection: close\r\n\r\nMissing url param\n"))
			time.Sleep(50 * time.Millisecond)
			conn.Close()
			return
		}

		handleFetch(conn, targetURL, tag)
		conn.Close()
		return
	}

	// ============================================
	// ROTA: /status
	// ============================================
	if method == "GET" && (path == "/status" || path == "/users") {
		status := fmt.Sprintf(`{"status":"ok","version":"2.1-fix","sni":"%s","conns":%d,"max":%d,"fetch":%d,"sni_count":%d}`,
			sniHost,
			atomic.LoadInt64(&currentConnections),
			maxConnections,
			atomic.LoadInt64(&fetchConnections),
			atomic.LoadInt64(&sniConnections))
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: GratisBet\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(status), status)
		conn.Write([]byte(resp))
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		return
	}

	// ============================================
	// ROTA: / ou /health
	// ============================================
	if method == "GET" && (path == "/" || path == "/health") {
		status := fmt.Sprintf("GratisBet Server v2.1-fix\nStatus: OK\nTLS: %v\nSNI: %s\nConns: %d/%d\nFetch: %d\nFix: Connection Reset",
			isTLS, sniHost,
			atomic.LoadInt64(&currentConnections), maxConnections,
			atomic.LoadInt64(&fetchConnections))
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: GratisBet\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(status), status)
		conn.Write([]byte(resp))
		time.Sleep(50 * time.Millisecond)
		conn.Close()
		return
	}

	// ============================================
	// ROTA: WebSocket Upgrade (SMUX)
	// ============================================
	if v, ok := hdrs["upgrade"]; ok && strings.Contains(strings.ToLower(v), "websocket") {
		if atomic.LoadInt64(&currentConnections) >= maxConnections {
			conn.Write([]byte("HTTP/1.1 503 Server Full\r\n\r\n"))
			conn.Close()
			return
		}

		reqUser := hdrs["user"]
		reqPass := hdrs["password"]

		if reqUser != user || reqPass != password {
			logger.Printf("[%s] 🚫 Auth FAILED (ws): %s\n", tag, conn.RemoteAddr())
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			conn.Close()
			return
		}

		conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
		logger.Printf("[%s] ✅ SMUX Auth OK: %s\n", tag, conn.RemoteAddr())

		createBridge(conn)
		return
	}

	// ============================================
	// 404
	// ============================================
	body := "404 Not Found - GratisBet Server v2.1\nEndpoints: /fetch, /status, /health"
	conn.Write([]byte(fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)))
	time.Sleep(50 * time.Millisecond)
	conn.Close()
}

// ============================================
// MAIN
// ============================================
func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🎰 GRATISBET VPS SERVER v2.1-fix                  ║
║                                                           ║
║   HTTP: 80  |  TLS: 443 (SNI Spoofing)  |  SOCKS: 8999   ║
║                                                           ║
║   🆓 Aceita QUALQUER SNI para internet grátis!           ║
║   📱 Suporta App Android (/fetch) + HTTP Injector (SMUX) ║
║   ⭐ FIX: Connection Reset corrigido!                    ║
╚═══════════════════════════════════════════════════════════╝
`)

	logger.Printf("[!] Inicializando servidor (HTTP: %d, TLS: %d, SOCKS: %d)\n", listenPort, listenPortTLS, listenPortSocks)

	// ============================================
	// SOCKS5 LOCAL
	// ============================================
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
	)
	go func() {
		logger.Printf("[!] SOCKS5 iniciado na porta %d\n", listenPortSocks)
		if err := server.ListenAndServe("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks)); err != nil {
			logger.Fatalf("SOCKS error: %v", err)
		}
	}()

	if len(os.Args) > 1 {
		if val, err := strconv.ParseInt(os.Args[1], 10, 64); err == nil && val > 0 {
			maxConnections = val
		}
	}

	// ============================================
	// HTTP LISTENER - PORTA 80
	// ============================================
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPort))
	if err != nil {
		logger.Printf("[!] Aviso: porta %d em uso: %v\n", listenPort, err)
	} else {
		logger.Printf("[!] HTTP Server iniciado na porta %d\n", listenPort)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					continue
				}
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					tcpConn.SetKeepAlive(true)
					tcpConn.SetKeepAlivePeriod(30 * time.Second)
					tcpConn.SetNoDelay(true)
				}
				go clientHandler(conn, false)
			}
		}()
	}

	// ============================================
	// TLS LISTENER - PORTA 443 COM SNI SPOOFING
	// ============================================
	cert, err := generateCert()
	if err != nil {
		logger.Printf("[!] Erro certificado: %v\n", err)
	} else {
		globalCert = &cert

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,

			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				sni := info.ServerName
				if sni == "" {
					sni = "(vazio)"
				}
				logger.Printf("[SNI] Recebido: %s ← ACEITO!\n", sni)
				atomic.AddInt64(&sniConnections, 1)
				return globalCert, nil
			},
		}

		tlsLn, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPortTLS), tlsConfig)
		if err != nil {
			logger.Printf("[!] Aviso: porta TLS %d em uso: %v\n", listenPortTLS, err)
		} else {
			logger.Printf("[!] TLS Server iniciado na porta %d (SNI Spoofing ATIVO!)\n", listenPortTLS)
			go func() {
				for {
					conn, err := tlsLn.Accept()
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return
						}
						continue
					}
					go clientHandler(conn, true)
				}
			}()
		}
	}

	// ============================================
	// INFO
	// ============================================
	logger.Println("")
	logger.Printf("[!] VPS IP: %s\n", vpsIP)
	logger.Printf("[!] Auth: %s / %s\n", user, password)
	logger.Printf("[!] MaxConnections: %d\n", maxConnections)
	logger.Println("")
	logger.Println("[!] Endpoints:")
	logger.Println("    • /fetch?user=...&password=...&url=... (App Android)")
	logger.Println("    • WebSocket Upgrade (HTTP Injector/SMUX)")
	logger.Println("    • /status, /health")
	logger.Println("")
	logger.Println("[!] ⭐ FIX v2.1: Connection Reset corrigido!")
	logger.Println("    • io.ReadAll antes de enviar")
	logger.Println("    • Content-Length exato")
	logger.Println("    • time.Sleep antes de conn.Close")
	logger.Println("")
	logger.Println("[!] Servidor pronto! Aguardando conexões...")
	logger.Println("")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	logger.Println("\n[!] Shutdown recebido, fechando...")
	if ln != nil {
		ln.Close()
	}
	logger.Println("[!] Servidor encerrado!")
}
