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
)

const (
	listenIP        = "0.0.0.0"
	listenPort      = 80   // HTTP original
	listenPortTLS   = 443  // TLS com SNI Spoofing
	listenIPSocks   = "127.0.0.1"
	listenPortSocks = 8999
	bufferSize      = 16 * 1024
	readHeaderLimit = 8 * 1024
	connDialTimeout = 8 * time.Second
	streamIdleTO    = 30 * time.Second
	sessionKeepAlive = 10 * time.Second

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

// ============================================
// SMUX CONFIG (original)
// ============================================
func newSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = sessionKeepAlive
	cfg.MaxReceiveBuffer = 64 * 1024
	cfg.MaxStreamBuffer = 64 * 1024
	cfg.KeepAliveTimeout = 2 * time.Minute
	return cfg
}

// ============================================
// GERAR CERTIFICADO TLS (novo)
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
// LER HEADERS (original)
// ============================================
func readRequestHeaders(r *bufio.Reader, limit int) (string, map[string]string, error) {
	var sb strings.Builder
	hdrs := make(map[string]string)
	total := 0

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		total += len(line)
		if total > limit {
			return "", nil, errors.New("header too large")
		}
		sb.WriteString(line)
		if line == "\r\n" {
			break
		}
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			v := strings.TrimSpace(parts[1])
			hdrs[k] = v
		}
	}
	return sb.String(), hdrs, nil
}

// ============================================
// PROXY COPY (original)
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
// HANDLE SESSION (original)
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
				logger.Println("Erro ao aceitar stream:", err)
				return
			}

			go func(s *smux.Stream) {
				defer func() {
					if r := recover(); r != nil {
						logger.Println("panic na stream:", r)
					}
				}()
				if s == nil {
					return
				}

				dialer := net.Dialer{Timeout: connDialTimeout, KeepAlive: 30 * time.Second}
				socksConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks))
				if err != nil {
					logger.Println("Erro ao abrir socks:", err)
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
// CREATE BRIDGE (original)
// ============================================
func createBridge(conn net.Conn) {
	logger.Printf("[!] Conexão iniciada: %s\n", conn.RemoteAddr().String())
	atomic.AddInt64(&currentConnections, 1)
	defer func() {
		atomic.AddInt64(&currentConnections, -1)
		logger.Printf("[!] Conexão fechada: %s\n", conn.RemoteAddr().String())
		conn.Close()
	}()

	session, err := smux.Server(conn, newSmuxConfig())
	if err != nil {
		msg := err.Error()
		resp := fmt.Sprintf("HTTP/1.1 403 Erro SMUX\r\nServer: GratisBet\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(msg), msg)
		_, _ = conn.Write([]byte(resp))
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
// CLIENT HANDLER (original + melhorias)
// ============================================
func clientHandler(conn net.Conn, isTLS bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Println("panic em clientHandler:", r)
			conn.Close()
		}
	}()

	tag := "HTTP"
	if isTLS {
		tag = "TLS"
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	r := bufio.NewReader(conn)

	_, hdrs, err := readRequestHeaders(r, readHeaderLimit)
	if err != nil {
		logger.Println("Erro leitura headers:", err)
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nServer: GratisBet\r\n\r\n"))
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	buf := new(strings.Builder)
	for k, v := range hdrs {
		buf.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	joined := buf.String()

	// Endpoint de status
	if strings.Contains(strings.ToLower(joined), "get /users") || strings.Contains(strings.ToLower(joined), "get /status") {
		status := fmt.Sprintf(`{"data": "%d/%d", "sni": %d, "tls": %v}`, 
			atomic.LoadInt64(&currentConnections), maxConnections,
			atomic.LoadInt64(&sniConnections), isTLS)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: GratisBet\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(status), status)
		_, _ = conn.Write([]byte(resp))
		conn.Close()
		return
	}

	// Health check
	if strings.Contains(strings.ToLower(joined), "get / ") || strings.Contains(strings.ToLower(joined), "get /health") {
		status := fmt.Sprintf("GratisBet Server v2.0\nStatus: OK\nTLS: %v\nSNI: %d\nConns: %d/%d", 
			isTLS, atomic.LoadInt64(&sniConnections),
			atomic.LoadInt64(&currentConnections), maxConnections)
		resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: GratisBet\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(status), status)
		_, _ = conn.Write([]byte(resp))
		conn.Close()
		return
	}

	// Limitar conexões
	if atomic.LoadInt64(&currentConnections) >= maxConnections {
		_, _ = conn.Write([]byte("HTTP/1.1 503 Servidor lotado\r\nServer: GratisBet\r\n\r\n"))
		conn.Close()
		return
	}

	// Verificar upgrade websocket
	if v, ok := hdrs["upgrade"]; !ok || !strings.Contains(strings.ToLower(v), "websocket") {
		_, _ = conn.Write([]byte("HTTP/1.1 403 Payload invalida\r\nServer: GratisBet\r\n\r\nPayload Invalida :)"))
		conn.Close()
		return
	}

	// Autenticação
	u, uok := hdrs["user"]
	p, pok := hdrs["password"]
	if !uok || !pok || u != user || p != password {
		logger.Printf("[%s] Auth FAILED: %s\n", tag, conn.RemoteAddr())
		_, _ = conn.Write([]byte("HTTP/1.1 403 Credenciais incorrectas\r\nServer: GratisBet\r\n\r\nPayload Invalida :)"))
		conn.Close()
		return
	}

	// Handshake de upgrade
	_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))

	logger.Printf("[%s] Nova conexão autenticada: %s\n", tag, conn.RemoteAddr())
	createBridge(conn)
}

// ============================================
// MAIN
// ============================================
func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🎰 GRATISBET VPS SERVER v2.0                      ║
║                                                           ║
║   HTTP: 80  |  TLS: 443 (SNI Spoofing)  |  SOCKS: 8999   ║
║                                                           ║
║   🆓 Aceita QUALQUER SNI para internet grátis!           ║
╚═══════════════════════════════════════════════════════════╝
`)

	logger.Printf("[!] Inicializando SOCKS e servidor na porta %d (HTTP: %d, TLS: %d)\n", listenPortSocks, listenPort, listenPortTLS)

	// ============================================
	// SOCKS5 LOCAL (original)
	// ============================================
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
	)
	go func() {
		logger.Printf("[!] SOCKS Server iniciado na porta %d\n", listenPortSocks)
		if err := server.ListenAndServe("tcp", fmt.Sprintf("%s:%d", listenIPSocks, listenPortSocks)); err != nil {
			logger.Fatalf("socks listen error: %v", err)
		}
	}()

	// Override de max_connections via arg
	if len(os.Args) > 1 {
		if val, err := strconv.ParseInt(os.Args[1], 10, 64); err == nil && val > 0 {
			maxConnections = val
		}
	}

	// ============================================
	// HTTP LISTENER - PORTA 80 (original)
	// ============================================
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPort))
	if err != nil {
		logger.Printf("[!] Aviso: não foi possível abrir porta %d: %v\n", listenPort, err)
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
					_ = tcpConn.SetKeepAlive(true)
					_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
					_ = tcpConn.SetNoDelay(true)
				}
				go clientHandler(conn, false)
			}
		}()
	}

	// ============================================
	// TLS LISTENER - PORTA 443 COM SNI SPOOFING (novo)
	// ============================================
	cert, err := generateCert()
	if err != nil {
		logger.Printf("[!] Erro gerando certificado: %v\n", err)
	} else {
		globalCert = &cert

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			
			// ⭐⭐⭐ SNI SPOOFING - ACEITA QUALQUER SNI! ⭐⭐⭐
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
			logger.Printf("[!] Aviso: não foi possível abrir porta TLS %d: %v\n", listenPortTLS, err)
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
	logger.Println("[!] SNIs para internet grátis:")
	logger.Println("    • www.signup.ao (governo Angola)")
	logger.Println("    • web.whatsapp.com")
	logger.Println("    • www.facebook.com")
	logger.Println("")
	logger.Println("[!] Servidor pronto! Aguardando conexões...")
	logger.Println("")

	// ============================================
	// GRACEFUL SHUTDOWN (original)
	// ============================================
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	<-stop
	logger.Println("\n[!] Shutdown recebido, fechando...")
	if ln != nil {
		ln.Close()
	}
	logger.Println("[!] Servidor encerrado!")
}
