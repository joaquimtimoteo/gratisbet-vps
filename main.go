package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const SERVER_VERSION = "6.0-tls-proxy"

// ════════════════════════════════════════════════════════════════════
//                    CONFIGURAÇÕES
// ════════════════════════════════════════════════════════════════════

const (
	LISTEN_PORT   = ":443"
	BUFFER_SIZE   = 64 * 1024
	CONN_TIMEOUT  = 30 * time.Second
	RELAY_TIMEOUT = 5 * time.Minute
)

var (
	activeConns int64
	totalConns  int64
	totalBytes  int64
	startTime   = time.Now()
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	fmt.Println("══════════════════════════════════════════════")
	fmt.Println("  GRATISBET PROXY v" + SERVER_VERSION)
	fmt.Println("  TLS + HTTP CONNECT")
	fmt.Println("══════════════════════════════════════════════")

	// Gerar certificado auto-assinado
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Printf("Erro gerando certificado: %v\n", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", LISTEN_PORT, tlsConfig)
	if err != nil {
		fmt.Printf("Erro ao iniciar: %v\n", err)
		return
	}

	fmt.Printf("  ✓ Porta %s ativa (TLS)\n", LISTEN_PORT)
	fmt.Println("  ✓ Método: TLS + HTTP CONNECT")
	fmt.Println("  ✓ Certificado: Auto-assinado")
	fmt.Println("══════════════════════════════════════════════")

	// Stats
	go func() {
		for {
			time.Sleep(30 * time.Second)
			mb := float64(atomic.LoadInt64(&totalBytes)) / 1024 / 1024
			active := atomic.LoadInt64(&activeConns)
			total := atomic.LoadInt64(&totalConns)
			fmt.Printf("[STATS] Active: %d | Total: %d | %.2f MB\n", active, total, mb)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	atomic.AddInt64(&activeConns, 1)
	atomic.AddInt64(&totalConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	reader := bufio.NewReader(clientConn)
	clientConn.SetReadDeadline(time.Now().Add(CONN_TIMEOUT))

	// Ler primeira linha
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return
	}

	method := strings.ToUpper(parts[0])
	target := parts[1]

	// Ler headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(strings.ToLower(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	clientConn.SetReadDeadline(time.Time{})
	clientIP := strings.Split(clientConn.RemoteAddr().String(), ":")[0]

	switch method {
	case "CONNECT":
		handleConnect(clientConn, target, clientIP)
	default:
		handleHTTPProxy(clientConn, reader, method, target, headers, clientIP)
	}
}

func handleConnect(clientConn net.Conn, target string, clientIP string) {
	if !strings.Contains(target, ":") {
		target = target + ":443"
	}

	fmt.Printf("[CONNECT] %s -> %s\n", clientIP, target)

	serverConn, err := net.DialTimeout("tcp", target, CONN_TIMEOUT)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	if tc, ok := serverConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetKeepAlive(true)
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	relay(clientConn, serverConn)
}

func handleHTTPProxy(clientConn net.Conn, reader *bufio.Reader, method, target string, headers map[string]string, clientIP string) {
	host := headers["host"]
	if host == "" {
		if strings.HasPrefix(target, "http://") {
			target = target[7:]
			if idx := strings.Index(target, "/"); idx > 0 {
				host = target[:idx]
				target = target[idx:]
			} else {
				host = target
				target = "/"
			}
		}
	}

	if host == "" {
		return
	}

	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	fmt.Printf("[HTTP] %s -> %s%s\n", clientIP, host, target)

	serverConn, err := net.DialTimeout("tcp", host, CONN_TIMEOUT)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	request := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, target)
	for k, v := range headers {
		request += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	request += "\r\n"

	serverConn.Write([]byte(request))
	relay(clientConn, serverConn)
}

func relay(client, server net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := copyBuffer(server, client)
		atomic.AddInt64(&totalBytes, n)
	}()

	go func() {
		defer wg.Done()
		n, _ := copyBuffer(client, server)
		atomic.AddInt64(&totalBytes, n)
	}()

	wg.Wait()
}

func copyBuffer(dst, src net.Conn) (int64, error) {
	buf := make([]byte, BUFFER_SIZE)
	var total int64

	for {
		src.SetReadDeadline(time.Now().Add(RELAY_TIMEOUT))
		n, err := src.Read(buf)
		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			return total, err
		}
	}
}

// ════════════════════════════════════════════════════════════════════
//                    CERTIFICADO AUTO-ASSINADO
// ════════════════════════════════════════════════════════════════════

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"GratisBet VPN"},
			CommonName:   "gratisbet.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"gratisbet.local", "localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
