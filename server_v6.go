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
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

/*
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v6.0 - SI CONNECT STYLE                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Baseado na análise do SI Connect SSHWSDNS                                    ║
║                                                                               ║
║  Suporta:                                                                     ║
║    • HTTP CONNECT method (como HTTP Injector/SI Connect)                      ║
║    • SSH Bridge para 127.0.0.1:22                                             ║
║    • SNI Spoofing via TLS                                                     ║
║                                                                               ║
║  Payload esperado:                                                            ║
║    CONNECT 216.106.176.133:443 HTTP/1.1                                       ║
║    Host: www.signup.ao                                                        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/

var config = struct {
	IP  string
	SNI string
}{
	IP:  "216.106.176.133",
	SNI: "www.signup.ao",
}

var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

var stats = struct {
	connections int64
	sshBridges  int64
	bytesIn     int64
	bytesOut    int64
}{}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v6.0 - SI CONNECT STYLE                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Payload HTTP Injector / SI Connect:                                          ║
║  ┌─────────────────────────────────────────────────────────────────────────┐  ║
║  │ CONNECT [ssh_server]:22 HTTP/1.1[crlf]                                  │  ║
║  │ Host: www.signup.ao[crlf]                                               │  ║
║  │ [crlf]                                                                  │  ║
║  └─────────────────────────────────────────────────────────────────────────┘  ║
║                                                                               ║
║  SSH Settings:                                                                ║
║    Host: 216.106.176.133                                                      ║
║    Port: 443                                                                  ║
║    User: gratisbet                                                            ║
║    Pass: gratisbet123                                                         ║
║                                                                               ║
║  SSL/TLS: ON                                                                  ║
║  SNI: www.signup.ao                                                           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝`)

	// Verificar SSH local
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:22", 2*time.Second); err != nil {
		logger.Println("[WARN] ⚠️  SSH não detectado em 127.0.0.1:22")
		logger.Println("[WARN] Execute: apt install openssh-server && systemctl start sshd")
	} else {
		conn.Close()
		logger.Println("[OK] ✅ SSH detectado em 127.0.0.1:22")
	}

	// Gerar certificado
	cert, err := generateCert()
	if err != nil {
		logger.Fatal("Erro certificado:", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s ← aceito", info.ServerName)
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

	logger.Println("[OK] ✅ Servidor TLS iniciado na porta 443")

	// Accept loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			atomic.AddInt64(&stats.connections, 1)
			go handleConnection(conn)
		}
	}()

	// HTTP :80 para health check
	go func() {
		http80 := &simpleHTTPServer{}
		listener80, _ := net.Listen("tcp", ":80")
		if listener80 != nil {
			logger.Println("[OK] ✅ HTTP health check na porta 80")
			for {
				conn, err := listener80.Accept()
				if err != nil {
					continue
				}
				go http80.handle(conn)
			}
		}
	}()

	logger.Println("[OK] ✅ Servidor pronto! Aguardando conexões...")
	logger.Println("")

	// Wait
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	fmt.Println("\n[!] Encerrando...")
}

type simpleHTTPServer struct{}

func (s *simpleHTTPServer) handle(conn net.Conn) {
	defer conn.Close()
	status := fmt.Sprintf(`{"status":"ok","version":"6.0","connections":%d,"ssh_bridges":%d}`,
		atomic.LoadInt64(&stats.connections),
		atomic.LoadInt64(&stats.sshBridges))
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + status))
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	
	clientIP := conn.RemoteAddr().String()
	logger.Printf("[CONN] Nova conexão de %s", clientIP)

	// Timeout para leitura inicial
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)

	// Ler primeira linha (ex: "CONNECT 127.0.0.1:22 HTTP/1.1" ou "GET / HTTP/1.1")
	line, err := reader.ReadString('\n')
	if err != nil {
		logger.Printf("[ERR] Erro lendo request: %v", err)
		return
	}

	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	
	if len(parts) < 2 {
		logger.Printf("[ERR] Request inválido: %s", line)
		return
	}

	method := strings.ToUpper(parts[0])
	target := parts[1]

	logger.Printf("[REQ] %s %s", method, target)

	// Ler headers
	headers := make(map[string]string)
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil || headerLine == "\r\n" || headerLine == "\n" {
			break
		}
		if idx := strings.Index(headerLine, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(headerLine[:idx]))
			val := strings.TrimSpace(headerLine[idx+1:])
			headers[key] = val
		}
	}

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	// Processar baseado no método
	switch method {
	case "CONNECT":
		// HTTP CONNECT - padrão de HTTP Injector/SI Connect
		handleCONNECT(conn, reader, target, headers)
		
	case "GET", "POST":
		// Fallback para requests HTTP normais
		handleHTTP(conn, method, target, headers)
		
	default:
		logger.Printf("[WARN] Método desconhecido: %s", method)
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

// handleCONNECT - processa HTTP CONNECT (túnel proxy)
func handleCONNECT(conn net.Conn, reader *bufio.Reader, target string, headers map[string]string) {
	logger.Printf("[CONNECT] Target: %s", target)
	
	// Determinar destino real
	// O target pode ser: "127.0.0.1:22", "server:22", ou apenas ":22"
	destHost := "127.0.0.1"
	destPort := "22"
	
	if strings.Contains(target, ":") {
		parts := strings.Split(target, ":")
		if len(parts) == 2 {
			if parts[0] != "" {
				destHost = parts[0]
			}
			destPort = parts[1]
		}
	}
	
	// Se o destino é nosso próprio IP ou localhost, conectar ao SSH local
	if destHost == config.IP || destHost == "127.0.0.1" || destHost == "localhost" || destHost == "" {
		destHost = "127.0.0.1"
	}
	
	destination := fmt.Sprintf("%s:%s", destHost, destPort)
	logger.Printf("[CONNECT] Conectando a %s", destination)
	
	// Conectar ao destino
	destConn, err := net.DialTimeout("tcp", destination, 10*time.Second)
	if err != nil {
		logger.Printf("[CONNECT] Falha ao conectar a %s: %v", destination, err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer destConn.Close()
	
	// Responder 200 Connection Established
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	logger.Printf("[CONNECT] ✅ Túnel estabelecido para %s", destination)
	
	atomic.AddInt64(&stats.sshBridges, 1)
	
	// Configurar timeouts
	conn.SetDeadline(time.Now().Add(10 * time.Minute))
	destConn.SetDeadline(time.Now().Add(10 * time.Minute))
	
	// Verificar se há dados no buffer
	buffered := reader.Buffered()
	if buffered > 0 {
		data := make([]byte, buffered)
		n, _ := reader.Read(data)
		if n > 0 {
			destConn.Write(data[:n])
			atomic.AddInt64(&stats.bytesIn, int64(n))
			logger.Printf("[CONNECT] Enviou %d bytes buffered", n)
		}
	}
	
	// Bridge bidirecional
	done := make(chan struct{}, 2)
	
	// Cliente -> Destino
	go func() {
		n, _ := io.Copy(destConn, reader)
		atomic.AddInt64(&stats.bytesIn, n)
		logger.Printf("[CONNECT] Cliente→Destino: %d bytes", n)
		done <- struct{}{}
	}()
	
	// Destino -> Cliente
	go func() {
		n, _ := io.Copy(conn, destConn)
		atomic.AddInt64(&stats.bytesOut, n)
		logger.Printf("[CONNECT] Destino→Cliente: %d bytes", n)
		done <- struct{}{}
	}()
	
	// Esperar uma direção terminar
	<-done
	logger.Printf("[CONNECT] Túnel encerrado")
}

// handleHTTP - processa requests HTTP normais
func handleHTTP(conn net.Conn, method, path string, headers map[string]string) {
	logger.Printf("[HTTP] %s %s", method, path)
	
	// Health check
	if path == "/" || path == "/health" || path == "/status" {
		status := fmt.Sprintf(`{
  "status": "ok",
  "version": "6.0-siconnect-style",
  "connections": %d,
  "ssh_bridges": %d,
  "bytes_in": %d,
  "bytes_out": %d,
  "usage": "Use HTTP CONNECT method for tunneling"
}`,
			atomic.LoadInt64(&stats.connections),
			atomic.LoadInt64(&stats.sshBridges),
			atomic.LoadInt64(&stats.bytesIn),
			atomic.LoadInt64(&stats.bytesOut))
		
		conn.Write([]byte("HTTP/1.1 200 OK\r\n"))
		conn.Write([]byte("Content-Type: application/json\r\n"))
		conn.Write([]byte(fmt.Sprintf("Content-Length: %d\r\n", len(status))))
		conn.Write([]byte("\r\n"))
		conn.Write([]byte(status))
		return
	}
	
	// Qualquer outro path - assumir que é SSH bridge (fallback)
	logger.Printf("[HTTP] Path não reconhecido, tentando SSH bridge...")
	
	// Conectar ao SSH local
	ssh, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		logger.Printf("[HTTP] SSH falhou: %v", err)
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer ssh.Close()
	
	// Responder 200 e iniciar bridge
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	
	atomic.AddInt64(&stats.sshBridges, 1)
	
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ssh, conn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, ssh)
		done <- struct{}{}
	}()
	<-done
}

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
