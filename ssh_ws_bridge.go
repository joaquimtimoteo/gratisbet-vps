package main

import (
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
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

/*
 * SSH over WebSocket Bridge
 * Compatível com HTTP Injector, SI Connect, HA Tunnel
 * 
 * O app conecta via WebSocket:443 com SNI spoofing
 * Este servidor faz bridge para SSH local (127.0.0.1:22)
 */

var logger = log.New(os.Stdout, "", log.LstdFlags)
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

func handleBridge(w http.ResponseWriter, r *http.Request) {
	// Upgrade para WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Printf("[WS] Upgrade erro: %v", err)
		return
	}
	defer ws.Close()

	clientIP := r.RemoteAddr
	logger.Printf("[WS] Nova conexão: %s", clientIP)

	// Conectar ao SSH local
	ssh, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		logger.Printf("[SSH] Conexão falhou: %v", err)
		return
	}
	defer ssh.Close()

	logger.Printf("[SSH] Bridge estabelecida: %s", clientIP)

	// Canais para sinalizar término
	done := make(chan struct{})

	// WS -> SSH
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, data, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := ssh.Write(data); err != nil {
				return
			}
		}
	}()

	// SSH -> WS
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 4096)
		for {
			n, err := ssh.Read(buf)
			if err != nil {
				return
			}
			if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	// Esperar término de qualquer direção
	<-done
	logger.Printf("[WS] Desconectado: %s", clientIP)
}

// Handler para HTTP Injector payload
func handleHTTPInjector(w http.ResponseWriter, r *http.Request) {
	// HTTP Injector envia payload HTTP primeiro
	// Responder com 101 Switching Protocols
	if r.Header.Get("Upgrade") == "websocket" {
		handleBridge(w, r)
		return
	}

	// Payload HTTP normal - conectar direto ao SSH
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack não suportado", 500)
		return
	}

	conn, buf, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	clientIP := r.RemoteAddr
	logger.Printf("[HTTP] Payload de: %s", clientIP)

	// Responder 200 OK para o payload
	buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	buf.Flush()

	// Conectar ao SSH
	ssh, err := net.DialTimeout("tcp", "127.0.0.1:22", 10*time.Second)
	if err != nil {
		logger.Printf("[SSH] Conexão falhou: %v", err)
		return
	}
	defer ssh.Close()

	logger.Printf("[SSH] Bridge HTTP estabelecida: %s", clientIP)

	// Bridge bidirecional
	go io.Copy(ssh, conn)
	io.Copy(conn, ssh)

	logger.Printf("[HTTP] Desconectado: %s", clientIP)
}

func main() {
	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║     SSH-WS Bridge v1.0 (GratisBet)       ║")
	fmt.Println("║  Compatível com HTTP Injector/SI Connect ║")
	fmt.Println("╚══════════════════════════════════════════╝")

	mux := http.NewServeMux()
	
	// Rota para WebSocket
	mux.HandleFunc("/ws", handleBridge)
	mux.HandleFunc("/ssh", handleBridge)
	mux.HandleFunc("/", handleHTTPInjector)

	// Gerar certificado TLS com SNI
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "www.signup.ao"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     []string{"signup.ao", "www.signup.ao", "m.signup.ao"},
		IPAddresses:  []net.IP{net.ParseIP("216.106.176.133")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}),
	)

	// Servidor TLS
	srv := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	// Servidor HTTP (porta 80) - redirect ou payload
	go func() {
		http.ListenAndServe(":80", mux)
	}()

	go func() {
		logger.Println("[OK] Porta 443 (TLS + SNI: www.signup.ao)")
		logger.Println("[OK] SSH Bridge: 127.0.0.1:22")
		logger.Println("")
		logger.Println("=== Configuração HTTP Injector ===")
		logger.Println("Payload: GET / HTTP/1.1[crlf]Host: www.signup.ao[crlf][crlf]")
		logger.Println("SSH Host: 216.106.176.133")
		logger.Println("SSH Port: 443")
		logger.Println("Tunnel Type: SSL/TLS")
		logger.Println("")
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logger.Fatal(err)
		}
	}()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	fmt.Println("\nEncerrando...")
}
