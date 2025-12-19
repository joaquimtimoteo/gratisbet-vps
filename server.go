package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtaci/smux"
)

/*
 * GratisBet VPN Server v1.0
 * 
 * Arquitetura:
 * - WebSocket sobre TLS (porta 443)
 * - SMUX para multiplexar conexões
 * - Fragmentação de pacotes < 400 bytes
 * - Proxy SOCKS5 ou direto para internet
 */

const (
	VPS_IP       = "216.106.176.133"
	SNI_HOST     = "signup.ao"
	AUTH_USER    = "sung"
	AUTH_PASS    = "123.456"
	MAX_FRAG     = 380 // Tamanho máximo de fragmento (< 400 bytes)
	WS_PATH      = "/vpn"
)

var logger = log.New(os.Stdout, "", log.LstdFlags)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// Configuração SMUX otimizada para pacotes pequenos
func smuxConfig() *smux.Config {
	config := smux.DefaultConfig()
	config.Version = 1
	config.KeepAliveInterval = 10 * time.Second
	config.KeepAliveTimeout = 30 * time.Second
	config.MaxFrameSize = MAX_FRAG
	config.MaxReceiveBuffer = 4 * 1024 * 1024
	config.MaxStreamBuffer = 1 * 1024 * 1024
	return config
}

// Wrapper para WebSocket como net.Conn (para SMUX)
type wsConn struct {
	*websocket.Conn
	readBuf  []byte
	readPos  int
	writeMu  sync.Mutex
}

func newWsConn(conn *websocket.Conn) *wsConn {
	return &wsConn{Conn: conn, readBuf: nil, readPos: 0}
}

func (w *wsConn) Read(p []byte) (int, error) {
	// Se tem dados no buffer, retorna
	if w.readPos < len(w.readBuf) {
		n := copy(p, w.readBuf[w.readPos:])
		w.readPos += n
		return n, nil
	}
	
	// Lê nova mensagem
	_, msg, err := w.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}
	
	// Se a mensagem cabe no buffer p, retorna direto
	if len(msg) <= len(p) {
		copy(p, msg)
		return len(msg), nil
	}
	
	// Senão, guarda no buffer
	w.readBuf = msg
	w.readPos = copy(p, msg)
	return w.readPos, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	
	// Fragmentar se necessário
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MAX_FRAG {
			chunk = p[:MAX_FRAG]
		}
		
		err := w.Conn.WriteMessage(websocket.BinaryMessage, chunk)
		if err != nil {
			return total, err
		}
		
		total += len(chunk)
		p = p[len(chunk):]
	}
	
	return total, nil
}

func (w *wsConn) SetDeadline(t time.Time) error {
	w.Conn.SetReadDeadline(t)
	w.Conn.SetWriteDeadline(t)
	return nil
}

func (w *wsConn) SetReadDeadline(t time.Time) error {
	return w.Conn.SetReadDeadline(t)
}

func (w *wsConn) SetWriteDeadline(t time.Time) error {
	return w.Conn.SetWriteDeadline(t)
}

func (w *wsConn) LocalAddr() net.Addr {
	return w.Conn.LocalAddr()
}

func (w *wsConn) RemoteAddr() net.Addr {
	return w.Conn.RemoteAddr()
}

// Handler de stream SMUX - proxy para internet
func handleStream(stream *smux.Stream) {
	defer stream.Close()
	
	// Ler header do pedido (primeiro pacote)
	// Formato: [1 byte tipo][2 bytes porta][N bytes host]
	header := make([]byte, 256)
	n, err := stream.Read(header)
	if err != nil || n < 4 {
		logger.Printf("[STREAM] Header inválido: %v", err)
		return
	}
	
	cmdType := header[0]
	port := binary.BigEndian.Uint16(header[1:3])
	hostLen := header[3]
	
	if int(hostLen) > n-4 {
		logger.Printf("[STREAM] Host length inválido")
		return
	}
	
	host := string(header[4 : 4+hostLen])
	
	logger.Printf("[STREAM] CMD=%d Host=%s Port=%d", cmdType, host, port)
	
	// Conectar ao destino
	addr := fmt.Sprintf("%s:%d", host, port)
	
	var targetConn net.Conn
	
	if cmdType == 0x01 { // TCP Connect
		targetConn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			logger.Printf("[STREAM] Erro ao conectar %s: %v", addr, err)
			stream.Write([]byte{0x01}) // Erro
			return
		}
		defer targetConn.Close()
		
		// Sucesso
		stream.Write([]byte{0x00})
		
		// Proxy bidirecional
		var wg sync.WaitGroup
		wg.Add(2)
		
		go func() {
			defer wg.Done()
			io.Copy(targetConn, stream)
			targetConn.(*net.TCPConn).CloseWrite()
		}()
		
		go func() {
			defer wg.Done()
			io.Copy(stream, targetConn)
			stream.Close()
		}()
		
		wg.Wait()
		
	} else {
		logger.Printf("[STREAM] Comando desconhecido: %d", cmdType)
		stream.Write([]byte{0xFF})
	}
}

// Handler principal WebSocket
func handleVPN(w http.ResponseWriter, r *http.Request) {
	// Autenticação via header
	auth := r.Header.Get("X-Auth")
	expected := AUTH_USER + ":" + AUTH_PASS
	
	if auth != expected {
		logger.Printf("[VPN] Auth falhou de %s", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Upgrade para WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Printf("[VPN] Upgrade falhou: %v", err)
		return
	}
	
	logger.Printf("[VPN] Nova conexão de %s", r.RemoteAddr)
	
	// Wrapper para SMUX
	wsC := newWsConn(conn)
	
	// Criar sessão SMUX (servidor)
	session, err := smux.Server(wsC, smuxConfig())
	if err != nil {
		logger.Printf("[VPN] SMUX server falhou: %v", err)
		conn.Close()
		return
	}
	defer session.Close()
	
	logger.Printf("[VPN] SMUX session iniciada")
	
	// Aceitar streams
	for {
		stream, err := session.AcceptStream()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "closed") {
				logger.Printf("[VPN] Session fechada normalmente")
			} else {
				logger.Printf("[VPN] AcceptStream erro: %v", err)
			}
			break
		}
		
		go handleStream(stream)
	}
}

// Handler de status
func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok","version":"vpn-1.0","smux":true}`))
}

// Handler de busca (manter compatibilidade)
func handleSearch(w http.ResponseWriter, r *http.Request) {
	// Implementação anterior do search...
	w.Write([]byte("OK|search|0\nUse /vpn para VPN"))
}

// Gerar certificado TLS
func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: SNI_HOST},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{SNI_HOST, "www." + SNI_HOST, "*." + SNI_HOST},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(VPS_IP)},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║           🔐 GRATISBET VPN SERVER v1.0                   ║
║                                                           ║
║   /vpn     → WebSocket + SMUX (VPN)                      ║
║   /status  → Health check                                ║
║   /search  → Busca (compatibilidade)                     ║
║                                                           ║
║   Fragmentação: < 380 bytes                              ║
║   TLS: 443 | HTTP: 80                                    ║
╚═══════════════════════════════════════════════════════════╝`)

	// Mux HTTP
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", handleVPN)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/", handleStatus)

	// HTTP Server (porta 80)
	go func() {
		logger.Println("[HTTP] :80")
		http.ListenAndServe(":80", mux)
	}()

	// TLS Server (porta 443)
	cert, err := generateCert()
	if err != nil {
		logger.Fatalf("Erro gerando certificado: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s", info.ServerName)
			return &cert, nil
		},
	}

	tlsServer := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		logger.Println("[TLS] :443")
		tlsServer.ListenAndServeTLS("", "")
	}()

	logger.Println("[OK] Servidor VPN pronto!")

	// Aguardar sinal
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	
	logger.Println("[!] Encerrando...")
}
