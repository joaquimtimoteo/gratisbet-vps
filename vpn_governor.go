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
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

/*
 * VPN GOVERNOR v1.0
 * 
 * Regra de ouro: NUNCA enviar mais de 1 frame em menos de 120ms
 * RX e TX serializados na mesma fila
 */

const (
	SEND_INTERVAL = 120 * time.Millisecond
	MAX_CHUNK     = 200
)

var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

// Frame na fila
type Frame struct {
	StreamID  uint16
	Direction string // "TX" (server->app) ou "RX" (app->server)
	Payload   []byte
}

// Stream de conexão TCP
type Stream struct {
	target net.Conn
	closed bool
}

// Session com governador
type Session struct {
	conn         *websocket.Conn
	streams      map[uint16]*Stream
	streamsMu    sync.RWMutex
	
	// GOVERNADOR
	queue        chan Frame
	activeStream *uint16
	lastSendTime time.Time
	govMu        sync.Mutex
	
	running      bool
}

func NewSession(conn *websocket.Conn) *Session {
	s := &Session{
		conn:         conn,
		streams:      make(map[uint16]*Stream),
		queue:        make(chan Frame, 1000),
		lastSendTime: time.Now().Add(-SEND_INTERVAL),
		running:      true,
	}
	go s.governorLoop()
	return s
}

// GOVERNADOR - Loop central que processa a fila
func (s *Session) governorLoop() {
	for s.running {
		select {
		case frame := <-s.queue:
			s.processFrame(frame)
		case <-time.After(5 * time.Millisecond):
			// Idle
		}
	}
}

func (s *Session) processFrame(frame Frame) {
	s.govMu.Lock()
	defer s.govMu.Unlock()
	
	// Esperar intervalo mínimo
	elapsed := time.Since(s.lastSendTime)
	if elapsed < SEND_INTERVAL {
		time.Sleep(SEND_INTERVAL - elapsed)
	}
	
	// Verificar stream ativo
	if s.activeStream != nil && *s.activeStream != frame.StreamID {
		// Outro stream tentando falar - requeue e espera
		select {
		case s.queue <- frame:
		default:
		}
		time.Sleep(5 * time.Millisecond)
		return
	}
	
	// Ativar stream se necessário
	if s.activeStream == nil {
		s.activeStream = &frame.StreamID
		logger.Printf("[GOV] Stream %d ativo", frame.StreamID)
	}
	
	// ENVIAR
	if frame.Direction == "TX" {
		s.sendToApp(frame.StreamID, frame.Payload)
	}
	
	s.lastSendTime = time.Now()
}

// Envia frame para o app (TX)
func (s *Session) sendToApp(id uint16, data []byte) {
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	
	err := s.conn.WriteMessage(websocket.BinaryMessage, frame)
	if err != nil {
		logger.Printf("[TX] Erro: %v", err)
		return
	}
	logger.Printf("[TX] id=%d len=%d", id, len(data))
}

// Queue frame para envio (fragmentado)
func (s *Session) queueTX(id uint16, data []byte) {
	// Fragmentar em chunks
	offset := 0
	for offset < len(data) {
		chunkSize := len(data) - offset
		if chunkSize > MAX_CHUNK {
			chunkSize = MAX_CHUNK
		}
		
		chunk := make([]byte, chunkSize)
		copy(chunk, data[offset:offset+chunkSize])
		
		select {
		case s.queue <- Frame{StreamID: id, Direction: "TX", Payload: chunk}:
		default:
			logger.Printf("[WARN] Queue cheia, descartando")
		}
		
		offset += chunkSize
	}
}

// Libera stream ativo
func (s *Session) releaseStream(id uint16) {
	s.govMu.Lock()
	defer s.govMu.Unlock()
	
	if s.activeStream != nil && *s.activeStream == id {
		s.activeStream = nil
		logger.Printf("[GOV] Stream %d liberado", id)
	}
}

func handleVPN(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth") != "sung:123.456" {
		http.Error(w, "Auth", 401)
		return
	}
	
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s := NewSession(conn)
	defer func() { s.running = false }()
	
	logger.Printf("[VPN] Conectado: %s", r.RemoteAddr)

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if len(msg) < 4 {
			continue
		}

		id := binary.BigEndian.Uint16(msg[0:2])
		length := binary.BigEndian.Uint16(msg[2:4])
		data := msg[4 : 4+length]

		logger.Printf("[RX] id=%d len=%d", id, length)

		s.streamsMu.RLock()
		stream := s.streams[id]
		s.streamsMu.RUnlock()

		if stream == nil && len(data) >= 4 {
			// CONNECT
			port := binary.BigEndian.Uint16(data[1:3])
			hostLen := data[3]
			host := string(data[4 : 4+hostLen])
			logger.Printf("[CONNECT] %s:%d", host, port)

			target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
			if err != nil {
				logger.Printf("[CONNECT] ERRO: %v", err)
				s.queueTX(id, []byte{0x01})
				continue
			}

			stream = &Stream{target: target}
			s.streamsMu.Lock()
			s.streams[id] = stream
			s.streamsMu.Unlock()
			
			// CONNECT OK - vai pela fila
			s.queueTX(id, []byte{0x00})
			logger.Printf("[CONNECT] OK id=%d", id)

			// Goroutine de leitura
			go func(id uint16, st *Stream) {
				buf := make([]byte, MAX_CHUNK)
				for !st.closed && s.running {
					st.target.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := st.target.Read(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						logger.Printf("[READ] id=%d erro=%v", id, err)
						break
					}
					if n > 0 {
						logger.Printf("[READ] id=%d bytes=%d", id, n)
						// Dados vão pela fila do governador
						chunk := make([]byte, n)
						copy(chunk, buf[:n])
						s.queueTX(id, chunk)
					}
				}
				if !st.closed {
					s.queueTX(id, []byte{}) // FIN
					st.closed = true
					s.releaseStream(id)
				}
			}(id, stream)

		} else if stream != nil && !stream.closed {
			if len(data) == 0 {
				// FIN
				logger.Printf("[FIN] id=%d", id)
				stream.closed = true
				stream.target.Close()
				s.streamsMu.Lock()
				delete(s.streams, id)
				s.streamsMu.Unlock()
				s.releaseStream(id)
			} else {
				// DATA - escrever no destino
				_, err := stream.target.Write(data)
				if err != nil {
					logger.Printf("[WRITE] id=%d ERRO: %v", id, err)
				} else {
					logger.Printf("[WRITE] id=%d len=%d", id, len(data))
				}
			}
		}
	}

	// Cleanup
	s.streamsMu.Lock()
	for _, st := range s.streams {
		st.closed = true
		st.target.Close()
	}
	s.streamsMu.Unlock()
	logger.Printf("[VPN] Desconectado")
}

func main() {
	fmt.Println("VPN GOVERNOR v1.0 - 120ms interval")
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", handleVPN)
	go http.ListenAndServe(":80", mux)

	// TLS
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "signup.ao"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     []string{"signup.ao", "www.signup.ao"},
		IPAddresses:  []net.IP{net.ParseIP("216.106.176.133")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, _ := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}),
	)

	srv := &http.Server{
		Addr:      ":443",
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go srv.ListenAndServeTLS("", "")

	logger.Println("[OK] :443")
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}
