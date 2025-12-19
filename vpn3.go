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

const SEND_DELAY = 30 * time.Millisecond

var logger = log.New(os.Stdout, "", log.LstdFlags)
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type Stream struct {
	target   net.Conn
	closed   bool
}

type Session struct {
	conn     *websocket.Conn
	streams  map[uint16]*Stream
	mu       sync.RWMutex
	writeMu  sync.Mutex
	lastSend time.Time
}

func (s *Session) sendFrame(id uint16, data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	
	elapsed := time.Since(s.lastSend)
	if elapsed < SEND_DELAY {
		time.Sleep(SEND_DELAY - elapsed)
	}
	
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	s.conn.WriteMessage(websocket.BinaryMessage, frame)
	logger.Printf("[SEND] id=%d len=%d", id, len(data))
	s.lastSend = time.Now()
}

func (s *Session) getStream(id uint16) *Stream {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streams[id]
}

func handleVPN(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth") != "sung:123.456" {
		http.Error(w, "Auth", 401)
		return
	}
	conn, _ := upgrader.Upgrade(w, r, nil)
	defer conn.Close()

	s := &Session{conn: conn, streams: make(map[uint16]*Stream), lastSend: time.Now()}
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

		logger.Printf("[RECV] id=%d len=%d", id, length)

		stream := s.getStream(id)

		if stream == nil && len(data) >= 4 {
			// CONNECT
			port := binary.BigEndian.Uint16(data[1:3])
			hostLen := data[3]
			host := string(data[4 : 4+hostLen])
			logger.Printf("[CONNECT] %s:%d", host, port)

			target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
			if err != nil {
				logger.Printf("[CONNECT] ERRO: %v", err)
				s.sendFrame(id, []byte{0x01})
				continue
			}

			stream = &Stream{target: target, closed: false}
			s.mu.Lock()
			s.streams[id] = stream
			s.mu.Unlock()
			
			s.sendFrame(id, []byte{0x00})
			logger.Printf("[CONNECT] OK id=%d", id)

			// Goroutine de leitura
			go func(id uint16, st *Stream) {
				buf := make([]byte, 300)
				for {
					if st.closed {
						break
					}
					st.target.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := st.target.Read(buf)
					if err != nil {
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue // Timeout é OK, continuar
						}
						logger.Printf("[READ] id=%d erro=%v", id, err)
						break
					}
					if n > 0 {
						logger.Printf("[READ] id=%d bytes=%d", id, n)
						s.sendFrame(id, buf[:n])
					}
				}
				if !st.closed {
					s.sendFrame(id, []byte{})
					st.closed = true
				}
				logger.Printf("[CLOSE] id=%d", id)
			}(id, stream)

		} else if stream != nil && !stream.closed {
			if len(data) == 0 {
				// FIN
				logger.Printf("[FIN] id=%d", id)
				stream.closed = true
				stream.target.Close()
				s.mu.Lock()
				delete(s.streams, id)
				s.mu.Unlock()
			} else {
				// DATA
				n, err := stream.target.Write(data)
				if err != nil {
					logger.Printf("[WRITE] id=%d ERRO: %v", id, err)
				} else {
					logger.Printf("[WRITE] id=%d len=%d", id, n)
				}
			}
		} else {
			logger.Printf("[WARN] id=%d stream nil ou closed", id)
		}
	}

	s.mu.Lock()
	for id, st := range s.streams {
		st.closed = true
		st.target.Close()
		logger.Printf("[CLEANUP] id=%d", id)
	}
	s.mu.Unlock()
	logger.Printf("[VPN] Desconectado")
}

func main() {
	fmt.Println("VPN v3.1 - Fixed")
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", handleVPN)
	go http.ListenAndServe(":80", mux)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "signup.ao"}, NotBefore: time.Now(), NotAfter: time.Now().Add(10*365*24*time.Hour), DNSNames: []string{"signup.ao", "www.signup.ao"}, IPAddresses: []net.IP{net.ParseIP("216.106.176.133")}}
	der, _ := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	srv := &http.Server{Addr: ":443", Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ListenAndServeTLS("", "")
	logger.Println("[OK] :443")
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}
