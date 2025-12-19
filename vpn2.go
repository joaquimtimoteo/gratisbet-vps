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
	"sync"
	"syscall"
	"time"
	"github.com/gorilla/websocket"
)

var logger = log.New(os.Stdout, "", log.LstdFlags)
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type Session struct {
	conn    *websocket.Conn
	streams map[uint16]net.Conn
	mu      sync.RWMutex
	writeMu sync.Mutex
}

func (s *Session) sendFrame(id uint16, data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(frame[0:2], id)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(data)))
	copy(frame[4:], data)
	s.conn.WriteMessage(websocket.BinaryMessage, frame)
}

func handleVPN(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth") != "sung:123.456" {
		http.Error(w, "Auth", 401)
		return
	}
	conn, _ := upgrader.Upgrade(w, r, nil)
	defer conn.Close()
	
	s := &Session{conn: conn, streams: make(map[uint16]net.Conn)}
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
		
		logger.Printf("[FRAME] id=%d len=%d", id, length)
		
		s.mu.RLock()
		target := s.streams[id]
		s.mu.RUnlock()
		
		if target == nil && len(data) >= 4 {
			port := binary.BigEndian.Uint16(data[1:3])
			hostLen := data[3]
			host := string(data[4 : 4+hostLen])
			logger.Printf("[CONNECT] %s:%d", host, port)
			
			target, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
			if err != nil {
				s.sendFrame(id, []byte{0x01})
				continue
			}
			
			s.mu.Lock()
			s.streams[id] = target
			s.mu.Unlock()
			
			s.sendFrame(id, []byte{0x00})
			
			go func(id uint16, t net.Conn) {
				buf := make([]byte, 4096)
				for {
					n, err := t.Read(buf)
					if err != nil {
						break
					}
					s.sendFrame(id, buf[:n])
				}
				s.sendFrame(id, []byte{})
				s.mu.Lock()
				delete(s.streams, id)
				s.mu.Unlock()
				t.Close()
			}(id, target)
		} else if target != nil {
			if len(data) == 0 {
				target.Close()
				s.mu.Lock()
				delete(s.streams, id)
				s.mu.Unlock()
			} else {
				target.Write(data)
			}
		}
	}
	
	s.mu.Lock()
	for _, t := range s.streams {
		t.Close()
	}
	s.mu.Unlock()
	logger.Printf("[VPN] Desconectado")
}

func main() {
	fmt.Println("VPN v2.0")
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
