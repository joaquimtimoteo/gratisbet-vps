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

var logger = log.New(os.Stdout, "", log.LstdFlags)
var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Auth") != "sung:123.456" {
		http.Error(w, "Auth", 401)
		return
	}
	conn, _ := upgrader.Upgrade(w, r, nil)
	defer conn.Close()
	logger.Printf("[TEST] Conectado: %s", r.RemoteAddr)
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			logger.Printf("[TEST] Erro: %v", err)
			break
		}
		logger.Printf("[TEST] Recebido: %s", string(msg))
		conn.WriteMessage(mt, []byte("ECHO:"+string(msg)))
		logger.Printf("[TEST] Enviado ECHO")
	}
}

func generateCert() tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	t := x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "signup.ao"}, NotBefore: time.Now(), NotAfter: time.Now().Add(10*365*24*time.Hour), DNSNames: []string{"signup.ao", "www.signup.ao"}, IPAddresses: []net.IP{net.ParseIP("216.106.176.133")}}
	der, _ := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}))
	return cert
}

func main() {
	fmt.Println("TESTE WEBSOCKET ECHO")
	mux := http.NewServeMux()
	mux.HandleFunc("/test", handleTest)
	go http.ListenAndServe(":80", mux)
	cert := generateCert()
	srv := &http.Server{Addr: ":443", Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go srv.ListenAndServeTLS("", "")
	logger.Println("[OK] :443")
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
}
