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
	"math/big"
	"net/http"
	"strings"
	"time"
)

func main() {
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  TEST SNI: saldo.unitel.ao")
	fmt.Println("════════════════════════════════════════")

	mux := http.NewServeMux()

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("[%s] PING from %s\n", time.Now().Format("15:04:05"), r.RemoteAddr)
		w.Write([]byte("PONG"))
	})

	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		size := r.URL.Query().Get("bytes")
		fmt.Printf("[%s] TEST bytes=%s from %s\n", time.Now().Format("15:04:05"), size, r.RemoteAddr)

		var resp string
		switch size {
		case "100":
			resp = "OK100:" + strings.Repeat("A", 94)
		case "500":
			resp = "OK500:" + strings.Repeat("B", 494)
		case "1000":
			resp = "OK1K:" + strings.Repeat("C", 995)
		case "5000":
			resp = "OK5K:" + strings.Repeat("D", 4995)
		case "10000":
			resp = "OK10K:" + strings.Repeat("E", 9994)
		case "50000":
			resp = "OK50K:" + strings.Repeat("F", 49994)
		default:
			resp = "USE: /test?bytes=100|500|1000|5000|10000|50000"
		}

		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(resp)))
		w.Write([]byte(resp))
		fmt.Printf("[%s] SENT %d bytes\n", time.Now().Format("15:04:05"), len(resp))
	})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "saldo.unitel.ao"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"saldo.unitel.ao"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	cert, _ := tls.X509KeyPair(certPEM, keyPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			fmt.Printf("[%s] SNI: %s\n", time.Now().Format("15:04:05"), info.ServerName)
			return &cert, nil
		},
	}

	go func() {
		http.ListenAndServe(":80", mux)
	}()

	fmt.Println("  /ping            -> 4 bytes")
	fmt.Println("  /test?bytes=100  -> 100 bytes")
	fmt.Println("  /test?bytes=500  -> 500 bytes")
	fmt.Println("  /test?bytes=1000 -> 1 KB")
	fmt.Println("  /test?bytes=5000 -> 5 KB")
	fmt.Println("  /test?bytes=10000-> 10 KB")
	fmt.Println("  /test?bytes=50000-> 50 KB")
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  Porta 80 e 443 ativas...")
	fmt.Println("")

	server := &http.Server{Addr: ":443", Handler: mux, TLSConfig: tlsConfig}
	listener, _ := tls.Listen("tcp", ":443", tlsConfig)
	server.Serve(listener)
}
