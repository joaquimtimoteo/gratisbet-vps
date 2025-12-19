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
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	user     = "sung"
	password = "123.456"
	sniHost  = "signup.ao"
	vpsIP    = "216.106.176.133"
)

var logger = log.New(os.Stdout, "", log.LstdFlags)

var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: sniHost},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sniHost, "www." + sniHost},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(vpsIP)},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func handleSearch(w http.ResponseWriter, r *http.Request, query string) {
	logger.Printf("[SEARCH] Query: %s", query)

	// Usar DuckDuckGo HTML (mais fácil de fazer scraping)
	ddgURL := fmt.Sprintf("https://html.duckduckgo.com/html/?q=%s", url.QueryEscape(query))
	
	req, _ := http.NewRequest("GET", ddgURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("[SEARCH] Error: %v", err)
		w.Write([]byte(fmt.Sprintf("OK|%s|0\nErro: %v", query, err)))
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	
	logger.Printf("[SEARCH] DDG: %d bytes", len(html))
	
	// Debug
	os.WriteFile("/tmp/ddg.html", body, 0644)
	
	// Extrair resultados do DuckDuckGo
	results := extractDDGResults(html)
	
	// Formatar resposta
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("OK|%s|%d\n", query, len(results)))
	
	for i, r := range results {
		if len(r) > 50 {
			r = r[:47] + "..."
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, r))
	}
	
	if len(results) == 0 {
		sb.WriteString("Sem resultados.\n")
	}
	
	response := sb.String()
	if len(response) > 420 {
		response = response[:420]
	}
	
	logger.Printf("[SEARCH] Results: %d, Size: %d", len(results), len(response))
	
	w.Write([]byte(response))
}

func extractDDGResults(html string) []string {
	var results []string
	seen := make(map[string]bool)
	
	// DuckDuckGo usa class="result__a" para links de resultados
	patterns := []string{
		`class="result__a"[^>]*>([^<]{10,100})</a>`,
		`class="result__title"[^>]*>([^<]{10,100})<`,
		`class="result__snippet"[^>]*>([^<]{10,100})<`,
		`<a[^>]*class="[^"]*result[^"]*"[^>]*>([^<]{10,80})</a>`,
		`<h2[^>]*>([^<]{10,80})</h2>`,
	}
	
	for _, pattern := range patterns {
		if len(results) >= 5 {
			break
		}
		
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(html, 20)
		
		for _, m := range matches {
			if len(m) > 1 {
				text := cleanText(m[1])
				if isValid(text) && !seen[text] {
					seen[text] = true
					results = append(results, text)
					logger.Printf("[MATCH] %s", text[:min(40, len(text))])
				}
			}
			if len(results) >= 5 {
				break
			}
		}
	}
	
	return results
}

func cleanText(s string) string {
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "<b>", "")
	s = strings.ReplaceAll(s, "</b>", "")
	return strings.TrimSpace(s)
}

func isValid(s string) bool {
	if len(s) < 10 || len(s) > 100 {
		return false
	}
	bad := []string{"{", "function", "var ", "window", "document", "duckduckgo", "Pesquisar"}
	for _, b := range bad {
		if strings.Contains(strings.ToLower(s), b) {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	logger.Printf("[%s] %s", r.RemoteAddr, r.URL.String())
	
	if query.Get("user") != user || query.Get("password") != password {
		if r.URL.Path != "/" {
			http.Error(w, "Auth", 403)
			return
		}
	}
	
	if r.URL.Path == "/search" {
		q := query.Get("q")
		if q != "" {
			handleSearch(w, r, q)
			return
		}
	}
	w.Write([]byte(`{"v":"6.5-ddg"}`))
}

func main() {
	fmt.Println("🔍 GRATISBET v6.5 (DuckDuckGo)")

	go func() {
		logger.Println("[HTTP] :80")
		http.ListenAndServe(":80", http.HandlerFunc(handleRequest))
	}()

	cert, _ := generateCert()
	server := &http.Server{
		Addr:    ":443",
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	go func() {
		logger.Println("[TLS] :443")
		server.ListenAndServeTLS("", "")
	}()

	logger.Println("[OK]")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
