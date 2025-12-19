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

	googleURL := fmt.Sprintf("https://www.google.com/search?q=%s&hl=pt", url.QueryEscape(query))
	
	req, _ := http.NewRequest("GET", googleURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
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
	
	logger.Printf("[SEARCH] Google: %d bytes", len(html))
	
	// Salvar HTML para debug
	os.WriteFile("/tmp/google_debug.html", body, 0644)
	logger.Printf("[DEBUG] HTML salvo em /tmp/google_debug.html")
	
	// Extrair resultados
	results := extractResults(html)
	
	// Formatar
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
	
	logger.Printf("[SEARCH] Results: %d, Response: %d bytes", len(results), len(response))
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

func extractResults(html string) []string {
	var results []string
	seen := make(map[string]bool)
	
	// Lista de padrões para tentar
	patterns := []string{
		`<h3[^>]*>([^<]{10,100})</h3>`,                    // h3 tags
		`class="[^"]*LC20lb[^"]*"[^>]*>([^<]{10,100})<`,   // LC20lb class
		`class="[^"]*DKV0Md[^"]*"[^>]*>([^<]{10,100})<`,   // DKV0Md class  
		`class="[^"]*BNeawe[^"]*"[^>]*>([^<]{10,100})<`,   // BNeawe class
		`<a[^>]*href="/url[^"]*"[^>]*>([^<]{10,80})</a>`,  // Links com /url
		`data-ved="[^"]*"[^>]*>([^<]{15,80})</`,           // data-ved elements
		`<span[^>]*>([A-Z][^<]{20,80})</span>`,            // Spans com texto
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
				if isValidResult(text) && !seen[text] {
					seen[text] = true
					results = append(results, text)
					logger.Printf("[MATCH] Pattern '%s' found: %s", pattern[:20], text[:min(30, len(text))])
				}
			}
			if len(results) >= 5 {
				break
			}
		}
	}
	
	// Se ainda não encontrou, tentar extração mais agressiva
	if len(results) == 0 {
		logger.Printf("[WARN] Nenhum padrão funcionou, tentando extração agressiva")
		
		// Procurar qualquer texto que pareça título
		re := regexp.MustCompile(`>([A-Z][a-zA-ZáàâãéèêíïóôõöúçñÁÀÂÃÉÈÊÍÏÓÔÕÖÚÇÑ\s\-]{15,70})<`)
		matches := re.FindAllStringSubmatch(html, 100)
		
		for _, m := range matches {
			text := cleanText(m[1])
			if isValidResult(text) && !seen[text] {
				seen[text] = true
				results = append(results, text)
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
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func isValidResult(s string) bool {
	if len(s) < 10 || len(s) > 100 {
		return false
	}
	// Filtrar lixo
	invalid := []string{"{", "}", "function", "var ", "const ", "let ", "return", "window.", "document.", "http", "www", "google", "Pesquisar", "Fazer login"}
	for _, inv := range invalid {
		if strings.Contains(strings.ToLower(s), strings.ToLower(inv)) {
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
	path := r.URL.Path
	query := r.URL.Query()
	
	logger.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.String())
	
	reqUser := query.Get("user")
	reqPass := query.Get("password")
	
	if reqUser != user || reqPass != password {
		if path != "/status" && path != "/" {
			http.Error(w, "Auth", 403)
			return
		}
	}
	
	switch path {
	case "/search":
		q := query.Get("q")
		if q == "" {
			w.Write([]byte("OK||0\nVazia"))
			return
		}
		handleSearch(w, r, q)
	default:
		w.Write([]byte(`{"ok":true,"v":"6.4"}`))
	}
}

func main() {
	fmt.Println("🔍 GRATISBET v6.4")

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
			MinVersion:   tls.VersionTLS12,
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
