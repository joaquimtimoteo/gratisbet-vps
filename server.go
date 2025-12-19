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
	listenIP      = "0.0.0.0"
	listenPort    = 80
	listenPortTLS = 443
	user          = "sung"
	password      = "123.456"
	sniHost       = "signup.ao"
	vpsIP         = "216.106.176.133"
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
		DNSNames:              []string{sniHost, "www." + sniHost, "*." + sniHost},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP(vpsIP)},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ========================================
// SEARCH - Busca no Google e retorna resumido
// ========================================
func handleSearch(w http.ResponseWriter, r *http.Request, query string) {
	logger.Printf("[SEARCH] Query: %s", query)

	// Buscar no Google
	googleURL := fmt.Sprintf("https://www.google.com/search?q=%s&hl=pt&num=5", url.QueryEscape(query))
	
	req, _ := http.NewRequest("GET", googleURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("[SEARCH] Google error: %v", err)
		w.Write([]byte(fmt.Sprintf("OK|%s|0\nErro ao buscar: %v", query, err)))
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	
	logger.Printf("[SEARCH] Google returned %d bytes", len(html))
	
	// Extrair resultados com múltiplos padrões
	results := extractSearchResults(html)
	
	// Se não encontrou resultados, tentar padrão alternativo
	if len(results) == 0 {
		results = extractAlternativeResults(html)
	}
	
	// Formatar resposta compacta (< 450 bytes)
	response := formatCompactResults(query, results)
	
	logger.Printf("[SEARCH] Results: %d, Size: %d bytes", len(results), len(response))
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

type SearchResult struct {
	Title string
}

func extractSearchResults(html string) []SearchResult {
	var results []SearchResult
	
	// Padrão 1: Títulos em <h3>
	h3Regex := regexp.MustCompile(`<h3[^>]*class="[^"]*"[^>]*>([^<]+)</h3>`)
	matches := h3Regex.FindAllStringSubmatch(html, 10)
	
	for _, m := range matches {
		title := cleanText(m[1])
		if len(title) > 10 && len(title) < 100 {
			results = append(results, SearchResult{Title: title})
		}
		if len(results) >= 5 {
			break
		}
	}
	
	// Padrão 2: Se não encontrou, tentar <h3> simples
	if len(results) == 0 {
		h3Simple := regexp.MustCompile(`<h3[^>]*>([^<]{10,80})</h3>`)
		matches = h3Simple.FindAllStringSubmatch(html, 10)
		for _, m := range matches {
			title := cleanText(m[1])
			if len(title) > 10 {
				results = append(results, SearchResult{Title: title})
			}
			if len(results) >= 5 {
				break
			}
		}
	}
	
	return results
}

func extractAlternativeResults(html string) []SearchResult {
	var results []SearchResult
	
	// Padrão alternativo: divs com texto longo
	divRegex := regexp.MustCompile(`<div[^>]*>([A-Z][^<]{20,80})</div>`)
	matches := divRegex.FindAllStringSubmatch(html, 20)
	
	seen := make(map[string]bool)
	for _, m := range matches {
		text := cleanText(m[1])
		// Filtrar textos que parecem resultados de busca
		if len(text) > 20 && len(text) < 80 && !seen[text] {
			// Evitar JavaScript, CSS, etc
			if !strings.Contains(text, "{") && !strings.Contains(text, "function") && !strings.Contains(text, "var ") {
				seen[text] = true
				results = append(results, SearchResult{Title: text})
			}
		}
		if len(results) >= 5 {
			break
		}
	}
	
	// Se ainda não encontrou, extrair qualquer texto significativo
	if len(results) == 0 {
		// Buscar por padrões de texto entre tags
		textRegex := regexp.MustCompile(`>([A-Z][a-záàâãéèêíïóôõöúçñ\s]{15,60}[.!?]?)<`)
		matches = textRegex.FindAllStringSubmatch(html, 30)
		
		for _, m := range matches {
			text := cleanText(m[1])
			if len(text) > 15 && !seen[text] {
				seen[text] = true
				results = append(results, SearchResult{Title: text})
			}
			if len(results) >= 5 {
				break
			}
		}
	}
	
	return results
}

func cleanText(s string) string {
	// Remove HTML tags
	re := regexp.MustCompile(`<[^>]*>`)
	s = re.ReplaceAllString(s, "")
	// Remove entidades HTML
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	// Limpar espaços extras
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimSpace(s)
	return s
}

func formatCompactResults(query string, results []SearchResult) string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("OK|%s|%d\n", query, len(results)))
	
	for i, r := range results {
		title := r.Title
		if len(title) > 55 {
			title = title[:52] + "..."
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, title))
	}
	
	if len(results) == 0 {
		sb.WriteString("Nenhum resultado encontrado.\n")
		sb.WriteString("Tente outra busca.\n")
	}
	
	result := sb.String()
	
	// Garantir que não excede 430 bytes
	if len(result) > 430 {
		result = result[:430]
	}
	
	return result
}

// ========================================
// HANDLER PRINCIPAL
// ========================================
func handleRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	query := r.URL.Query()
	
	logger.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.String())
	
	// Verificar autenticação
	reqUser := query.Get("user")
	reqPass := query.Get("password")
	
	if reqUser != user || reqPass != password {
		if path != "/status" && path != "/" && path != "/health" {
			http.Error(w, "Auth failed", http.StatusForbidden)
			return
		}
	}
	
	switch {
	case path == "/search":
		q := query.Get("q")
		if q == "" {
			w.Write([]byte("OK||0\nQuery vazia"))
			return
		}
		handleSearch(w, r, q)
		
	case path == "/status" || path == "/" || path == "/health":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":"6.2-search"}`))
		
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🔍 GRATISBET SEARCH SERVER v6.2                   ║
║                                                           ║
║   /search?q=...  → Busca Google (< 450 bytes)            ║
║   /status        → Health check                          ║
║                                                           ║
║   HTTP: 80  |  TLS: 443                                  ║
╚═══════════════════════════════════════════════════════════╝`)

	// HTTP Server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", handleRequest)
	
	go func() {
		logger.Println("[!] HTTP porta 80")
		http.ListenAndServe(fmt.Sprintf("%s:%d", listenIP, listenPort), httpMux)
	}()

	// TLS Server
	cert, _ := generateCert()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s ← OK", info.ServerName)
			return &cert, nil
		},
	}

	tlsMux := http.NewServeMux()
	tlsMux.HandleFunc("/", handleRequest)

	tlsServer := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", listenIP, listenPortTLS),
		Handler:   tlsMux,
		TLSConfig: tlsConfig,
	}

	go func() {
		logger.Println("[!] TLS porta 443")
		tlsServer.ListenAndServeTLS("", "")
	}()

	logger.Println("[!] Servidor v6.2 pronto!")
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}
