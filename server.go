package main

import (
	"compress/gzip"
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
	googleURL := fmt.Sprintf("https://www.google.com/search?q=%s&hl=pt", url.QueryEscape(query))
	
	req, _ := http.NewRequest("GET", googleURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("[SEARCH] Error: %v", err)
		w.Write([]byte("ERRO|Falha na busca"))
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	html := string(body)
	
	// Extrair resultados
	results := extractSearchResults(html)
	
	// Formatar resposta compacta (< 500 bytes)
	response := formatCompactResults(query, results)
	
	logger.Printf("[SEARCH] Results: %d, Size: %d bytes", len(results), len(response))
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

type SearchResult struct {
	Title string
	URL   string
	Desc  string
}

func extractSearchResults(html string) []SearchResult {
	var results []SearchResult
	
	// Padrão para extrair títulos e links dos resultados do Google
	// Google usa <h3> para títulos de resultados
	titleRegex := regexp.MustCompile(`<h3[^>]*>([^<]+)</h3>`)
	linkRegex := regexp.MustCompile(`<a href="/url\?q=([^&"]+)`)
	
	titles := titleRegex.FindAllStringSubmatch(html, 10)
	links := linkRegex.FindAllStringSubmatch(html, 10)
	
	for i := 0; i < len(titles) && i < 5; i++ {
		result := SearchResult{
			Title: cleanText(titles[i][1]),
		}
		if i < len(links) {
			result.URL = links[i][1]
		}
		if result.Title != "" && len(result.Title) > 5 {
			results = append(results, result)
		}
	}
	
	// Se não encontrou com o padrão acima, tentar outro
	if len(results) == 0 {
		// Padrão alternativo
		altRegex := regexp.MustCompile(`<div class="[^"]*">([^<]{20,100})</div>`)
		matches := altRegex.FindAllStringSubmatch(html, 10)
		for i, m := range matches {
			if i >= 5 {
				break
			}
			text := cleanText(m[1])
			if len(text) > 20 && !strings.Contains(text, "{") {
				results = append(results, SearchResult{Title: text})
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
	// Trim
	s = strings.TrimSpace(s)
	return s
}

func formatCompactResults(query string, results []SearchResult) string {
	var sb strings.Builder
	
	// Formato: QUERY|NUM_RESULTS\nTITLE1\nTITLE2\n...
	sb.WriteString(fmt.Sprintf("OK|%s|%d\n", query, len(results)))
	
	for i, r := range results {
		// Limitar título a 60 chars
		title := r.Title
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, title))
	}
	
	// Se não houver resultados
	if len(results) == 0 {
		sb.WriteString("Nenhum resultado encontrado.\n")
	}
	
	result := sb.String()
	
	// Garantir que não excede 450 bytes
	if len(result) > 450 {
		result = result[:450]
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
		// Permitir /status sem auth
		if path != "/status" && path != "/" && path != "/health" {
			http.Error(w, "Auth failed", http.StatusForbidden)
			return
		}
	}
	
	switch {
	case path == "/search":
		q := query.Get("q")
		if q == "" {
			w.Write([]byte("ERRO|Query vazia"))
			return
		}
		handleSearch(w, r, q)
		
	case path == "/fetch":
		targetURL := query.Get("url")
		if targetURL == "" {
			http.Error(w, "Missing url", http.StatusBadRequest)
			return
		}
		handleFetch(w, r, targetURL)
		
	case path == "/status" || path == "/" || path == "/health":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":"6.0-search"}`))
		
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

// Fetch normal (para testes)
func handleFetch(w http.ResponseWriter, r *http.Request, targetURL string) {
	decoded, _ := url.QueryUnescape(targetURL)
	if decoded != "" {
		targetURL = decoded
	}
	
	logger.Printf("[FETCH] %s", targetURL)
	
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36")
	req.Header.Set("Accept-Encoding", "gzip")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	// Comprimir
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Content-Encoding", "gzip")
	
	gz := gzip.NewWriter(w)
	gz.Write(body)
	gz.Close()
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════╗
║        🔍 GRATISBET SEARCH SERVER v6.0                   ║
║                                                           ║
║   /search?q=...  → Busca Google (< 500 bytes)            ║
║   /fetch?url=... → Fetch normal                          ║
║   /status        → Health check                          ║
║                                                           ║
║   HTTP: 80  |  TLS: 443                                  ║
╚═══════════════════════════════════════════════════════════╝`)

	// HTTP Server
	go func() {
		http.HandleFunc("/", handleRequest)
		logger.Println("[!] HTTP porta 80")
		http.ListenAndServe(fmt.Sprintf("%s:%d", listenIP, listenPort), nil)
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

	tlsListener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", listenIP, listenPortTLS), tlsConfig)
	if err != nil {
		logger.Fatal(err)
	}

	go func() {
		logger.Println("[!] TLS porta 443")
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				continue
			}
			go handleTLSConn(conn)
		}
	}()

	logger.Println("[!] Servidor v6.0 pronto!")
	
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
}

func handleTLSConn(conn net.Conn) {
	defer conn.Close()
	
	// Usar http.Server para processar a conexão
	server := &http.Server{
		Handler: http.HandlerFunc(handleRequest),
	}
	
	// Criar um listener fake com uma conexão
	server.Serve(&singleConnListener{conn: conn})
}

type singleConnListener struct {
	conn   net.Conn
	served bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.served {
		return nil, fmt.Errorf("closed")
	}
	l.served = true
	return l.conn, nil
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
