package main

import (
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

/*
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v8.0 - BROWSER OTIMIZADO                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  Otimizações para funcionar com DPI da Unitel:                               ║
║                                                                               ║
║  1. FRAGMENTAÇÃO: Respostas divididas em chunks <400 bytes                   ║
║  2. COMPRESSÃO: Apenas texto essencial, sem HTML/CSS/JS                      ║
║  3. CACHE: Respostas cacheadas por 5 minutos                                 ║
║  4. ENDPOINTS ESPECIALIZADOS: /search, /read, /weather, /news               ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/

const (
	MAX_CHUNK_SIZE = 350 // Bytes por chunk (seguro para DPI)
	CACHE_TTL      = 5 * time.Minute
	SERVER_PORT    = ":443"
	HTTP_PORT      = ":80"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	cache  = &ResponseCache{items: make(map[string]*CacheItem)}
)

// ============================================
// CACHE
// ============================================
type CacheItem struct {
	Data      string
	Chunks    []string
	CreatedAt time.Time
}

type ResponseCache struct {
	items map[string]*CacheItem
	mu    sync.RWMutex
}

func (c *ResponseCache) Get(key string) (*CacheItem, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok {
		return nil, false
	}
	if time.Since(item.CreatedAt) > CACHE_TTL {
		return nil, false
	}
	return item, true
}

func (c *ResponseCache) Set(key string, data string) *CacheItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	chunks := splitIntoChunks(data, MAX_CHUNK_SIZE)
	item := &CacheItem{
		Data:      data,
		Chunks:    chunks,
		CreatedAt: time.Now(),
	}
	c.items[key] = item
	return item
}

func splitIntoChunks(data string, size int) []string {
	var chunks []string
	runes := []rune(data)
	for i := 0; i < len(runes); i += size {
		end := i + size
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[i:end]))
	}
	return chunks
}

func cacheKey(endpoint, query string) string {
	h := sha256.Sum256([]byte(endpoint + ":" + query))
	return hex.EncodeToString(h[:8])
}

// ============================================
// TEXT EXTRACTION
// ============================================
func extractText(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return cleanText(htmlContent)
	}
	
	var text strings.Builder
	var extract func(*html.Node)
	
	extract = func(n *html.Node) {
		// Skip script, style, nav, footer, header
		if n.Type == html.ElementNode {
			switch n.Data {
			case "script", "style", "nav", "footer", "header", "aside", "noscript", "iframe":
				return
			}
		}
		
		if n.Type == html.TextNode {
			t := strings.TrimSpace(n.Data)
			if len(t) > 0 {
				text.WriteString(t)
				text.WriteString(" ")
			}
		}
		
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
		
		// Add newlines after block elements
		if n.Type == html.ElementNode {
			switch n.Data {
			case "p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "h6", "tr":
				text.WriteString("\n")
			}
		}
	}
	
	extract(doc)
	return cleanText(text.String())
}

func cleanText(text string) string {
	// Remove extra whitespace
	space := regexp.MustCompile(`\s+`)
	text = space.ReplaceAllString(text, " ")
	
	// Remove extra newlines
	newlines := regexp.MustCompile(`\n{3,}`)
	text = newlines.ReplaceAllString(text, "\n\n")
	
	return strings.TrimSpace(text)
}

// ============================================
// HTTP CLIENT
// ============================================
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func fetchURL(targetURL string) (string, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return "", err
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 Chrome/91.0.4472.120 Mobile Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8")
	
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, _ = gzip.NewReader(resp.Body)
	}
	
	body, err := io.ReadAll(io.LimitReader(reader, 500*1024)) // Max 500KB
	if err != nil {
		return "", err
	}
	
	return string(body), nil
}

// ============================================
// SEARCH HANDLERS
// ============================================
func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Missing query", http.StatusBadRequest)
		return
	}
	
	chunk := r.URL.Query().Get("chunk")
	key := cacheKey("search", query)
	
	// Check cache
	if item, ok := cache.Get(key); ok {
		logger.Printf("[CACHE HIT] search: %s", query)
		serveChunked(w, item, chunk)
		return
	}
	
	logger.Printf("[SEARCH] %s", query)
	
	// Fetch from DuckDuckGo HTML
	searchURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		http.Error(w, "Search failed", http.StatusInternalServerError)
		return
	}
	
	// Parse results
	results := parseDuckDuckGoResults(htmlContent)
	
	// Cache and serve
	item := cache.Set(key, results)
	serveChunked(w, item, chunk)
}

func parseDuckDuckGoResults(htmlContent string) string {
	var results strings.Builder
	results.WriteString("📱 RESULTADOS:\n\n")
	
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return "Erro ao processar resultados"
	}
	
	count := 0
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if count >= 5 {
			return
		}
		
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "class" && strings.Contains(attr.Val, "result__a") {
					// Get title
					title := extractNodeText(n)
					
					// Get URL
					href := ""
					for _, a := range n.Attr {
						if a.Key == "href" {
							href = a.Val
							break
						}
					}
					
					if title != "" && href != "" {
						count++
						results.WriteString(fmt.Sprintf("%d. %s\n", count, title))
						// Extract domain from URL
						if u, err := url.Parse(href); err == nil {
							results.WriteString(fmt.Sprintf("   🔗 %s\n\n", u.Host))
						}
					}
				}
			}
		}
		
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	
	extract(doc)
	
	if count == 0 {
		return "Nenhum resultado encontrado."
	}
	
	return results.String()
}

func extractNodeText(n *html.Node) string {
	var text strings.Builder
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(n)
	return strings.TrimSpace(text.String())
}

// ============================================
// READ HANDLER (Article extractor)
// ============================================
func handleRead(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing URL", http.StatusBadRequest)
		return
	}
	
	chunk := r.URL.Query().Get("chunk")
	key := cacheKey("read", targetURL)
	
	// Check cache
	if item, ok := cache.Get(key); ok {
		logger.Printf("[CACHE HIT] read: %s", targetURL)
		serveChunked(w, item, chunk)
		return
	}
	
	logger.Printf("[READ] %s", targetURL)
	
	// Fetch page
	htmlContent, err := fetchURL(targetURL)
	if err != nil {
		http.Error(w, "Failed to fetch", http.StatusInternalServerError)
		return
	}
	
	// Extract text
	text := extractText(htmlContent)
	
	// Limit to 2000 chars
	if len(text) > 2000 {
		text = text[:2000] + "..."
	}
	
	// Cache and serve
	item := cache.Set(key, text)
	serveChunked(w, item, chunk)
}

// ============================================
// WEATHER HANDLER
// ============================================
func handleWeather(w http.ResponseWriter, r *http.Request) {
	city := r.URL.Query().Get("city")
	if city == "" {
		city = "Luanda"
	}
	
	chunk := r.URL.Query().Get("chunk")
	key := cacheKey("weather", city)
	
	// Check cache
	if item, ok := cache.Get(key); ok {
		logger.Printf("[CACHE HIT] weather: %s", city)
		serveChunked(w, item, chunk)
		return
	}
	
	logger.Printf("[WEATHER] %s", city)
	
	// Fetch from wttr.in (text format)
	weatherURL := fmt.Sprintf("https://wttr.in/%s?format=3", url.QueryEscape(city))
	resp, err := httpClient.Get(weatherURL)
	if err != nil {
		http.Error(w, "Weather failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	weather := strings.TrimSpace(string(body))
	
	// Cache and serve
	item := cache.Set(key, "🌤️ "+weather)
	serveChunked(w, item, chunk)
}

// ============================================
// NEWS HANDLER
// ============================================
func handleNews(w http.ResponseWriter, r *http.Request) {
	chunk := r.URL.Query().Get("chunk")
	key := cacheKey("news", "angola")
	
	// Check cache
	if item, ok := cache.Get(key); ok {
		logger.Printf("[CACHE HIT] news")
		serveChunked(w, item, chunk)
		return
	}
	
	logger.Printf("[NEWS] Fetching...")
	
	// Simple news from Google News RSS
	newsURL := "https://news.google.com/rss/search?q=angola&hl=pt-BR"
	resp, err := httpClient.Get(newsURL)
	if err != nil {
		http.Error(w, "News failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	body, _ := io.ReadAll(resp.Body)
	
	// Simple XML parsing for titles
	var news strings.Builder
	news.WriteString("📰 NOTÍCIAS ANGOLA:\n\n")
	
	titleRegex := regexp.MustCompile(`<title>([^<]+)</title>`)
	matches := titleRegex.FindAllStringSubmatch(string(body), 6)
	
	for i, match := range matches {
		if i == 0 {
			continue // Skip feed title
		}
		if len(match) > 1 {
			news.WriteString(fmt.Sprintf("%d. %s\n\n", i, html.UnescapeString(match[1])))
		}
	}
	
	// Cache and serve
	item := cache.Set(key, news.String())
	serveChunked(w, item, chunk)
}

// ============================================
// CHUNK SERVER
// ============================================
func serveChunked(w http.ResponseWriter, item *CacheItem, chunkNum string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Chunks", fmt.Sprintf("%d", len(item.Chunks)))
	
	if chunkNum == "" {
		// Return metadata
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_chunks": len(item.Chunks),
			"total_size":   len(item.Data),
		})
		return
	}
	
	// Return specific chunk
	var idx int
	fmt.Sscanf(chunkNum, "%d", &idx)
	
	if idx < 0 || idx >= len(item.Chunks) {
		http.Error(w, "Invalid chunk", http.StatusBadRequest)
		return
	}
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"chunk":   idx,
		"total":   len(item.Chunks),
		"content": item.Chunks[idx],
		"last":    idx == len(item.Chunks)-1,
	})
}

// ============================================
// QUICK ENDPOINTS (Single response, <400 bytes)
// ============================================
func handleQuickSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Write([]byte("?q=termo"))
		return
	}
	
	// Return minimal results
	searchURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		w.Write([]byte("Erro"))
		return
	}
	
	// Extract just first 3 result titles
	doc, _ := html.Parse(strings.NewReader(htmlContent))
	var results []string
	count := 0
	
	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if count >= 3 {
			return
		}
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "class" && strings.Contains(attr.Val, "result__a") {
					title := extractNodeText(n)
					if title != "" && len(title) < 50 {
						results = append(results, title)
						count++
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)
	
	response := strings.Join(results, "\n")
	if len(response) > 350 {
		response = response[:350]
	}
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

// ============================================
// STATUS & HELP
// ============================================
func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := `GRATISBET v8.0

ENDPOINTS:
/qs?q=termo - Busca rapida
/search?q=termo - Busca completa
/read?url=URL - Ler artigo
/weather?city=Luanda - Tempo
/news - Noticias Angola

Use &chunk=0,1,2... para respostas grandes`
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(status))
}

// ============================================
// TLS SERVER
// ============================================
func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "www.signup.ao"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"www.signup.ao", "signup.ao"},
	}
	
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	
	return tls.X509KeyPair(certPEM, keyPEM)
}

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                GRATISBET SERVER v8.0 - BROWSER OTIMIZADO                      ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ENDPOINTS:                                                                   ║
║  ─────────                                                                    ║
║  /qs?q=termo         Busca rápida (<400 bytes)                               ║
║  /search?q=termo     Busca completa (chunked)                                ║
║  /read?url=URL       Extrair texto de página                                 ║
║  /weather?city=X     Previsão do tempo                                       ║
║  /news               Notícias Angola                                         ║
║                                                                               ║
║  CHUNKING:                                                                    ║
║  ─────────                                                                    ║
║  Primeiro request retorna total_chunks                                        ║
║  Depois: ?chunk=0, ?chunk=1, etc.                                            ║
║                                                                               ║
║  Chunks: 350 bytes max (safe for Unitel DPI)                                 ║
║  Cache: 5 minutos                                                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝`)

	// Setup HTTP handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleStatus)
	mux.HandleFunc("/qs", handleQuickSearch)
	mux.HandleFunc("/search", handleSearch)
	mux.HandleFunc("/read", handleRead)
	mux.HandleFunc("/weather", handleWeather)
	mux.HandleFunc("/news", handleNews)
	
	// Generate TLS cert
	cert, err := generateCert()
	if err != nil {
		logger.Fatal("Cert error:", err)
	}
	
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			logger.Printf("[SNI] %s", info.ServerName)
			return &cert, nil
		},
	}
	
	// Start HTTPS server
	go func() {
		server := &http.Server{
			Addr:      SERVER_PORT,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}
		
		listener, err := tls.Listen("tcp", SERVER_PORT, tlsConfig)
		if err != nil {
			logger.Fatal("TLS Listen error:", err)
		}
		
		logger.Println("[OK] ✅ HTTPS server on :443")
		server.Serve(listener)
	}()
	
	// Start HTTP server (for health checks)
	go func() {
		http.ListenAndServe(HTTP_PORT, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("GratisBet v8.0 OK"))
		}))
		logger.Println("[OK] ✅ HTTP server on :80")
	}()
	
	logger.Println("[OK] ✅ Server ready!")
	logger.Println("")
	
	// Keep running
	select {}
}
