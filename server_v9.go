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
║                     GRATISBET SERVER v9.0 - COMPLETO                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ENDPOINTS:                                                                   ║
║  ─────────                                                                    ║
║  /ping              Health check                                              ║
║  /qs?q=termo        Quick Search (<400 bytes)                                ║
║  /search?q=termo    Full Search                                              ║
║  /weather?city=X    Previsão do tempo                                        ║
║  /news              Notícias Angola                                          ║
║  /ai?q=pergunta     Chat com IA                                              ║
║  /football          Placares de futebol                                      ║
║  /exchange          Câmbio AOA                                               ║
║                                                                               ║
║  SNI: www.signup.ao (zero-rated na Unitel)                                   ║
║  Max response: 350 bytes (safe for DPI)                                      ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
*/

const (
	MAX_RESPONSE_SIZE = 350
	CACHE_TTL         = 5 * time.Minute
	SERVER_PORT_HTTPS = ":443"
	SERVER_PORT_HTTP  = ":80"
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	cache  = &SimpleCache{items: make(map[string]*CacheItem)}
)

// ════════════════════════════════════════════════════════════════════════════
// CACHE
// ════════════════════════════════════════════════════════════════════════════

type CacheItem struct {
	Data      string
	CreatedAt time.Time
}

type SimpleCache struct {
	items map[string]*CacheItem
	mu    sync.RWMutex
}

func (c *SimpleCache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	item, ok := c.items[key]
	if !ok || time.Since(item.CreatedAt) > CACHE_TTL {
		return "", false
	}
	return item.Data, true
}

func (c *SimpleCache) Set(key, data string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = &CacheItem{Data: data, CreatedAt: time.Now()}
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP CLIENT
// ════════════════════════════════════════════════════════════════════════════

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
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// ════════════════════════════════════════════════════════════════════════════
// /ping - Health Check
// ════════════════════════════════════════════════════════════════════════════

func handlePing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("GRATISBET OK"))
}

// ════════════════════════════════════════════════════════════════════════════
// /qs - Quick Search
// ════════════════════════════════════════════════════════════════════════════

func handleQuickSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Write([]byte("Uso: /qs?q=termo"))
		return
	}

	cacheKey := "qs:" + query
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] qs: %s", query)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[SEARCH] %s", query)

	searchURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		w.Write([]byte("Erro na busca"))
		return
	}

	results := parseSearchResults(htmlContent, 3)
	response := truncate(results, MAX_RESPONSE_SIZE)

	cache.Set(cacheKey, response)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(response))
}

func parseSearchResults(htmlContent string, maxResults int) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return "Erro ao processar"
	}

	var results []string
	count := 0

	var extract func(*html.Node)
	extract = func(n *html.Node) {
		if count >= maxResults {
			return
		}
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "class" && strings.Contains(attr.Val, "result__a") {
					title := extractNodeText(n)
					if title != "" {
						count++
						results = append(results, fmt.Sprintf("%d. %s", count, title))
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			extract(c)
		}
	}
	extract(doc)

	if len(results) == 0 {
		return "Nenhum resultado"
	}
	return strings.Join(results, "\n")
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

// ════════════════════════════════════════════════════════════════════════════
// /search - Full Search
// ════════════════════════════════════════════════════════════════════════════

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		w.Write([]byte("Uso: /search?q=termo"))
		return
	}

	cacheKey := "search:" + query
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] search: %s", query)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[SEARCH FULL] %s", query)

	searchURL := "https://html.duckduckgo.com/html/?q=" + url.QueryEscape(query)
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		w.Write([]byte("Erro na busca"))
		return
	}

	results := parseSearchResults(htmlContent, 5)

	cache.Set(cacheKey, results)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(results))
}

// ════════════════════════════════════════════════════════════════════════════
// /weather - Previsão do Tempo
// ════════════════════════════════════════════════════════════════════════════

func handleWeather(w http.ResponseWriter, r *http.Request) {
	city := r.URL.Query().Get("city")
	if city == "" {
		city = "Luanda"
	}

	cacheKey := "weather:" + city
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] weather: %s", city)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[WEATHER] %s", city)

	weatherURL := fmt.Sprintf("https://wttr.in/%s?format=3", url.QueryEscape(city))
	resp, err := httpClient.Get(weatherURL)
	if err != nil {
		w.Write([]byte("Erro ao buscar tempo"))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	weather := strings.TrimSpace(string(body))

	cache.Set(cacheKey, weather)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(weather))
}

// ════════════════════════════════════════════════════════════════════════════
// /news - Notícias Angola
// ════════════════════════════════════════════════════════════════════════════

func handleNews(w http.ResponseWriter, r *http.Request) {
	cacheKey := "news:angola"
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] news")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[NEWS] Fetching...")

	newsURL := "https://news.google.com/rss/search?q=angola&hl=pt-PT"
	resp, err := httpClient.Get(newsURL)
	if err != nil {
		w.Write([]byte("Erro ao buscar noticias"))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var news []string
	titleRegex := regexp.MustCompile(`<title><!\[CDATA\[([^\]]+)\]\]></title>|<title>([^<]+)</title>`)
	matches := titleRegex.FindAllStringSubmatch(string(body), 6)

	for i, match := range matches {
		if i == 0 {
			continue
		}
		title := match[1]
		if title == "" {
			title = match[2]
		}
		title = html.UnescapeString(title)
		if title != "" && len(title) > 5 {
			news = append(news, fmt.Sprintf("%d. %s", i, truncate(title, 80)))
		}
	}

	result := strings.Join(news, "\n")
	if result == "" {
		result = "Sem noticias disponiveis"
	}

	cache.Set(cacheKey, result)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(result))
}

// ════════════════════════════════════════════════════════════════════════════
// /ai - Chat com IA (Simples)
// ════════════════════════════════════════════════════════════════════════════

func handleAI(w http.ResponseWriter, r *http.Request) {
	question := r.URL.Query().Get("q")
	if question == "" {
		w.Write([]byte("Uso: /ai?q=pergunta"))
		return
	}

	logger.Printf("[AI] %s", question)

	// Respostas simples baseadas em padrões
	response := generateAIResponse(question)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(truncate(response, MAX_RESPONSE_SIZE)))
}

func generateAIResponse(question string) string {
	q := strings.ToLower(question)

	// Saudações
	if strings.Contains(q, "ola") || strings.Contains(q, "oi") || strings.Contains(q, "bom dia") {
		return "Ola! Sou o assistente GratisBet. Como posso ajudar?"
	}

	// Sobre o app
	if strings.Contains(q, "gratisbet") || strings.Contains(q, "app") {
		return "GratisBet e um app que permite usar internet gratis em Angola atraves da rede Unitel!"
	}

	// Capital de Angola
	if strings.Contains(q, "capital") && strings.Contains(q, "angola") {
		return "A capital de Angola e Luanda, uma cidade costeira com mais de 8 milhoes de habitantes."
	}

	// Presidente
	if strings.Contains(q, "presidente") && strings.Contains(q, "angola") {
		return "O Presidente de Angola e Joao Lourenco, no cargo desde 2017."
	}

	// Matemática simples
	if strings.Contains(q, "quanto") && strings.Contains(q, "+") {
		return "Para calculos matematicos, use uma calculadora. Posso ajudar com outras perguntas!"
	}

	// Tempo
	if strings.Contains(q, "hora") || strings.Contains(q, "tempo") {
		return "Para saber a hora atual, veja seu telefone. Para previsao do tempo, use /weather"
	}

	// Piada
	if strings.Contains(q, "piada") || strings.Contains(q, "rir") {
		return "Por que o programador usa oculos? Porque ele nao consegue C#! 😄"
	}

	// Aniversário
	if strings.Contains(q, "aniversario") || strings.Contains(q, "parabens") {
		return "Feliz aniversario! Que este dia seja cheio de alegria, saude e realizacoes. Parabens! 🎂"
	}

	// Estudar
	if strings.Contains(q, "estudar") || strings.Contains(q, "estudo") {
		return "Dicas: 1) Faca pausas de 5min a cada 25min. 2) Revise antes de dormir. 3) Ensine o que aprendeu."
	}

	// IA
	if strings.Contains(q, "inteligencia artificial") || strings.Contains(q, " ia ") {
		return "IA e a simulacao de inteligencia humana por maquinas. Usada em assistentes virtuais, traducao e mais."
	}

	// Resposta genérica
	return "Obrigado pela pergunta! Sou um assistente simples. Tente perguntas sobre Angola, dicas ou curiosidades."
}

// ════════════════════════════════════════════════════════════════════════════
// /football - Placares de Futebol
// ════════════════════════════════════════════════════════════════════════════

func handleFootball(w http.ResponseWriter, r *http.Request) {
	cacheKey := "football"
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] football")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[FOOTBALL] Fetching...")

	// Buscar resultados do Girabola via pesquisa
	searchURL := "https://html.duckduckgo.com/html/?q=girabola+resultados+hoje"
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		// Retornar dados de exemplo
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(getSampleFootball()))
		return
	}

	// Tentar extrair resultados
	results := parseSearchResults(htmlContent, 3)
	if results == "" || results == "Nenhum resultado" {
		results = getSampleFootball()
	}

	cache.Set(cacheKey, results)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(results))
}

func getSampleFootball() string {
	return `GIRABOLA 2024:
Petro 2-1 1Agosto | FIM
Sagrada 0-0 Inter | AO VIVO
Libolo 3-1 Huila | FIM
Kabuscorp 1-2 Bravos | FIM`
}

// ════════════════════════════════════════════════════════════════════════════
// /exchange - Câmbio AOA
// ════════════════════════════════════════════════════════════════════════════

func handleExchange(w http.ResponseWriter, r *http.Request) {
	cacheKey := "exchange"
	if cached, ok := cache.Get(cacheKey); ok {
		logger.Printf("[CACHE] exchange")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(cached))
		return
	}

	logger.Printf("[EXCHANGE] Fetching...")

	// Buscar câmbio via pesquisa
	searchURL := "https://html.duckduckgo.com/html/?q=dolar+kwanza+hoje+cotacao"
	htmlContent, err := fetchURL(searchURL)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(getSampleExchange()))
		return
	}

	results := parseSearchResults(htmlContent, 2)
	if results == "" || results == "Nenhum resultado" {
		results = getSampleExchange()
	}

	// Adicionar header
	results = "CAMBIO AOA:\n" + results

	cache.Set(cacheKey, results)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(results))
}

func getSampleExchange() string {
	return `CAMBIO AOA (estimativa):
USD: 1 = 830 AOA
EUR: 1 = 900 AOA
BRL: 1 = 140 AOA
ZAR: 1 = 45 AOA`
}

// ════════════════════════════════════════════════════════════════════════════
// STATUS
// ════════════════════════════════════════════════════════════════════════════

func handleStatus(w http.ResponseWriter, r *http.Request) {
	status := `GRATISBET v9.0

/ping - Status
/qs?q=X - Busca rapida
/search?q=X - Busca completa
/weather?city=X - Tempo
/news - Noticias Angola
/ai?q=X - Chat IA
/football - Futebol
/exchange - Cambio`

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(status))
}

// ════════════════════════════════════════════════════════════════════════════
// TLS CERTIFICATE
// ════════════════════════════════════════════════════════════════════════════

func generateCert() (tls.Certificate, error) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "www.signup.ao"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"www.signup.ao", "signup.ao", "*.signup.ao"},
	}

	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN
// ════════════════════════════════════════════════════════════════════════════

func main() {
	fmt.Println(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     GRATISBET SERVER v9.0 - COMPLETO                          ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ENDPOINTS:                                                                   ║
║  ─────────                                                                    ║
║  /ping              Health check                                              ║
║  /qs?q=termo        Quick Search (<350 bytes)                                ║
║  /search?q=termo    Full Search                                              ║
║  /weather?city=X    Previsao do tempo                                        ║
║  /news              Noticias Angola                                          ║
║  /ai?q=pergunta     Chat com IA                                              ║
║  /football          Placares futebol                                         ║
║  /exchange          Cambio AOA                                               ║
║                                                                               ║
║  SNI: www.signup.ao                                                          ║
║  Cache: 5 minutos                                                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝`)

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleStatus)
	mux.HandleFunc("/ping", handlePing)
	mux.HandleFunc("/qs", handleQuickSearch)
	mux.HandleFunc("/search", handleSearch)
	mux.HandleFunc("/weather", handleWeather)
	mux.HandleFunc("/news", handleNews)
	mux.HandleFunc("/ai", handleAI)
	mux.HandleFunc("/football", handleFootball)
	mux.HandleFunc("/exchange", handleExchange)

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

	// Start HTTP server (port 80)
	go func() {
		logger.Println("[OK] HTTP server starting on :80")
		http.ListenAndServe(SERVER_PORT_HTTP, mux)
	}()

	// Start HTTPS server (port 443)
	go func() {
		server := &http.Server{
			Addr:      SERVER_PORT_HTTPS,
			Handler:   mux,
			TLSConfig: tlsConfig,
		}

		listener, err := tls.Listen("tcp", SERVER_PORT_HTTPS, tlsConfig)
		if err != nil {
			logger.Fatal("TLS Listen error:", err)
		}

		logger.Println("[OK] HTTPS server starting on :443")
		server.Serve(listener)
	}()

	logger.Println("")
	logger.Println("[OK] ✅ GratisBet Server v9.0 READY!")
	logger.Println("")

	select {}
}
