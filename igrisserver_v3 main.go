package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func main() {
	// Cliente HTTP com headers de browser real
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Seguir redirects
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "GratisBet Proxy Server v3.0 - Anti-403 Edition")
	})

	http.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, "Missing url parameter", http.StatusBadRequest)
			return
		}

		decoded, err := url.QueryUnescape(targetURL)
		if err != nil {
			decoded = targetURL
		}

		log.Printf("[PROXY] %s", decoded)

		// Criar request com headers de browser real
		req, err := http.NewRequest("GET", decoded, nil)
		if err != nil {
			log.Printf("[ERROR] Create request: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// Extrair o host do URL alvo
		parsedURL, _ := url.Parse(decoded)
		host := parsedURL.Host

		// Headers que simulam um browser real Android
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "pt-AO,pt;q=0.9,pt-PT;q=0.8,en-US;q=0.7,en;q=0.6")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-CH-UA-Mobile", "?1")
		req.Header.Set("Sec-CH-UA-Platform", `"Android"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Cache-Control", "max-age=0")
		
		// Headers críticos para evitar 403
		req.Header.Set("Origin", fmt.Sprintf("https://%s", host))
		req.Header.Set("Referer", fmt.Sprintf("https://%s/", host))

		// Headers específicos para APIs JSON
		if strings.Contains(decoded, "/api/") || strings.Contains(decoded, "gateway") || strings.Contains(decoded, ".json") {
			req.Header.Set("Accept", "application/json, text/plain, */*")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}

		// Headers para JavaScript
		if strings.Contains(decoded, ".js") {
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Sec-Fetch-Dest", "script")
			req.Header.Set("Sec-Fetch-Mode", "no-cors")
		}
		
		// Headers para CSS
		if strings.Contains(decoded, ".css") {
			req.Header.Set("Accept", "text/css,*/*;q=0.1")
			req.Header.Set("Sec-Fetch-Dest", "style")
			req.Header.Set("Sec-Fetch-Mode", "no-cors")
		}
		
		// Headers para imagens
		if strings.Contains(decoded, ".png") || strings.Contains(decoded, ".jpg") || 
		   strings.Contains(decoded, ".jpeg") || strings.Contains(decoded, ".webp") || 
		   strings.Contains(decoded, ".svg") || strings.Contains(decoded, ".gif") ||
		   strings.Contains(decoded, ".ico") {
			req.Header.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
			req.Header.Set("Sec-Fetch-Dest", "image")
			req.Header.Set("Sec-Fetch-Mode", "no-cors")
		}

		// Headers para fonts
		if strings.Contains(decoded, ".woff") || strings.Contains(decoded, ".ttf") || strings.Contains(decoded, ".otf") {
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Sec-Fetch-Dest", "font")
			req.Header.Set("Sec-Fetch-Mode", "cors")
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] Request failed: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[ERROR] Read body: %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		log.Printf("[SENT] %d bytes (status %d)", len(body), resp.StatusCode)

		// Copiar headers de resposta importantes
		for _, h := range []string{"Content-Type", "Cache-Control", "ETag", "Last-Modified"} {
			if v := resp.Header.Get(h); v != "" {
				w.Header().Set(h, v)
			}
		}

		// CORS headers para permitir acesso
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK - %s", time.Now().Format(time.RFC3339))
	})

	log.Println("=================================")
	log.Println("  GratisBet Proxy Server v3.0")
	log.Println("  Anti-403 Edition")
	log.Println("  Port: 80")
	log.Println("=================================")

	log.Fatal(http.ListenAndServe(":80", nil))
}
