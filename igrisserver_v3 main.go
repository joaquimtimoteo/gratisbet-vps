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
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:      100,
			IdleConnTimeout:   90 * time.Second,
			DisableCompression: true,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "GratisBet Proxy Server v3.0")
	})

	http.HandleFunc("/proxy", func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.Query().Get("url")
		if targetURL == "" {
			http.Error(w, "Missing url", http.StatusBadRequest)
			return
		}

		decoded, err := url.QueryUnescape(targetURL)
		if err != nil {
			decoded = targetURL
		}

		log.Printf("[PROXY] %s", decoded)

		req, err := http.NewRequest("GET", decoded, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		parsedURL, _ := url.Parse(decoded)
		host := parsedURL.Host

		// Headers de browser Android
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		req.Header.Set("Accept-Language", "pt-AO,pt;q=0.9,en;q=0.8")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Connection", "keep-alive")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-CH-UA", `"Chromium";v="120", "Google Chrome";v="120"`)
		req.Header.Set("Sec-CH-UA-Mobile", "?1")
		req.Header.Set("Sec-CH-UA-Platform", `"Android"`)
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Origin", fmt.Sprintf("https://%s", host))
		req.Header.Set("Referer", fmt.Sprintf("https://%s/", host))

		// Headers para APIs
		if strings.Contains(decoded, "/api/") || strings.Contains(decoded, "gateway") {
			req.Header.Set("Accept", "application/json, text/plain, */*")
			req.Header.Set("Sec-Fetch-Dest", "empty")
			req.Header.Set("Sec-Fetch-Mode", "cors")
			req.Header.Set("X-Requested-With", "XMLHttpRequest")
		}

		// Headers para JS
		if strings.Contains(decoded, ".js") {
			req.Header.Set("Accept", "*/*")
			req.Header.Set("Sec-Fetch-Dest", "script")
		}

		// Headers para CSS
		if strings.Contains(decoded, ".css") {
			req.Header.Set("Accept", "text/css,*/*;q=0.1")
			req.Header.Set("Sec-Fetch-Dest", "style")
		}

		// Headers para imagens
		if strings.Contains(decoded, ".png") || strings.Contains(decoded, ".jpg") ||
			strings.Contains(decoded, ".webp") || strings.Contains(decoded, ".svg") ||
			strings.Contains(decoded, ".ico") || strings.Contains(decoded, ".gif") {
			req.Header.Set("Accept", "image/avif,image/webp,image/apng,image/*,*/*;q=0.8")
			req.Header.Set("Sec-Fetch-Dest", "image")
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[ERROR] %v", err)
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		log.Printf("[SENT] %d bytes (status %d)", len(body), resp.StatusCode)

		// Copiar Content-Type
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}

		// CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")

		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	log.Println("=================================")
	log.Println("  GratisBet Proxy v3.0")
	log.Println("  Anti-403 Edition")
	log.Println("  Port: 80")
	log.Println("=================================")

	log.Fatal(http.ListenAndServe(":80", nil))
}
