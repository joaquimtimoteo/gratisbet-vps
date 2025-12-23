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

// API Football Key
const FOOTBALL_API_KEY = "416ad7217f99978b716b399ea3d08edc"

func main() {
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:       100,
			IdleConnTimeout:    90 * time.Second,
			DisableCompression: true,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "GratisBet Proxy + Football API")
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

		// Detectar se é API Football
		isFootballAPI := strings.Contains(decoded, "api-sports.io") || strings.Contains(decoded, "api-football")

		if isFootballAPI {
			// Headers específicos para API Football
			req.Header.Set("x-rapidapi-key", FOOTBALL_API_KEY)
			req.Header.Set("x-rapidapi-host", "v3.football.api-sports.io")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "GratisBet/1.0")
			log.Printf("[API-FOOTBALL] Request com API key")
		} else {
			// Headers de browser para sites normais
			req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
			req.Header.Set("Accept-Language", "pt-AO,pt;q=0.9,en;q=0.8")
			req.Header.Set("Accept-Encoding", "identity")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Origin", fmt.Sprintf("https://%s", host))
			req.Header.Set("Referer", fmt.Sprintf("https://%s/", host))

			// Headers para APIs JSON
			if strings.Contains(decoded, "/api/") || strings.Contains(decoded, "gateway") || strings.Contains(decoded, ".json") {
				req.Header.Set("Accept", "application/json, text/plain, */*")
				req.Header.Set("X-Requested-With", "XMLHttpRequest")
			}
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

		// Content-Type
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
	log.Println("  GratisBet Proxy + Football")
	log.Println("  Port: 80")
	log.Println("=================================")

	log.Fatal(http.ListenAndServe(":80", nil))
}
