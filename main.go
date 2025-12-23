package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

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
		fmt.Fprintf(w, "GratisBet Proxy OK")
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

		// Headers de browser
		req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "pt-AO,pt;q=0.9,en;q=0.8")
		req.Header.Set("Accept-Encoding", "identity")

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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(resp.StatusCode)
		w.Write(body)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	log.Println("=================================")
	log.Println("  GratisBet Proxy Server")
	log.Println("  Port: 80")
	log.Println("=================================")

	log.Fatal(http.ListenAndServe(":80", nil))
}
