package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Simple struct for JSON response
type Response struct {
	Message string `json:"message"`
}

// Home handler - serves a basic "site" page (GET request)
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<html><body><h1>Welcome to the simple Go site!</h1><p>Test your handlers with Postman.</p></body></html>")
}

// Test GET handler
func testGetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	response := Response{Message: "This is a GET response"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Test POST handler - expects JSON body like {"input": "some value"}
func testPostHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input map[string]string
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	message := fmt.Sprintf("Received input: %v", input["input"])
	response := Response{Message: message}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Redirect HTTP to HTTPS
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
}

func main() {
	// Register handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/test-get", testGetHandler)
	mux.HandleFunc("/test-post", testPostHandler)

	// HTTPS server
	httpsSrv := &http.Server{
		Addr:    ":443",
		Handler: mux,
	}

	// HTTP server for redirect
	httpSrv := &http.Server{
		Addr:    ":80",
		Handler: http.HandlerFunc(redirectToHTTPS),
	}

	// Start HTTP redirect in a goroutine
	go func() {
		log.Println("Starting HTTP redirect server on :80")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Start HTTPS server
	go func() {
		log.Println("Starting HTTPS server on :443")
		// Updated paths based on your /etc/ssl/rassilkiin.ru directory (assuming standard file names; adjust if different)
		certPath := "/etc/ssl/rassilkiin.ru/fullchain.pem" // Or cert.pem if that's the name
		keyPath := "/etc/ssl/rassilkiin.ru/privkey.pem"    // Or key.pem if that's the name
		if err := httpsSrv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpsSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTPS shutdown error: %v", err)
	}
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	log.Println("Servers stopped gracefully")
}
