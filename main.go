package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func main() {
	// Register handlers
	http.HandleFunc("/", homeHandler)              // Basic site root
	http.HandleFunc("/test-get", testGetHandler)   // GET endpoint
	http.HandleFunc("/test-post", testPostHandler) // POST endpoint

	// Start HTTPS server on port 443 with your cert and key
	log.Println("Starting HTTPS server on :443")
	if err := http.ListenAndServeTLS(":443", "/path/to/fullchain.pem", "/path/to/privkey.pem", nil); err != nil {
		log.Fatal(err)
	}
}
