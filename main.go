package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

var (
	store        sync.Map
	clientID     string
	clientSecret string
	redirectURI  string
	certFile     string
	keyFile      string
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	clientID = os.Getenv("VK_CLIENT_ID")
	clientSecret = os.Getenv("VK_CLIENT_SECRET")
	redirectURI = os.Getenv("VK_REDIRECT_URI")
	certFile = os.Getenv("SSL_CERT_FILE")
	keyFile = os.Getenv("SSL_KEY_FILE")

	fmt.Println(certFile)
	fmt.Println(keyFile)

	if clientID == "" || clientSecret == "" || redirectURI == "" || certFile == "" || keyFile == "" {
		log.Fatal("Missing required environment variables")
	}

	http.HandleFunc("/", servePage)
	http.HandleFunc("/auth", handleAuth)
	log.Println("Starting server on :443")
	err = http.ListenAndServeTLS(":443", certFile, keyFile, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func servePage(w http.ResponseWriter, r *http.Request) {
	// Generate code_verifier
	verifier, err := generateVerifier()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Compute code_challenge
	challenge := computeChallenge(verifier)

	// Generate state
	state, err := generateState()
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Store verifier with state
	store.Store(state, verifier)

	// HTML with embedded state and challenge
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>VK Auth</title>
</head>
<body>
    <div>
        <script nonce="csp_nonce" src="https://unpkg.com/@vkid/sdk@<3.0.0/dist-sdk/umd/index.js"></script>
        <script nonce="csp_nonce" type="text/javascript">
            if ('VKIDSDK' in window) {
                const VKID = window.VKIDSDK;

                VKID.Config.init({
                    app: %s,
                    redirectUrl: '%s',
                    responseMode: VKID.ConfigResponseMode.Callback,
                    source: VKID.ConfigSource.LOWCODE,
                    scope: '', // Fill in required scopes if needed
                    state: '%s',
                    codeChallenge: '%s'
                });

                const oneTap = new VKID.OneTap();

                oneTap.render({
                    container: document.currentScript.parentElement,
                    showAlternativeLogin: true
                })
                .on(VKID.WidgetEvents.ERROR, vkidOnError)
                .on(VKID.OneTapInternalEvents.LOGIN_SUCCESS, function (payload) {
                    fetch('/auth', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            code: payload.code,
                            device_id: payload.device_id,
                            state: '%s'
                        })
                    })
                    .then(response => response.json())
                    .then(data => {
                        console.log('Success:', data);
                    })
                    .catch(error => {
                        console.error('Error:', error);
                    });
                });
              
                function vkidOnError(error) {
                    console.error('VKID Error:', error);
                }
            }
        </script>
    </div>
</body>
</html>
`, clientID, redirectURI, state, challenge, state)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var data struct {
		Code     string `json:"code"`
		DeviceID string `json:"device_id"`
		State    string `json:"state"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	verifAny, ok := store.LoadAndDelete(data.State)
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	verifier := verifAny.(string)

	// Exchange code for token
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", data.Code)
	form.Add("device_id", data.DeviceID)
	form.Add("client_id", clientID)
	form.Add("client_secret", clientSecret)
	form.Add("redirect_uri", redirectURI)
	form.Add("code_verifier", verifier)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://id.vk.com/oauth2/auth", strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		// Add other fields if needed
	}
	err = json.Unmarshal(respBody, &tokenResp)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	if tokenResp.AccessToken != "" {
		log.Printf("Access Token: %s\n", tokenResp.AccessToken)
	} else {
		log.Println("Failed to get access token")
	}

	jsonResp, err := json.Marshal(map[string]string{"status": "success"})
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResp)
}

func generateVerifier() (string, error) {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func computeChallenge(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func generateState() (string, error) {
	buf := make([]byte, 16)
	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
