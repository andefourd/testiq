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
	"sync"
	"time"

	"github.com/SevereCloud/vksdk/v3/api"
)

const (
	clientID     = "54437079"                                                                // Ваш app ID
	clientSecret = "c3175a46c3175a46c3175a46d7c029fe91cc317c3175a46aa6bead05b0a4731cb5de7f6" // Замените на client_secret
	redirectURL  = "https://oauth.vk.com/blank.html"
	apiVersion   = "5.199"
	port         = ":80" // Порт для localhost
)

var (
	pkceStore = struct {
		sync.Mutex
		m map[string]string // state -> code_verifier
	}{m: make(map[string]string)}
)

// Генерация random строки для verifier
func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Вычисление challenge = base64url(SHA256(verifier))
func computeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// Endpoint для инициализации PKCE
func initPkceHandler(w http.ResponseWriter, r *http.Request) {
	verifier, err := generateVerifier()
	if err != nil {
		http.Error(w, "Ошибка генерации verifier", http.StatusInternalServerError)
		return
	}
	state := "state_" + time.Now().Format("20060102150405") // Простой state
	challenge := computeChallenge(verifier)

	pkceStore.Lock()
	pkceStore.m[state] = verifier
	pkceStore.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"state":          state,
		"code_challenge": challenge,
	})
}

// Endpoint для обмена code на token
func exchangeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Только POST", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Ошибка body", http.StatusBadRequest)
		return
	}

	var data struct {
		Code     string `json:"code"`
		DeviceID string `json:"device_id"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		http.Error(w, "Ошибка JSON", http.StatusBadRequest)
		return
	}

	pkceStore.Lock()
	verifier, ok := pkceStore.m[data.State]
	delete(pkceStore.m, data.State) // Удаляем после использования
	pkceStore.Unlock()
	if !ok {
		http.Error(w, "Неверный state", http.StatusBadRequest)
		return
	}

	// Формируем запрос на exchange
	url := "https://oauth.vk.com/access_token"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		http.Error(w, "Ошибка запроса", http.StatusInternalServerError)
		return
	}

	q := req.URL.Query()
	q.Add("client_id", clientID)
	q.Add("client_secret", clientSecret)
	q.Add("redirect_uri", redirectURL)
	q.Add("code", data.Code)
	q.Add("device_id", data.DeviceID)
	q.Add("code_verifier", verifier)
	q.Add("v", apiVersion)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка exchange: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	bodyResp, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Ошибка чтения response", http.StatusInternalServerError)
		return
	}

	var tokenResp map[string]interface{}
	if err := json.Unmarshal(bodyResp, &tokenResp); err != nil {
		http.Error(w, "Ошибка парсинга token", http.StatusInternalServerError)
		return
	}

	if errMsg, ok := tokenResp["error"].(string); ok {
		http.Error(w, fmt.Sprintf("Ошибка VK: %s - %s", errMsg, tokenResp["error_description"]), http.StatusBadRequest)
		return
	}

	accessToken := tokenResp["access_token"].(string)

	// Получаем данные пользователя
	vkClient := api.NewVK(accessToken)
	params := api.Params{
		"fields": "photo_200,first_name,last_name,sex,bdate,city",
		"v":      apiVersion,
	}
	users, err := vkClient.UsersGet(params)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Возвращаем данные клиенту
	response := map[string]interface{}{
		"access_token": accessToken,
		"user_data":    users,
		"email":        tokenResp["email"],
		"user_id":      tokenResp["user_id"],
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/init-pkce", initPkceHandler)
	http.HandleFunc("/exchange", exchangeHandler)
	http.HandleFunc("/", homeHandler) // Главная страница с кнопкой

	log.Printf("Сервер запущен на http://localhost:80")
	log.Fatal(http.ListenAndServe(port, nil))
}

// Главная страница с кнопкой VK ID OneTap
func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
        <!DOCTYPE html>
        <html>
        <head>
            <title>VK ID Auth on Localhost</title>
        </head>
        <body>
            <h1>Войти через VK ID</h1>
            <div id="vkid-button-container"></div>
            <script nonce="csp_nonce" src="https://unpkg.com/@vkid/sdk@2.4.1/dist-sdk/umd/index.js"></script>
            <script nonce="csp_nonce" type="text/javascript">
                if ('VKIDSDK' in window) {
                    const VKID = window.VKIDSDK;
                    console.log('VKID SDK loaded'); // Debug
                    fetch('http://localhost:80/init-pkce')
                        .then(response => response.json())
                        .then(data => {
                            console.log('PKCE data:', data); // Debug
                            VKID.Config.init({
                                app: 54437079,
                                redirectUrl: 'https://oauth.vk.com/blank.html',
                                responseMode: VKID.ConfigResponseMode.Callback,
                                source: VKID.ConfigSource.LOWCODE,
                                scope: 'vkid.personal_info,email',
                                state: data.state,
                                codeChallenge: data.code_challenge,
                                codeChallengeMethod: 'S256'
                            });
                            console.log('Config initialized'); // Debug
                            const oneTap = new VKID.OneTap();
                            oneTap.render({
                                container: document.getElementById('vkid-button-container'),
                                showAlternativeLogin: true
                            })
                            .on(VKID.WidgetEvents.ERROR, vkidOnError)
                            .on(VKID.OneTapInternalEvents.LOGIN_SUCCESS, function (payload) {
                                console.log('Login success payload:', payload); // Debug
                                const code = payload.code;
                                const deviceId = payload.device_id;
                                fetch('http://localhost:80/exchange', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ code: code, device_id: deviceId, state: data.state })
                                })
                                .then(response => response.json())
                                .then(vkidOnSuccess)
                                .catch(vkidOnError);
                            });
                        })
                        .catch(vkidOnError);
                 
                    function vkidOnSuccess(data) {
                        console.log('Success:', data);
                    }
                 
                    function vkidOnError(error) {
                        console.error('Error:', error);
                    }
                } else {
                    console.error('VKIDSDK not in window');
                }
            </script>
        </body>
        </html>
    `)
}
