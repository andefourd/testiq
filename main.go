package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

const (
	staticDir = "./static"
	indexFile = "index.html"

	// Redirect URI должен совпадать с тем, что вы указали в настройках VK-приложения
	redirectPath = "/vk/callback"
)

var (
	vkClientID     = os.Getenv("VK_CLIENT_ID")
	vkClientSecret = os.Getenv("VK_CLIENT_SECRET")
	domainOrigin   = "" // заполним ниже из окружения или определим динамически
	stateStore     = NewStateStore()
)

// Простое хранилище временных состояний (state) для защиты от CSRF
type StateStore struct {
	m map[string]time.Time
	sync.Mutex
}

func NewStateStore() *StateStore {
	return &StateStore{m: make(map[string]time.Time)}
}

func (s *StateStore) Put(state string) {
	s.Lock()
	defer s.Unlock()
	s.m[state] = time.Now().Add(10 * time.Minute)
}

func (s *StateStore) Valid(state string) bool {
	s.Lock()
	defer s.Unlock()
	exp, ok := s.m[state]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, state)
		return false
	}
	delete(s.m, state) // одноразовый
	return true
}

func main() {
	godotenv.Load()

	vkClientID := os.Getenv("VK_CLIENT_ID")
	vkClientSecret := os.Getenv("VK_CLIENT_SECRET")
	domainOrigin := os.Getenv("SITE_ORIGIN")

	// Проверки
	if vkClientID == "" || vkClientSecret == "" {
		log.Fatal("Не задан VK_CLIENT_ID или VK_CLIENT_SECRET. Установите переменные окружения.")
	}

	mux := http.NewServeMux()

	// Статика (основная страница)
	mux.Handle("/", http.FileServer(http.Dir(staticDir)))

	// Запуск OAuth: /vk/start -> редирект на oauth.vk.com/authorize
	mux.HandleFunc("/vk/start", vkStartHandler)

	// Callback: VK перенаправит сюда с ?code=...&state=...
	mux.HandleFunc(redirectPath, vkCallbackHandler)

	// Простая health-страница
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:         ":443",
		Handler:      loggingMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Запуск HTTPS и HTTP редиректа (на случай, если вы хотите редиректить)
	go func() {
		log.Println("Запуск HTTPS на :443")
		cert := "/etc/ssl/rassilkiin.ru/fullchain.pem"
		key := "/etc/ssl/rassilkiin.ru/private.key"
		if err := server.ListenAndServeTLS(cert, key); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS error: %v", err)
		}
	}()

	// HTTP redirect -> HTTPS
	go func() {
		httpSrv := &http.Server{
			Addr: ":80",
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, domainOrigin+r.RequestURI, http.StatusMovedPermanently)
			}),
		}
		log.Println("Запуск HTTP на :80 (редирект на HTTPS)")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP redirect error: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	log.Println("Shutdown signal received. Stopping servers...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	log.Println("Server stopped")
}

// vkStartHandler генерирует state и редиректит пользователя на VK OAuth
func vkStartHandler(w http.ResponseWriter, r *http.Request) {
	state := randString(24)
	stateStore.Put(state)

	authURL := url.URL{
		Scheme: "https",
		Host:   "oauth.vk.com",
		Path:   "/authorize",
	}
	q := authURL.Query()
	q.Set("client_id", vkClientID)
	q.Set("display", "page")
	q.Set("redirect_uri", domainOrigin+redirectPath)
	q.Set("scope", "email") // укажите требуемые scope
	q.Set("response_type", "code")
	q.Set("v", "5.131")
	q.Set("state", state)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// vkCallbackHandler обменивает code на access_token и возвращает popup-страницу,
// которая отправляет токен обратно в opener (window.opener.postMessage)
func vkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Проверка ошибок/параметров
	errParam := r.URL.Query().Get("error")
	if errParam != "" {
		http.Error(w, "OAuth error: "+errParam, http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	log.Println("Code: ", code)
	state := r.URL.Query().Get("state")
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}
	if !stateStore.Valid(state) {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Обмен code на access_token
	tokenResp, err := exchangeCodeForToken(code)
	if err != nil {
		log.Printf("Error exchanging code: %v", err)
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Логируем токен в консоль (как вы просили)
	log.Printf("Получен VK access_token: %s (user_id=%d, email=%s)", tokenResp.AccessToken, tokenResp.UserID, tokenResp.Email)

	// Вернём HTML, который отправит токен в opener и закроет popup
	tmpl := template.Must(template.New("popup").Parse(popupHTML))
	data := struct {
		Origin      string
		AccessToken string
		UserID      int64
		Email       string
		ExpiresIn   int
	}{
		Origin:      domainOrigin, // безопаснее указывать точный origin
		AccessToken: tokenResp.AccessToken,
		UserID:      tokenResp.UserID,
		Email:       tokenResp.Email,
		ExpiresIn:   tokenResp.ExpiresIn,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tmpl.Execute(w, data)
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	UserID      int64  `json:"user_id"`
	Email       string `json:"email,omitempty"`
}

// exchangeCodeForToken вызывает VK token endpoint
func exchangeCodeForToken(code string) (*tokenResponse, error) {
	u := url.URL{
		Scheme: "https",
		Host:   "oauth.vk.com",
		Path:   "/access_token",
	}
	q := u.Query()
	q.Set("client_id", vkClientID)
	log.Println("vkClientID: ", vkClientID)
	q.Set("client_secret", vkClientSecret)
	q.Set("redirect_uri", domainOrigin+redirectPath)
	q.Set("code", code)

	log.Println(q)

	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// VK возвращает JSON с access_token или ошибкой
	if resp.StatusCode != http.StatusOK {
		var bodyBytes = make([]byte, 0)
		_ = json.NewDecoder(resp.Body).Decode(&bodyBytes)
		return nil, fmt.Errorf("vk token endpoint returned status %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// Простой логирующий middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range b {
		b[i] = letters[seed.Intn(len(letters))]
	}
	return string(b)
}

var popupHTML = `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>VK Auth</title>
</head>
<body>
  <script>
    // сообщение родительскому окну (opener)
    (function() {
      try {
        var payload = {
          access_token: "{{.AccessToken}}",
          user_id: {{.UserID}},
          email: "{{.Email}}",
          expires_in: {{.ExpiresIn}}
        };
        // отправляем только на наш origin
        var targetOrigin = "{{.Origin}}";
        if (window.opener && !window.opener.closed) {
          window.opener.postMessage(payload, targetOrigin);
        }
      } catch (e) {
        console.error(e);
      }
      // закрываем popup через короткую паузу
      setTimeout(function(){ window.close(); }, 300);
    })();
  </script>
  <p>Авторизация завершена. Можно закрыть окно.</p>
</body>
</html>`
