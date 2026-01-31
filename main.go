package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ЗАХАРДКОДЕННЫЕ ДАННЫЕ
const (
	VK_CLIENT_ID     = "54437079"
	VK_CLIENT_SECRET = "c3175a46c3175a46c3175a46d7c029fe91cc317c3175a46aa6bead05b0a4731cb5de7f6"
	VK_REDIRECT_URI  = "https://rassilkiin.ru/auth/vk/callback"
	SESSION_SECRET   = "32_char_secret_key_for_aes_256!!"
)

// Структуры для VK API
type VKTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	UserID      int    `json:"user_id"`
	Email       string `json:"email"`
}

type VKUserResponse struct {
	Response []VKUser `json:"response"`
}

type VKUser struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Photo200  string `json:"photo_200"`
	Photo100  string `json:"photo_100"`
}

// Данные сессии
type SessionData struct {
	UserID    int    `json:"user_id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Photo     string `json:"photo"`
	Email     string `json:"email"`
	Token     string `json:"token"`
}

// Шифрование/дешифрование сессии
func encryptSession(data SessionData) (string, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(SESSION_SECRET))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptSession(encrypted string) (*SessionData, error) {
	ciphertext, err := base64.URLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(SESSION_SECRET))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("слишком короткий шифртекст")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var data SessionData
	err = json.Unmarshal(plaintext, &data)
	return &data, err
}

// Получение токена VK
func getVKToken(code string) (*VKTokenResponse, error) {
	params := url.Values{}
	params.Add("client_id", VK_CLIENT_ID)
	params.Add("client_secret", VK_CLIENT_SECRET)
	params.Add("redirect_uri", VK_REDIRECT_URI)
	params.Add("code", code)

	url := fmt.Sprintf("https://oauth.vk.com/access_token?%s", params.Encode())

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var tokenResp VKTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// Получение данных пользователя VK
func getVKUserInfo(accessToken string, userID int) (*VKUser, error) {
	url := fmt.Sprintf(
		"https://api.vk.com/method/users.get?user_ids=%d&fields=photo_200,photo_100&access_token=%s&v=5.199",
		userID, accessToken,
	)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userResp VKUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, err
	}

	if len(userResp.Response) == 0 {
		return nil, fmt.Errorf("пользователь не найден")
	}

	return &userResp.Response[0], nil
}

// Обработчики
func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Проверяем сессию
	if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
		if _, err := decryptSession(cookie.Value); err == nil {
			// Пользователь авторизован, перенаправляем на профиль
			http.Redirect(w, r, "/profile", http.StatusFound)
			return
		}
	}

	// Рендерим главную страницу
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, nil)
}

func vkLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Параметры для запроса авторизации
	params := url.Values{}
	params.Add("client_id", VK_CLIENT_ID)
	params.Add("display", "page")
	params.Add("redirect_uri", VK_REDIRECT_URI)
	params.Add("scope", "email,photos,friends,status")
	params.Add("response_type", "code")
	params.Add("v", "5.199")

	authURL := fmt.Sprintf("https://oauth.vk.com/authorize?%s", params.Encode())
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func vkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Код авторизации не получен", http.StatusBadRequest)
		return
	}

	// Получаем токен
	token, err := getVKToken(code)
	if err != nil {
		log.Printf("Ошибка получения токена: %v", err)
		http.Error(w, "Ошибка получения токена", http.StatusInternalServerError)
		return
	}

	// Получаем данные пользователя
	user, err := getVKUserInfo(token.AccessToken, token.UserID)
	if err != nil {
		log.Printf("Ошибка получения данных пользователя: %v", err)
		http.Error(w, "Ошибка получения данных пользователя", http.StatusInternalServerError)
		return
	}

	// Создаем сессию
	sessionData := SessionData{
		UserID:    user.ID,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Photo:     user.Photo200,
		Email:     token.Email,
		Token:     token.AccessToken,
	}

	// Шифруем сессию
	encryptedSession, err := encryptSession(sessionData)
	if err != nil {
		log.Printf("Ошибка шифрования сессии: %v", err)
		http.Error(w, "Ошибка создания сессии", http.StatusInternalServerError)
		return
	}

	// Устанавливаем куку
	cookie := &http.Cookie{
		Name:     "session",
		Value:    encryptedSession,
		Path:     "/",
		MaxAge:   86400 * 7, // 7 дней
		HttpOnly: true,
		Secure:   true, // Только HTTPS
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	http.Redirect(w, r, "/profile", http.StatusFound)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем сессию
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sessionData, err := decryptSession(cookie.Value)
	if err != nil {
		// Невалидная сессия, удаляем куку
		http.SetCookie(w, &http.Cookie{
			Name:   "session",
			Value:  "",
			MaxAge: -1,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Рендерим профиль
	tmpl, err := template.ParseFiles("templates/profile.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, sessionData)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаляем сессионную куку
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func staticHandler(w http.ResponseWriter, r *http.Request) {
	// Обслуживаем статические файлы
	path := strings.TrimPrefix(r.URL.Path, "/static/")

	// Проверяем расширение файла для безопасности
	if !strings.HasSuffix(path, ".css") {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	http.ServeFile(w, r, "static/"+path)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	log.Println("=== НАСТРОЙКИ ПРИЛОЖЕНИЯ ===")
	log.Printf("VK Client ID: %s", VK_CLIENT_ID)
	log.Printf("Redirect URI: %s", VK_REDIRECT_URI)
	log.Printf("Запуск на порту: 443 (HTTPS)")

	// ПУТИ К ВАШИМ SSL СЕРТИФИКАТАМ - ИСПРАВЛЕННЫЕ
	certFile := "/etc/ssl/rassilkiin.ru/fullchain.pem" // Полная цепочка сертификатов
	keyFile := "/etc/ssl/rassilkiin.ru/private.key"    // Приватный ключ

	// Проверяем существование файлов
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("SSL сертификат не найден: %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("SSL ключ не найден: %s", keyFile)
	}

	log.Printf("Используем SSL сертификат: %s", certFile)
	log.Printf("Используем SSL ключ: %s", keyFile)

	// Настройка маршрутов
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login/vk", vkLoginHandler)
	http.HandleFunc("/auth/vk/callback", vkCallbackHandler)
	http.HandleFunc("/profile", profileHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/static/", staticHandler)
	http.HandleFunc("/health", healthHandler)

	// Настройки TLS
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	// Настройки сервера
	server := &http.Server{
		Addr:         ":443",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
		TLSConfig:    tlsConfig,
	}

	log.Println("Сервер запускается...")
	log.Println("Откройте в браузере: https://rassilkiin.ru")
	log.Println("Ожидание подключений на порту 443...")

	// Запускаем HTTPS сервер
	if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
