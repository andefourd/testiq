package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// Конфигурация VK OAuth
var vkOAuthConfig = &oauth2.Config{
	ClientID:     os.Getenv("VK_CLIENT_ID"),     // Замените на ваш Client ID
	ClientSecret: os.Getenv("VK_CLIENT_SECRET"), // Замените на ваш Client Secret
	RedirectURL:  "http://localhost:8080/auth/vk/callback",
	Scopes:       []string{"email", "friends", "photos", "status"},
	Endpoint: oauth2.Endpoint{
		AuthURL:  "https://oauth.vk.com/authorize",
		TokenURL: "https://oauth.vk.com/access_token",
	},
}

// Структуры для парсинга ответов VK
type VKUserResponse struct {
	Response []VKUser `json:"response"`
}

type VKUser struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Photo     string `json:"photo_200"`
	Email     string `json:"email"`
}

type VKTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	UserID      int    `json:"user_id"`
	Email       string `json:"email"`
}

// VKLoginHandler - перенаправление на страницу авторизации VK
func VKLoginHandler(c *gin.Context) {
	// Генерируем URL для авторизации с дополнительными параметрами VK
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&v=5.199&state=random_state",
		vkOAuthConfig.Endpoint.AuthURL,
		vkOAuthConfig.ClientID,
		url.QueryEscape(vkOAuthConfig.RedirectURL),
		"email,friends,photos,status",
	)

	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// VKCallbackHandler - обработка callback от VK
func VKCallbackHandler(c *gin.Context) {
	// Получаем код авторизации
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Код авторизации не получен"})
		return
	}

	// Получаем токен доступа
	token, err := exchangeCodeForToken(code)
	if err != nil {
		log.Printf("Ошибка получения токена: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить токен"})
		return
	}

	// Получаем информацию о пользователе
	user, err := getUserInfo(token.AccessToken, token.UserID)
	if err != nil {
		log.Printf("Ошибка получения данных пользователя: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить данные пользователя"})
		return
	}

	// Сохраняем данные в сессии
	session := sessions.Default(c)
	session.Set("user_id", user.ID)
	session.Set("first_name", user.FirstName)
	session.Set("last_name", user.LastName)
	session.Set("photo", user.Photo)
	session.Set("email", token.Email)
	session.Set("access_token", token.AccessToken)
	session.Save()

	// Перенаправляем на профиль
	c.Redirect(http.StatusFound, "/profile")
}

// exchangeCodeForToken - обмен кода авторизации на токен доступа
func exchangeCodeForToken(code string) (*VKTokenResponse, error) {
	// Формируем URL для получения токена
	params := url.Values{}
	params.Add("client_id", vkOAuthConfig.ClientID)
	params.Add("client_secret", vkOAuthConfig.ClientSecret)
	params.Add("redirect_uri", vkOAuthConfig.RedirectURL)
	params.Add("code", code)

	tokenURL := fmt.Sprintf("%s?%s", vkOAuthConfig.Endpoint.TokenURL, params.Encode())

	// Выполняем запрос
	resp, err := http.Get(tokenURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Парсим ответ
	var tokenResp VKTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// getUserInfo - получение информации о пользователе VK
func getUserInfo(accessToken string, userID int) (*VKUser, error) {
	// Формируем запрос к API VK
	apiURL := fmt.Sprintf("https://api.vk.com/method/users.get?user_ids=%d&fields=photo_200,email&access_token=%s&v=5.199",
		userID, accessToken)

	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Парсим ответ
	var userResp VKUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, err
	}

	if len(userResp.Response) == 0 {
		return nil, fmt.Errorf("пользователь не найден")
	}

	return &userResp.Response[0], nil
}

// ProfileHandler - отображение профиля пользователя
func ProfileHandler(c *gin.Context) {
	session := sessions.Default(c)
	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(http.StatusFound, "/")
		return
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"FirstName": session.Get("first_name"),
		"LastName":  session.Get("last_name"),
		"Photo":     session.Get("photo"),
		"Email":     session.Get("email"),
		"UserID":    userID,
	})
}

// LogoutHandler - выход из системы
func LogoutHandler(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, "/")
}
