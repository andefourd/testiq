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
)

// Конфигурация VK OAuth
var (
	clientID     = os.Getenv("VK_CLIENT_ID")
	clientSecret = os.Getenv("VK_CLIENT_SECRET")
	redirectURL  = os.Getenv("VK_REDIRECT_URL")
)

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
	if clientID == "" || redirectURL == "" {
		log.Println("VK_CLIENT_ID или VK_REDIRECT_URL не установлены")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Конфигурация сервера неполна"})
		return
	}

	// Генерируем URL для авторизации с дополнительными параметрами VK
	authURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&response_type=code&v=5.199&state=random_state",
		"https://oauth.vk.com/authorize",
		clientID,
		url.QueryEscape(redirectURL),
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
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, fmt.Errorf("конфигурация VK неполна")
	}

	// Формируем URL для получения токена
	params := url.Values{}
	params.Add("client_id", clientID)
	params.Add("client_secret", clientSecret)
	params.Add("redirect_uri", redirectURL)
	params.Add("code", code)

	tokenURL := fmt.Sprintf("%s?%s", "https://oauth.vk.com/access_token", params.Encode())

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
