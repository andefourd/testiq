package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/vk"

	"github.com/SevereCloud/vksdk/v3/api"
)

const (
	clientID     = "54387179"                      // Замените на ваш client_id из VK
	clientSecret = "hturDjuQzeaN3nhD8myg"          // Замените на ваш client_secret
	redirectURL  = "http://77.223.97.218/callback" // Ваш callback URI
)

var oauthConf = &oauth2.Config{
	ClientID:     clientID,
	ClientSecret: clientSecret,
	RedirectURL:  redirectURL,
	Endpoint:     vk.Endpoint,                             // Встроенные эндпоинты VK: https://oauth.vk.com/authorize и https://oauth.vk.com/access_token
	Scopes:       []string{"vkid.personal_info", "email"}, // Исправленные scopes для VK ID: базовая информация + email
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/callback", callbackHandler)

	log.Println("Сервер запущен на http://77.223.97.218:80") // Порт по умолчанию 80 для HTTP
	log.Fatal(http.ListenAndServe(":80", nil))
}

// Главная страница с кнопкой "Войти через VK"
func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `<html><body><a href="/login">Войти через VK ID</a></body></html>`)
}

// Генерация URL для авторизации и редирект
func loginHandler(w http.ResponseWriter, r *http.Request) {
	state := "random-state-string" // Для защиты от CSRF, сгенерируйте случайно и проверьте в callback
	url := oauthConf.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Обработка callback от VK
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code не получен", http.StatusBadRequest)
		return
	}

	// Обмен code на token
	token, err := oauthConf.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка обмена token: %v", err), http.StatusInternalServerError)
		return
	}

	// Доступ к email (если scope=email): VK возвращает его в token.Extra
	email := token.Extra("email")
	userID := token.Extra("user_id")

	// Создаем VK API клиент с token (используем vksdk для удобства)
	vkClient := api.NewVK(token.AccessToken)

	// Получаем данные пользователя (метод users.get)
	params := api.Params{
		"fields": "photo_200,first_name,last_name", // Поля: фото, имя, фамилия (из vkid.personal_info)
		"v":      "5.199",                          // Версия API для совместимости
	}
	users, err := vkClient.UsersGet(params)
	if err != nil {
		http.Error(w, fmt.Sprintf("Ошибка получения user info: %v", err), http.StatusInternalServerError)
		return
	}

	// Выводим данные (в реальности сохраните в сессии или БД)
	userData, _ := json.Marshal(users)
	fmt.Fprintf(w, "Успешная авторизация! Данные пользователя: %s\nEmail: %v\nUser ID: %v\nAccess Token: %s", userData, email, userID, token.AccessToken)
}
