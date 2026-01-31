package main

import (
	"fmt"
	"log"
	"os"
	"vk-auth-example/handlers"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using environment variables")
	}

	fmt.Println(os.Getenv("VK_CLIENT_ID"))
	fmt.Println(os.Getenv("VK_CLIENT_SECRET"))

	// Инициализация Gin
	r := gin.Default()

	// Настройка сессий
	store := cookie.NewStore([]byte("secret-key"))
	r.Use(sessions.Sessions("vk-session", store))

	// Загрузка статических файлов
	r.Static("/static", "./static")
	r.LoadHTMLGlob("templates/*")

	// Маршруты
	r.GET("/", handlers.HomeHandler)
	r.GET("/login/vk", handlers.VKLoginHandler)
	r.GET("/auth/vk/callback", handlers.VKCallbackHandler)
	r.GET("/profile", handlers.ProfileHandler)
	r.GET("/logout", handlers.LogoutHandler)

	// Порт из переменной окружения или 80 по умолчанию
	port := os.Getenv("PORT")
	if port == "" {
		port = "80" // стандартный HTTP порт
	}

	// Запуск сервера
	log.Printf("Сервер запущен на http://localhost")
	r.Run(":" + port)
}
