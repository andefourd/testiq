package main

import (
	"fmt"
	"net/http"
	"time"
)

// Обработчик для /ping
func pingHandler(w http.ResponseWriter, r *http.Request) {
	// Логируем попытку
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	clientIP := r.RemoteAddr
	fmt.Printf("[%s] Получен ping от %s\n", timestamp, clientIP)

	// Отправляем ответ
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("pong"))
}

func main() {
	// Регистрируем хендлер для /ping перед статикой
	http.HandleFunc("/ping", pingHandler)

	// Указываем, что файлы в папке "static" нужно отдавать как статический сайт
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	port := ":80" // Go будет работать прямо на стандартном порту сайта
	fmt.Printf("Сервер запущен на http://localhost%s\n", port)
	fmt.Println("Для теста отправьте GET запрос на http://localhost/ping")

	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Println("Ошибка запуска:", err)
	}
}
