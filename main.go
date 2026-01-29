package main

import (
	"fmt"
	"net/http"
	"time"
)

var clickCounter int = 0

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

// Обработчик для отслеживания кликов
func clickHandler(w http.ResponseWriter, r *http.Request) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	clientIP := r.RemoteAddr

	// Получаем информацию о клиенте
	userAgent := r.UserAgent()
	referer := r.Referer()
	method := r.Method

	// Увеличиваем счетчик
	clickCounter++

	// Логируем информацию о клике
	fmt.Printf("========================================\n")
	fmt.Printf("[%s] КЛИК ЗАФИКСИРОВАН!\n", timestamp)
	fmt.Printf("Клиент: %s\n", clientIP)
	fmt.Printf("User-Agent: %s\n", userAgent)
	fmt.Printf("Метод запроса: %s\n", method)
	fmt.Printf("Реферер: %s\n", referer)
	fmt.Printf("Общее количество кликов: %d\n", clickCounter)
	fmt.Printf("========================================\n")

	// Отправляем JSON ответ с текущим счетчиком
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "ok", "count": %d, "timestamp": "%s"}`, clickCounter, timestamp)
}

// Обработчик для сброса счетчика
func resetHandler(w http.ResponseWriter, r *http.Request) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	clientIP := r.RemoteAddr

	oldCount := clickCounter
	clickCounter = 0

	// Логируем сброс
	fmt.Printf("========================================\n")
	fmt.Printf("[%s] СБРОС СЧЕТЧИКА!\n", timestamp)
	fmt.Printf("Клиент: %s\n", clientIP)
	fmt.Printf("Старое значение: %d\n", oldCount)
	fmt.Printf("Новое значение: %d\n", clickCounter)
	fmt.Printf("========================================\n")

	// Отправляем JSON ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status": "reset", "old_count": %d, "new_count": %d, "timestamp": "%s"}`, oldCount, clickCounter, timestamp)
}

func main() {
	// Регистрируем хендлеры
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/click", clickHandler)
	http.HandleFunc("/reset", resetHandler)

	// Указываем, что файлы в папке "static" нужно отдавать как статический сайт
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	port := ":80" // Go будет работать прямо на стандартном порту сайта
	fmt.Printf("Сервер запущен на http://localhost%s\n", port)
	fmt.Printf("Эндпоинты:\n")
	fmt.Printf("  GET  http://localhost/ping  - проверка работы сервера\n")
	fmt.Printf("  POST http://localhost/click - зафиксировать клик\n")
	fmt.Printf("  POST http://localhost/reset - сбросить счетчик\n")
	fmt.Println("\nЖдем клики...")

	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Println("Ошибка запуска:", err)
	}
}
