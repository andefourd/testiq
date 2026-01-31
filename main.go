package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Определяем константы для путей к сертификатам и ключу
const (
	certFile  = "/etc/ssl/rassilkiin.ru/fullchain.pem"
	keyFile   = "/etc/ssl/rassilkiin.ru/private.key"
	staticDir = "./static"   // Папка для статических файлов
	indexFile = "index.html" // Имя файла главной страницы
)

// Глобальный счетчик (используем atomic для потокобезопасности)
var globalCounter atomic.Int64

func main() {
	// Инициализация счетчика
	globalCounter.Store(0)

	// --- Проверка наличия файлов сертификатов ---
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("Ошибка: файл сертификата не найден по пути %s", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("Ошибка: файл приватного ключа не найден по пути %s", keyFile)
	}
	// --- Проверка наличия папки static и index.html ---
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		log.Fatalf("Ошибка: папка статических файлов '%s' не найдена. Создайте её.", staticDir)
	}
	if _, err := os.Stat(filepath.Join(staticDir, indexFile)); os.IsNotExist(err) {
		log.Fatalf("Ошибка: файл '%s' не найден в папке '%s'. Создайте его.", indexFile, staticDir)
	}

	// Создаем мультиплексор (роутер) для обработки HTTP-запросов
	mux := http.NewServeMux()

	// --- Добавляем новые хендлеры ---

	// Хендлер для проверки работоспособности сервера
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[PING] %s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]string{
			"status":  "ok",
			"message": "pong",
			"time":    time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	// Хендлер для увеличения счетчика
	mux.HandleFunc("/increase", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[INCREASE] %s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)

		// Увеличиваем счетчик
		newValue := globalCounter.Add(1)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":      "success",
			"new_value":   newValue,
			"message":     "Счетчик увеличен",
			"incremented": true,
			"timestamp":   time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	// Хендлер для получения текущего значения счетчика
	mux.HandleFunc("/counter", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[COUNTER] %s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)

		currentValue := globalCounter.Load()

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":    "success",
			"value":     currentValue,
			"timestamp": time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	// Хендлер для сброса счетчика
	mux.HandleFunc("/counter/reset", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[COUNTER RESET] %s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)

		oldValue := globalCounter.Swap(0)

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"status":    "success",
			"old_value": oldValue,
			"new_value": 0,
			"message":   "Счетчик сброшен",
			"timestamp": time.Now().Format(time.RFC3339),
		}
		json.NewEncoder(w).Encode(response)
	})

	// Обработчик для всех остальных запросов (статические файлы)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Логируем каждый входящий запрос
		log.Printf("[%s] %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)

		// Формируем полный путь к файлу в папке static
		requestedPath := filepath.Join(staticDir, filepath.Clean(r.URL.Path))

		// Проверяем, существует ли запрошенный файл и не является ли он директорией
		if stat, err := os.Stat(requestedPath); err == nil && !stat.IsDir() {
			// Если файл существует, отдаем его
			http.ServeFile(w, r, requestedPath)
			return
		}

		// Если запрошенный путь является корневым ("/") или файл не найден,
		// отдаем index.html
		http.ServeFile(w, r, filepath.Join(staticDir, indexFile))
	})

	// --- Настройка HTTPS сервера ---
	httpsSrv := &http.Server{
		Addr:         ":443", // Слушаем порт 443 для HTTPS
		Handler:      mux,    // Используем наш мультиплексор
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{ // Настройки TLS для безопасности
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		},
	}

	// Запускаем HTTPS сервер в отдельной горутине
	go func() {
		log.Println("Запуск HTTPS сервера на https://rassilkiin.ru (порт 443)")
		if err := httpsSrv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска HTTPS сервера: %v", err)
		}
	}()

	// --- Настройка HTTP сервера для редиректа ---
	httpSrv := &http.Server{
		Addr: ":80", // Слушаем порт 80 для HTTP
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Логируем запросы, приходящие на HTTP
			log.Printf("[HTTP Redirect] %s %s %s %s -> HTTPS", r.RemoteAddr, r.Method, r.URL.Path, r.Proto)
			// Перенаправляем на HTTPS
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		}),
	}

	// Запускаем HTTP сервер в отдельной горутине
	go func() {
		log.Println("Запуск HTTP сервера для редиректа на HTTPS (порт 80)")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Ошибка запуска HTTP сервера: %v", err)
		}
	}()

	// --- Обработка сигналов для аккуратного завершения работы ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, os.Kill) // Отлавливаем Ctrl+C и сигнал завершения
	<-quit                                     // Ожидаем сигнал
	log.Println("Получен сигнал завершения. Начинаю остановку серверов...")

	// Создаем контекст с таймаутом для остановки HTTPS сервера
	ctxHttps, cancelHttps := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelHttps()
	if err := httpsSrv.Shutdown(ctxHttps); err != nil {
		log.Fatalf("Ошибка при остановке HTTPS сервера: %v", err)
	}

	// Создаем контекст с таймаутом для остановки HTTP сервера
	ctxHttp, cancelHttp := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelHttp()
	if err := httpSrv.Shutdown(ctxHttp); err != nil {
		log.Fatalf("Ошибка при остановке HTTP сервера: %v", err)
	}

	log.Println("Все серверы остановлены. Приложение завершило работу.")
}
