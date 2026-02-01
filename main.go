package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

// Хранилище для токена
var accessToken string

func main() {
	// Загружаем .env
	err := godotenv.Load()
	if err != nil {
		log.Println("Не удалось загрузить .env, используем дефолтные")
	}

	// Получаем app_id и scope
	appID := os.Getenv("VK_APP_ID")
	if appID == "" {
		log.Fatal("VK_APP_ID не задан в .env")
	}
	scope := os.Getenv("VK_SCOPE") // e.g., "friends,photos"

	// Эндпоинт для получения токена от клиента
	http.HandleFunc("/receive-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			Token string `json:"token"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, "Неверный формат JSON", http.StatusBadRequest)
			return
		}

		// Сохраняем токен
		accessToken = data.Token

		// Выводим токен в консоль сервера
		fmt.Println("Полученный токен:", accessToken)

		// Отправляем успешный ответ
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})
	})

	// Главная страница с улучшенным дизайном и JS для VK Bridge
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
		<!DOCTYPE html>
		<html lang="ru">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>VK Mini App</title>
			<style>
				body {
					font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
					background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
					margin: 0;
					padding: 0;
					display: flex;
					justify-content: center;
					align-items: center;
					min-height: 100vh;
					color: #333;
				}
				.container {
					background: white;
					border-radius: 16px;
					box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
					padding: 40px;
					text-align: center;
					max-width: 400px;
					width: 90%;
				}
				h1 {
					font-size: 28px;
					margin-bottom: 30px;
					color: #4c75a3;
				}
				button {
					background: #4c75a3;
					color: white;
					border: none;
					border-radius: 8px;
					padding: 15px 30px;
					font-size: 18px;
					cursor: pointer;
					transition: background 0.3s ease, transform 0.2s ease;
					box-shadow: 0 4px 10px rgba(76, 117, 163, 0.3);
				}
				button:hover {
					background: #3a5f8a;
					transform: translateY(-2px);
				}
				button:disabled {
					background: #ccc;
					cursor: not-allowed;
					box-shadow: none;
				}
				#token {
					margin-top: 30px;
					padding: 15px;
					background: #e8f5e9;
					border-radius: 8px;
					color: #2e7d32;
					font-family: monospace;
					word-break: break-all;
					box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
				}
				#error {
					margin-top: 20px;
					color: #d32f2f;
					font-size: 14px;
				}
			</style>
			<script src="https://unpkg.com/@vkontakte/vk-bridge/dist/browser.min.js"></script>
			<script>
				let isInitialized = false;

				// Инициализация VK Bridge
				vkBridge.send('VKWebAppInit')
					.then(data => {
						console.log('VK Bridge initialized:', data);
						isInitialized = true;
						document.getElementById('authButton').disabled = false;
					})
					.catch(error => {
						console.error('Init error:', error);
						document.getElementById('error').innerText = 'Это Mini App работает только внутри VK! Откройте через VK.';
						document.getElementById('authButton').disabled = true;
					});

				// Функция авторизации
				function authorize() {
					if (!isInitialized) {
						alert('VK Bridge не инициализирован. Откройте в VK.');
						return;
					}
					vkBridge.send('VKWebAppGetAuthToken', {
						app_id: ` + appID + `,
						scope: '` + scope + `'
					})
					.then(data => {
						if (data.access_token) {
							// Отправляем токен на сервер
							sendTokenToServer(data.access_token);
						}
					})
					.catch(error => {
						console.error('Auth error:', error);
						alert('Ошибка авторизации: ' + JSON.stringify(error));
					});
				}

				// Функция отправки токена на сервер
				function sendTokenToServer(token) {
					fetch('/receive-token', {
						method: 'POST',
						headers: {
							'Content-Type': 'application/json',
						},
						body: JSON.stringify({ token: token })
					})
					.then(response => response.json())
					.then(data => {
						if (data.success) {
							// Показываем сообщение о передаче токена
							document.getElementById('token').innerText = 'токен передан';
						} else {
							document.getElementById('error').innerText = 'Ошибка при передаче токена';
						}
					})
					.catch(error => {
						console.error('Ошибка при отправке токена:', error);
						document.getElementById('error').innerText = 'Ошибка при передаче токена';
					});
				}
			</script>
		</head>
		<body>
			<div class="container">
				<h1>VK Mini App</h1>
				<button id="authButton" onclick="authorize()" disabled>Авторизоваться в VK</button>
				<div id="token"></div>
				<div id="error"></div>
			</div>
		</body>
		</html>
		`
		fmt.Fprint(w, html)
	})

	// Пути к сертификатам (адаптировано под testiq/ssl)
	certFile := "/etc/ssl/rassilkiin/fullchain.pem"
	keyFile := "/etc/ssl/rassilkiin/privkey.pem"

	// Запуск на HTTPS :443
	log.Println("Сервер запущен на HTTPS :443")
	log.Fatal(http.ListenAndServeTLS(":443", certFile, keyFile, nil))
}
