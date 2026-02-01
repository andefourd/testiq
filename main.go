package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

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

	// Главная страница с JS для VK Bridge
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		html := `
		<!DOCTYPE html>
		<html lang="ru">
		<head>
			<meta charset="UTF-8">
			<title>VK Mini App</title>
			<style>
				body { font-family: sans-serif; text-align: center; margin-top: 100px; }
				button { padding: 10px 20px; background: #4c75a3; color: white; border: none; cursor: pointer; }
				#token { margin-top: 20px; color: green; }
			</style>
			<script src="https://unpkg.com/@vkontakte/vk-bridge/dist/browser.min.js"></script>
			<script>
				// Инициализация VK Bridge
				vkBridge.send('VKWebAppInit')
					.then(data => console.log('VK Bridge initialized:', data))
					.catch(error => {
						console.error('Init error:', error);
						alert('Это Mini App работает только внутри VK! Откройте через VK для тестирования.');
					});

				// Функция авторизации
				function authorize() {
					vkBridge.send('VKWebAppGetAuthToken', {
						app_id: ` + appID + `,
						scope: '` + scope + `'
					})
					.then(data => {
						if (data.access_token) {
							document.getElementById('token').innerText = 'Access Token: ' + data.access_token;
							console.log('Scope:', data.scope);
						}
					})
					.catch(error => {
						console.error('Auth error:', error);
						alert('Ошибка авторизации: ' + JSON.stringify(error));
					});
				}
			</script>
		</head>
		<body>
			<h1>VK Mini App</h1>
			<button onclick="authorize()">Авторизоваться в VK</button>
			<div id="token"></div>
		</body>
		</html>
		`
		fmt.Fprint(w, html)
	})

	certFile := "/etc/ssl/rassilkiin/fullchain.pem"
	keyFile := "/etc/ssl/rassilkiin/privkey.pem"

	// Запуск на HTTPS :443
	log.Println("Сервер запущен на HTTPS :443")
	log.Fatal(http.ListenAndServeTLS(":443", certFile, keyFile, nil))
}
