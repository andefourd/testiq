package main

import (
	"fmt"
	"net/http"
)

func main() {
	// Указываем, что файлы в папке "static" нужно отдавать как статический сайт
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	port := ":80" // Go будет работать прямо на стандартном порту сайта
	fmt.Printf("Сервер запущен на http://localhost%s\n", port)

	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Println("Ошибка запуска:", err)
	}
}
