package main

import (
	"log"
	"net/http"

	"sso-demo/books/api"
	"sso-demo/books/auth"
)

const (
	ServerName = "books"
	ListenAddr = "localhost:8000"
)

func main() {
	http.Handle("/login", auth.Login())
	http.Handle("/callback", auth.LoginCallback())

	http.Handle("/", api.Home())
	http.Handle("/ping", api.Ping())
	http.Handle("/my-book", api.MyBook())

	log.Printf("%s server listen on %s", ServerName, ListenAddr)
	if err := http.ListenAndServe(ListenAddr, nil); err != nil {
		log.Fatalln(err)
	}
}
