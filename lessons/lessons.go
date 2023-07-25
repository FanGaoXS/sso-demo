package main

import (
	"log"
	"net/http"

	"sso-demo/lessons/api"
	"sso-demo/lessons/auth"
)

const (
	ServerName = "lessons"
	ListenAddr = "localhost:8001"
)

func main() {
	http.Handle("/login", auth.Login())
	http.Handle("/callback", auth.LoginCallback())

	http.Handle("/", api.Home())
	http.Handle("/ping", api.Ping())
	http.Handle("/my-lesson", api.MyLesson())

	log.Printf("%s server listen on %s", ServerName, ListenAddr)
	if err := http.ListenAndServe(ListenAddr, nil); err != nil {
		log.Fatalln(err)
	}
}
