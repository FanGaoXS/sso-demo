package api

import (
	"fmt"
	"log"
	"net/http"

	"sso-demo/lessons/auth"
)

func Home() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ui, err := auth.GetUserInfo(ctx, r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		log.Printf("%s has been logged in %s, do not log in again", ui.Name, ui.Audience)
		msg := fmt.Sprintf("Welcome, %s!", ui.Name)
		w.Write([]byte(msg))
	}
}

func MyLesson() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		ui, err := auth.GetUserInfo(ctx, r)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		msg := fmt.Sprintf("These are your books, %s!", ui.Name)
		w.Write([]byte(msg))
	}
}

func Ping() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	}
}
