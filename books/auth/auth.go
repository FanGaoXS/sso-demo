package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sso-demo/userinfo"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	OidcProvider = "http://sso.college.edu:5556/dex"
	ClientId     = "books-college"
	ClientSecret = "books-college-secret"
	RedirectURL  = "http://books.college.edu:8000/callback"
	CookieDomain = ".college.edu"
)

func Oauth2Config(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     ClientId,
		ClientSecret: ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess, "profile", "email", "groups"},
	}
}

func Login() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		provider, err := oidc.NewProvider(ctx, OidcProvider)
		if err != nil {
			http.Error(w, fmt.Sprintf("init oidc provider failed: %s", err), http.StatusInternalServerError)
			return
		}

		oauth2Config := Oauth2Config(provider)
		url := oauth2Config.AuthCodeURL("state")
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func LoginCallback() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		provider, err := oidc.NewProvider(ctx, OidcProvider)
		if err != nil {
			http.Error(w, fmt.Sprintf("init oidc provider failed: %s", err), http.StatusInternalServerError)
			return
		}
		config := Oauth2Config(provider)
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, fmt.Sprintf("exchange token with server failed: %s", err), http.StatusUnauthorized)
			return
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, fmt.Sprintf("get rawIDToken with token failed"), http.StatusUnauthorized)
			return
		}
		idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: ClientId})
		idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("verify IDToken with oidc provider failed: %s", err), http.StatusUnauthorized)
			return
		}

		setTokenIntoCookie(w, oauth2Token)
		bytes, _ := json.Marshal(idToken)
		w.Write(bytes)
	}
}

func GetUserInfo(ctx context.Context, r *http.Request) (*userinfo.UserInfo, error) {
	token, err := getTokenFromCookie(r)
	if err != nil {
		return nil, fmt.Errorf("get userinfo failed: %v", err)
	}

	provider, err := oidc.NewProvider(ctx, OidcProvider)
	if err != nil {
		return nil, fmt.Errorf("initialize provider failed: %v", err)
	}
	idTokenVerifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true})
	idToken, err := idTokenVerifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verify rawIDToken failed: %v", err)
	}

	var ui *userinfo.UserInfo
	if err = idToken.Claims(&ui); err != nil {
		return nil, fmt.Errorf("parse idToken failed: %v", err)
	}

	return ui, nil
}

func getTokenFromCookie(r *http.Request) (string, error) {
	rawExpiry, err := r.Cookie("expiry")
	if err != nil {
		return "", fmt.Errorf("get token from cookie failed: %v", err)
	}
	expiry, err := time.Parse(time.RFC3339, rawExpiry.Value)
	if err != nil {
		return "", fmt.Errorf("parse expiry which is from cookie failed: %v", err)
	}
	if expiry.Before(time.Now()) {
		return "", fmt.Errorf("token is expired")
	}

	rawIDToken, err := r.Cookie("id_token")
	if err != nil {
		return "", fmt.Errorf("get token from cookie failed: %v", err)
	}

	return rawIDToken.Value, nil
}

func setTokenIntoCookie(w http.ResponseWriter, oauth2Token *oauth2.Token) {
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	cookies := []*http.Cookie{
		{Name: "access_token", Value: oauth2Token.AccessToken},
		{Name: "token_type", Value: oauth2Token.TokenType},
		{Name: "refresh_token", Value: oauth2Token.RefreshToken},
		{Name: "expiry", Value: oauth2Token.Expiry.Format(time.RFC3339)},
		{Name: "id_token", Value: rawIDToken},
	}
	for _, c := range cookies {
		c.Domain = CookieDomain
		c.Path = "/"
		c.MaxAge = 60 * 5 // 5 minutes
		c.HttpOnly = true
		http.SetCookie(w, c)
	}
}
