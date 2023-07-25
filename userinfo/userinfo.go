package userinfo

type UserInfo struct {
	Issuer        string   `json:"iss"`
	Subject       string   `json:"sub"`
	Audience      string   `json:"aud"`
	Expire        int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	AtHash        string   `json:"at_hash"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
	Name          string   `json:"name"`
}
