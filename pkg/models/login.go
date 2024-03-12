package models

// LoginCredentials represents the credentials used for login
type LoginCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
