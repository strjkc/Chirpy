package handlers

import (
	"github.com/strjkc/chirpy/internal/auth"
	user "github.com/strjkc/chirpy/users"
)

type Handlers struct {
	auth    *auth.AuthService
	service *user.UserService
}

func NewHandlers(auth *auth.AuthService, service *user.UserService) *Handlers {
	return &Handlers{auth: auth, service: service}
}
