package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/strjkc/chirpy/internal/auth"
	user "github.com/strjkc/chirpy/users"
)

func (h *Handlers) CreateUsersHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type res struct {
		ID          string `json:"id"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	request := req{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	fmt.Printf("Error %v", err)
	if err != nil {
		jsonResponseError(w, err)
		return
	}

	createdUser, err := h.service.CreateUser(r.Context(), user.UserInput{request.Email, request.Password})
	if err != nil {
		jsonResponseError(w, err)
	}

	response := res{
		ID:          createdUser.ID,
		CreatedAt:   createdUser.CreatedAt,
		UpdatedAt:   createdUser.UpdatedAt,
		Email:       createdUser.Email,
		IsChirpyRed: createdUser.IsChirpyRed,
	}

	data, err := json.Marshal(response)
	fmt.Printf("Error %v", err)
	if err != nil {
		jsonResponseError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func (h *Handlers) UpdateUsersHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type res struct {
		ID          string `json:"id"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
		Email       string `json:"email"`
		IsChirpyRed bool   `json:"is_chirpy_red"`
	}

	tkn, err := auth.GetBearerToken(r.Header)
	if err != nil {
		jsonResponseError(w, err)
		return
	}

	requestData := req{}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		jsonResponseError(w, err)
		return
	}

	updatedUser, err := h.service.UpdateUser(r.Context(), user.UserInput{requestData.Email, requestData.Password}, tkn)
	if err != nil {
		jsonResponseError(w, err)
		return
	}

	respData := res{
		ID:          updatedUser.ID,
		CreatedAt:   updatedUser.CreatedAt,
		UpdatedAt:   updatedUser.UpdatedAt,
		Email:       updatedUser.Email,
		IsChirpyRed: updatedUser.IsChirpyRed,
	}

	response, err := json.Marshal(respData)
	if err != nil {
		jsonResponseError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
