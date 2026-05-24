package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/strjkc/chirpy/config"
	"github.com/strjkc/chirpy/internal/auth"
	"github.com/strjkc/chirpy/internal/database"
)

func (cfg *config.ApiConfig) createUsersHandler(w http.ResponseWriter, r *http.Request) {
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
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	hashedPass, err := auth.HashPassword(request.Password)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured, user not created")
	}

	params := database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Email:          request.Email,
		HashedPassword: hashedPass,
	}

	createdUser, err := cfg.db.CreateUser(r.Context(), params)
	fmt.Printf("Error %v", err)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	response := res{
		ID:          createdUser.ID.String(),
		CreatedAt:   createdUser.CreatedAt.String(),
		UpdatedAt:   createdUser.UpdatedAt.String(),
		Email:       createdUser.Email,
		IsChirpyRed: createdUser.IsChirpyRed,
	}

	data, err := json.Marshal(response)
	fmt.Printf("Error %v", err)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func (cfg *apiConfig) updateUsersHandler(w http.ResponseWriter, r *http.Request) {
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
		jsonResponseError(w, 401, "Invalid token")
		return
	}

	uuid, err := auth.ValidateJWT(tkn, cfg.keyb64)
	if err != nil {
		jsonResponseError(w, 401, "Invalid token")
		return
	}

	requestData := req{}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	if len(requestData.Email) < 4 {
		jsonResponseError(w, 404, "Invalid email")
		return
	}

	// unslafe code, if attacker grabs token he can change my pass, email format is not validated
	hashedPass, err := auth.HashPassword(requestData.Password)
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	dbUser, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{ID: uuid, HashedPassword: hashedPass, Email: requestData.Email})
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	respData := res{
		ID:          dbUser.ID.String(),
		CreatedAt:   dbUser.CreatedAt.String(),
		UpdatedAt:   dbUser.UpdatedAt.String(),
		Email:       dbUser.Email,
		IsChirpyRed: dbUser.IsChirpyRed,
	}

	response, err := json.Marshal(respData)
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}
