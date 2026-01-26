package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/strjkc/chirpy/internal/auth"

	"github.com/google/uuid"

	"github.com/joho/godotenv"

	_ "github.com/lib/pq"

	"github.com/strjkc/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	keyb64         string
	polkaApiKey    string
}

func readinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Store(cfg.fileserverHits.Add(1))
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	resp := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, cfg.fileserverHits.Load())
	w.Write([]byte(resp))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	cfg.db.DeleteAll(r.Context())
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Data Reset!"))
}

func jsonResponseError(w http.ResponseWriter, statusCode int, msg string) {
	type error struct {
		Error string `json:"error"`
	}

	resp := error{
		Error: msg,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("bla")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(data)
}

func handlerPostChirp(w http.ResponseWriter, r *http.Request) {
	type body struct {
		Body string `json:"body"`
	}

	type valid struct {
		Cleaned_body string `json:"cleaned_body"`
	}

	profane := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	decoder := json.NewDecoder(r.Body)
	target := body{}
	err := decoder.Decode(&target)
	if err != nil {
		jsonResponseError(w, 500, "Something Went Wrong")
		return
	}

	if len(target.Body) > 140 {
		jsonResponseError(w, 400, "Chirp is too long")
		return
	}

	respBody := target.Body

	strs := strings.Split(target.Body, " ")
	for i, bodyStr := range strs {
		if _, ok := profane[strings.ToLower(bodyStr)]; ok {
			strs[i] = "****"
		}
	}
	respBody = strings.Join(strs, " ")

	resp := valid{
		Cleaned_body: respBody,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		jsonResponseError(w, 500, "Something Went Wrong")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(data)
}

func (cfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	type request struct {
		Body string `json:"body"`
		// UserID string `json:"user_id"`
	}

	type response struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		jsonResponseError(w, 401, err.Error())
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.keyb64)
	if err != nil {
		jsonResponseError(w, 401, err.Error())
		return
	}

	req := request{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&req)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	if len(req.Body) < 1 {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	params := database.CreateChirpParams{
		Body:   req.Body,
		UserID: userID,
	}

	data, err := cfg.db.CreateChirp(r.Context(), params)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	resp := response{
		ID:        data.ID.String(),
		CreatedAt: data.CreatedAt.String(),
		UpdatedAt: data.UpdatedAt.String(),
		Body:      data.Body,
		UserID:    data.UserID.String(),
	}

	resp1, err := json.Marshal(resp)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(resp1)
}

type Chirp struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	Body      string `json:"body"`
	UserID    string `json:"user_id"`
}

func (cfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirpId, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		fmt.Println("error parsing uuid")
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	dbChirp, err := cfg.db.GetChirp(r.Context(), chirpId)
	if err != nil {
		fmt.Println("error fetching from db")
		jsonResponseError(w, 404, "Chirp not found")
		return
	}

	respChirp := Chirp{
		ID:        dbChirp.ID.String(),
		CreatedAt: dbChirp.CreatedAt.String(),
		UpdatedAt: dbChirp.UpdatedAt.String(),
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID.String(),
	}

	resp, err := json.Marshal(respChirp)
	if err != nil {
		fmt.Println("error marshaling")
		jsonResponseError(w, 500, "An Error occured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()
	sortOrder := queryParams.Get("sort")
	authorID := queryParams.Get("author_id")
	fmt.Println(authorID)

	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		jsonResponseError(w, 404, "Chirps not found")
		return
	}

	if sortOrder == "desc" {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.After(chirps[j].CreatedAt)
		})
	} else {
		sort.Slice(chirps, func(i, j int) bool {
			return chirps[i].CreatedAt.Before(chirps[j].CreatedAt)
		})
	}

	respChirps := make([]Chirp, 0)
	for _, chirp := range chirps {
		c := Chirp{
			ID:        chirp.ID.String(),
			CreatedAt: chirp.CreatedAt.String(),
			UpdatedAt: chirp.UpdatedAt.String(),
			Body:      chirp.Body,
			UserID:    chirp.UserID.String(),
		}
		respChirps = append(respChirps, c)
	}

	resp, err := json.Marshal(respChirps)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	if authorID != "" {
		filtered := respChirps[:0]
		for _, chirp := range respChirps {
			if chirp.UserID == authorID {
				filtered = append(filtered, chirp)
			}
		}
		respChirps = filtered
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, r *http.Request) {
	type req struct {
		Email            string `json:"email"`
		Password         string `json:"password"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
	}

	type res struct {
		ID           string `json:"id"`
		CreatedAt    string `json:"created_at"`
		UpdatedAt    string `json:"updated_at"`
		Email        string `json:"email"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		IsChirpyRed  bool   `json:"is_chirpy_red"`
	}

	request := req{}
	decoder := json.NewDecoder(r.Body)
	decoder.Decode(&request)

	user, err := cfg.db.GetUser(r.Context(), request.Email)
	if err != nil {
		jsonResponseError(w, 401, "Incorrect email or password")
		return
	}

	isOk, err := auth.CheckPasswordHash(request.Password, user.HashedPassword)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	if !isOk {
		jsonResponseError(w, 401, "Incorrect email or password")
		return
	}

	tokenLife := 3600
	duration := time.Duration(tokenLife) * time.Second

	token, err := auth.MakeJWT(user.ID, cfg.keyb64, duration)
	if err != nil {
		fmt.Println(err)
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	refreshTknDuration := time.Now().Add(time.Duration(1440) * time.Hour)
	refreshToken, _ := auth.MakeRefreshToken()
	_, err = cfg.db.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: refreshTknDuration,
	})
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	response := res{
		ID:           user.ID.String(),
		CreatedAt:    user.CreatedAt.String(),
		UpdatedAt:    user.UpdatedAt.String(),
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
		IsChirpyRed:  user.IsChirpyRed,
	}

	marshResp, err := json.Marshal(response)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(marshResp)
}

func (cfg *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	fullTkn := r.Header.Get("Authorization")
	if len(fullTkn) < 1 {
		jsonResponseError(w, 401, "Token error")
		return
	}

	tknArr := strings.Split(fullTkn, " ")
	token := tknArr[1]

	dbToken, err := cfg.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		jsonResponseError(w, 401, "Invalid token")
		return
	}

	tokenExp := dbToken.ExpiresAt

	if !tokenExp.After(time.Now()) || dbToken.RevokedAt.Valid {
		jsonResponseError(w, 401, "Invalid token")
		return
	}

	authTokenLife := 3600
	duration := time.Duration(authTokenLife) * time.Second

	newJwt, err := auth.MakeJWT(dbToken.UserID, cfg.keyb64, duration)
	if err != nil {
		jsonResponseError(w, 500, "Internal Error")
		return
	}

	type response struct {
		Token string `json:"token"`
	}

	resp := response{
		Token: newJwt,
	}

	respJson, err := json.Marshal(resp)
	if err != nil {
		jsonResponseError(w, 500, "Internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(respJson)
}

func (cfg *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	fullTkn := r.Header.Get("Authorization")
	if len(fullTkn) < 1 {
		jsonResponseError(w, 401, "Token error")
		return
	}

	tknArr := strings.Split(fullTkn, " ")
	token := tknArr[1]

	err := cfg.db.RevokeToken(r.Context(), token)
	if err != nil {
		jsonResponseError(w, 500, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

func (cfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		jsonResponseError(w, 401, "Invalid token")
		return
	}
	chirpId, err := uuid.Parse(r.PathValue("chirpID"))

	uuid, err := auth.ValidateJWT(token, cfg.keyb64)
	if err != nil {
		jsonResponseError(w, 401, "Invalid token")
		return
	}

	res, err := cfg.db.DeleteChirp(r.Context(), database.DeleteChirpParams{ID: chirpId, UserID: uuid})
	if err != nil {
		jsonResponseError(w, 404, "Chirp Not Found")
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		jsonResponseError(w, 500, "Internal Error")
		return
	}

	if rowsAffected == 0 {
		jsonResponseError(w, 403, "Chirp Not Found")
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) setChirpyRedHandler(w http.ResponseWriter, r *http.Request) {
	type hookData struct {
		UserID string `json:"user_id"`
	}

	type req struct {
		Event    string   `json:"event"`
		HookData hookData `json:"data"`
	}

	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil {
		fmt.Print("An erorr occured parsing api key from header")
		jsonResponseError(w, 401, err.Error())
		return
	}

	if apiKey != cfg.polkaApiKey {
		jsonResponseError(w, 401, "Invalid api key")
		return
	}

	requestData := req{}
	err = json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		fmt.Print("Error decoding data")
		jsonResponseError(w, 500, "An error occured")
		return
	}

	if requestData.Event != "user.upgraded" {
		jsonResponseError(w, 204, "Invalid event")
		return
	}

	uuid, err := uuid.Parse(requestData.HookData.UserID)
	if err != nil {
		fmt.Println("Error parsing uuid")
		jsonResponseError(w, 500, "An error occured")
		return
	}

	result, err := cfg.db.SetChirpyRed(r.Context(), uuid)
	if err != nil {
		fmt.Println("Running sql %v", err)
		jsonResponseError(w, 500, "An error occured")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		fmt.Println("error parsing rows affected")
		jsonResponseError(w, 500, "An error occured")
		return
	}

	if rowsAffected == 0 {
		jsonResponseError(w, 404, "User not found")
		return
	}

	w.WriteHeader(204)
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	dbURL := os.Getenv("DB_URL")
	key := os.Getenv("KEY")
	polkaKey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}
	dbQueries := database.New(db)
	cfg := apiConfig{}
	cfg.db = dbQueries
	cfg.keyb64 = key
	cfg.polkaApiKey = polkaKey
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("POST /api/validate_chirp", handlerPostChirp)
	mux.HandleFunc("POST /api/users", cfg.usersHandler)
	mux.HandleFunc("PUT /api/users", cfg.updateUsersHandler)
	mux.HandleFunc("POST /api/login", cfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", cfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", cfg.revokeHandler)
	mux.HandleFunc("POST /api/chirps", cfg.createChirpHandler)
	mux.HandleFunc("POST /api/polka/webhooks", cfg.setChirpyRedHandler)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.deleteChirpHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.getChirpHandler)
	mux.HandleFunc("GET /api/chirps", cfg.getChirpsHandler)
	mux.HandleFunc("GET /api/healthz", readinessHandler)
	mux.HandleFunc("GET /admin/metrics", cfg.metricsHandler)
	mux.HandleFunc("POST /admin/reset", cfg.resetHandler)
	server := http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	err = server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
