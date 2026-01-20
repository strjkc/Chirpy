package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/joho/godotenv"

	_ "github.com/lib/pq"

	"github.com/strjkc/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
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
		Email string `json:"email"`
	}

	type res struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Email     string `json:"email"`
	}

	request := req{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	params := database.CreateUserParams{
		ID:        uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Email:     request.Email,
	}

	createdUser, err := cfg.db.CreateUser(r.Context(), params)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	response := res{
		ID:        createdUser.ID.String(),
		CreatedAt: createdUser.CreatedAt.String(),
		UpdatedAt: createdUser.UpdatedAt.String(),
		Email:     createdUser.Email,
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
		Body   string `json:"body"`
		UserID string `json:"user_id"`
	}

	type response struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
		Body      string `json:"body"`
		UserID    string `json:"user_id"`
	}

	req := request{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		jsonResponseError(w, 500, "An Error occured")
		return
	}

	parsedUUID, err := uuid.Parse(req.UserID)
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
		UserID: parsedUUID,
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
	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		jsonResponseError(w, 404, "Chirps not found")
		return
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		panic(err)
	}
	dbQueries := database.New(db)
	cfg := apiConfig{}
	cfg.db = dbQueries
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("POST /api/validate_chirp", handlerPostChirp)
	mux.HandleFunc("POST /api/users", cfg.usersHandler)
	mux.HandleFunc("POST /api/chirps", cfg.createChirpHandler)
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
