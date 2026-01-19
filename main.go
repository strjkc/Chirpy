package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

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

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		panic(err)
	}
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("posgres", dbURL)
	if err != nil {
		panic(err)
	}
	dbQueries := database.New(db)
	cfg := apiConfig{}
	cfg.db = dbQueries
	mux := http.NewServeMux()
	mux.Handle("/app/", http.StripPrefix("/app/", cfg.middlewareMetricsInc(http.FileServer(http.Dir(".")))))
	mux.HandleFunc("POST /api/validate_chirp", handlerPostChirp)
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
