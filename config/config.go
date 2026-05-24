package config

import (
	"sync/atomic"

	"github.com/strjkc/chirpy/internal/database"
)

type ApiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	keyb64         string
	polkaApiKey    string
}
