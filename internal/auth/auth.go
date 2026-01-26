package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	params := argon2id.Params{
		Memory:      128 * 1024,
		Iterations:  10,
		Parallelism: uint8(runtime.NumCPU()),
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := argon2id.CreateHash(password, &params)
	if err != nil {
		return "", err
	}

	return hash, nil
}

func CheckPasswordHash(password, hash string) (bool, error) {
	isOk, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}

	return isOk, nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	curTime := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  &jwt.NumericDate{Time: curTime},
		ExpiresAt: &jwt.NumericDate{Time: curTime.Add(expiresIn)},
		Subject:   userID.String(),
	}
	fmt.Printf("%v", claims)
	// key := os.Getenv("DB_URL")
	key, err := base64.StdEncoding.DecodeString(tokenSecret)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		key, err := base64.StdEncoding.DecodeString(tokenSecret)
		if err != nil {
			return "", err
		}
		return key, nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	claimsSubject, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.UUID{}, err
	}
	userID, err := uuid.Parse(claimsSubject)
	if err != nil {
		return uuid.UUID{}, err
	}

	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	brToken := headers.Get("Authorization")
	if len(brToken) < 1 {
		return "", fmt.Errorf("Token not submited or invalid format")
	}
	arr := strings.Split(brToken, " ")

	token := arr[1]
	if len(token) < 1 {
		return "", fmt.Errorf("Token Ivalid")
	}
	return token, nil
}

func MakeRefreshToken() (string, error) {
	bArr := make([]byte, 32)

	_, _ = rand.Read(bArr)

	tokenString := hex.EncodeToString(bArr)

	return tokenString, nil
}

func GetAPIKey(header http.Header) (string, error) {
	keyStr := header.Get("Authorization")
	if len(keyStr) < 1 {
		return "", fmt.Errorf("api key invalid or missing")
	}
	keyArr := strings.Split(keyStr, " ")
	apiKey := keyArr[1]
	if len(apiKey) < 15 {
		return "", fmt.Errorf("invalid api key format")
	}
	return apiKey, nil
}
