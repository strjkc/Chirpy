package auth

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
)

func TestHashPassword(t *testing.T) {
	pass := "Strongpass123@"
	result, err := HashPassword(pass)
	if err != nil {
		t.Error("Hashing Failed")
	}

	lst := strings.Split(result, "$")
	if len(lst[len(lst)-1]) != 43 {
		t.Error("Invalid length")
		fmt.Println(result)
	}

	isOk, err := CheckPasswordHash(pass, result)
	if err != nil {
		t.Error("Hashing Check Failed")
	}

	if isOk != true {
		t.Error("Pass check failed")
	}

	isOk, _ = CheckPasswordHash("1234", result)

	if isOk != false {
		t.Error("Pass check failed, on invalid password")
	}
}

func TestToken(t *testing.T) {
	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJjaGlycHkiLCJzdWIiOiJiNjkxODZkNy1lNDQ2LTRkZjctODhjZi1hYjFmYTJkMjgyNjUiLCJleHAiOjE3NjkyNTQ1MDEsImlhdCI6MTc2OTI1MDkwMX0.M0820DKR5V0iL3id4wy9oVmnP_1tdB9Lico2CS8rISA"
	godotenv.Load("../../.env")
	key := os.Getenv("KEY")
	user, err := ValidateJWT(tokenString, key)
	if err != nil {
		t.Error("Failed decoding")
	}
	if user.String() != "b69186d7-e446-4df7-88cf-ab1fa2d28265" {
		t.Error("uuid not correct")
	}
	fmt.Print(user.String())
}
