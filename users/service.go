package user

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/strjkc/chirpy/internal/auth"
	"github.com/strjkc/chirpy/internal/customErrors"
	"github.com/strjkc/chirpy/internal/database"
)

type UserService struct {
	db   *database.Queries
	auth auth.AuthService
}

func NewUserService(DBConnection *database.Queries, auth auth.AuthService) *UserService {
	return &UserService{db: DBConnection, auth: auth}
}

func (u *UserService) CreateUser(cntx context.Context, newUser UserInput) (User, error) {
	if err := validUserInput(newUser); err != nil {
		return User{}, err
	}

	hashedPass, err := auth.HashPassword(newUser.Password)
	if err != nil {
		return User{}, err
	}
	params := database.CreateUserParams{
		ID:             uuid.New(),
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
		Email:          newUser.Email,
		HashedPassword: hashedPass,
	}
	dbUser, err := u.db.CreateUser(cntx, params)
	fmt.Printf("Error %v", err)
	if err != nil {
		return User{}, err
	}
	user := buildUser(dbUser)
	return user, nil
}

func (u *UserService) UpdateUser(cntx context.Context, newUser UserInput, token string) (User, error) {
	if err := validUserInput(newUser); err != nil {
		return User{}, err
	}

	uuid, err := u.auth.ValidateJWT(token)
	if err != nil {
		return User{}, err
	}

	//TODO:
	// unslafe code, if attacker grabs token he can change my pass
	// we should have a different input where we have old and new pass as input data
	hashedPass, err := auth.HashPassword(newUser.Password)
	if err != nil {
		return User{}, err
	}

	dbUser, err := u.db.UpdateUser(cntx, database.UpdateUserParams{ID: uuid, HashedPassword: hashedPass, Email: newUser.Email})
	if err != nil {
		return User{}, err
	}

	user := buildUser(dbUser)
	return user, nil
}

func validEmail(email string) bool {
	emailRe := regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}$`)
	return emailRe.MatchString(email)
}

func validUserInput(newUser UserInput) error {
	if len(newUser.Password) < 6 {
		return customErrors.NewError(customErrors.ValidationError, "password too short")
	}
	if !validEmail(newUser.Email) {
		return customErrors.NewError(customErrors.ValidationError, "invalid email")
	}
	return nil
}

func buildUser(dbUser database.User) User {
	return User{
		ID:          dbUser.ID.String(),
		Email:       dbUser.Email,
		Password:    dbUser.HashedPassword,
		CreatedAt:   dbUser.CreatedAt.String(),
		UpdatedAt:   dbUser.UpdatedAt.String(),
		IsChirpyRed: dbUser.IsChirpyRed,
	}
}
