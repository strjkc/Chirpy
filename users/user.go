package user

type User struct {
	ID          string
	Email       string
	Password    string
	CreatedAt   string
	UpdatedAt   string
	IsChirpyRed bool
}

type UserInput struct {
	Email    string
	Password string
}
