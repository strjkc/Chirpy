package customErrors

type ErrType int

const (
	ValidationError ErrType = iota
	NotAuthorized
	NotAuthenticated
	InternalError
)

type Error struct {
	Type    ErrType
	Message string
}

func NewError(erType ErrType, message string) Error {
	return Error{erType, message}
}

func (e Error) Error() string {
	return e.Message
}
