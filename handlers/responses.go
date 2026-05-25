package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/strjkc/chirpy/internal/customErrors"
)

type errResp struct {
	Error string `json:"error"`
}

func jsonResponseError(w http.ResponseWriter, err error) {
	var cerr customErrors.Error
	if errors.As(err, &cerr) {
		switch cerr.Type {
		case customErrors.InternalError:
			sendResponse(w, 500, err.Error())
			return
		case customErrors.ValidationError:
			sendResponse(w, 400, err.Error())
			return
		case customErrors.NotAuthenticated:
			sendResponse(w, 401, err.Error())
			return
		case customErrors.NotAuthorized:
			sendResponse(w, 403, err.Error())
			return
		default:
			sendResponse(w, 500, err.Error())
			return
		}
	}
	sendResponse(w, 500, err.Error())
	return
}

func sendResponse(w http.ResponseWriter, status int, msg string) {
	resp := errResp{
		Error: msg,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		fmt.Println("responses->sendResponse: error marshaling resopnse error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(data)
}
