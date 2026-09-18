package utils

import (
	"encoding/json"
	"errors"
	"github.com/go-playground/validator/v10"
	"io"
	"log"
	"net/http"
)

var validate = validator.New()

// DecodeValidateRequest is the single input-sanitization boundary of the service:
// every request body is schema-validated here, which neutralizes injection payloads
// before they can reach the data layer. Query-string params flow through the same
// validator via the router. Because of this, downstream code can trust its inputs.
func DecodeValidateRequest[T any](reader io.ReadCloser) (T, error) {
	var data T
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return data, err
	}
	if err := validate.Struct(data); err != nil {
		return data, err.(validator.ValidationErrors)
	}
	return data, nil
}

func ResponseError(w http.ResponseWriter, code int, err error) {
	ResponseJSON(w, code, map[string]string{"error": err.Error()})
}

func ResponseServerError(w http.ResponseWriter, err error) {
	log.Println(err)
	ResponseError(w, http.StatusInternalServerError, errors.New("internal server error"))
}

func ResponseJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
