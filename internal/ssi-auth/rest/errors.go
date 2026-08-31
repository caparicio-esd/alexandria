package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/caparicio-esd/alexandria/internal/common"
	"github.com/gin-gonic/gin"
)

// errorBody is the single error shape this API speaks. Keeping it in one place
// means an auditor can read exactly what leaves the process on a failure.
type errorBody struct {
	Error string `json:"error"`
	// Field names the offending input when the domain could pinpoint one.
	Field string `json:"field,omitempty"`
}

// respondError is the only translation table between domain errors and HTTP.
// Nothing else in this package chooses a status code.
//
// Domain errors carry their own message and are safe to echo; anything that
// falls through is infrastructure, so it is logged in full and answered opaque.
func respondError(c *gin.Context, err error) {
	// Filed on the context rather than logged here: the access log emits one
	// record per request, at a level chosen from the status, and it picks this
	// up. Logging in both places would double-count every failure.
	_ = c.Error(err)

	var (
		invalid   common.ValidationError
		typeErr   *json.UnmarshalTypeError
		syntaxErr *json.SyntaxError
	)

	switch {
	// A body that will not decode is the caller's mistake, not an outage. It is
	// answered in this API's own vocabulary rather than with the library's
	// message, which names the Go struct the request happened to be decoded
	// into — an internal detail that must not leave the process.
	case errors.As(err, &typeErr):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorBody{
			Error: fmt.Sprintf("must be %s", jsonKind(typeErr.Type)),
			Field: typeErr.Field,
		})

	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		c.AbortWithStatusJSON(http.StatusBadRequest,
			errorBody{Error: "body is not valid json"})

	case errors.Is(err, io.EOF):
		c.AbortWithStatusJSON(http.StatusBadRequest,
			errorBody{Error: "body is empty"})

	case errors.As(err, &invalid):
		c.AbortWithStatusJSON(http.StatusBadRequest,
			errorBody{Error: invalid.Reason, Field: invalid.Field})

	case errors.Is(err, common.ErrInvalidInput):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorBody{Error: err.Error()})

	case errors.Is(err, common.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, errorBody{Error: err.Error()})

	case errors.Is(err, common.ErrConflict):
		c.AbortWithStatusJSON(http.StatusConflict, errorBody{Error: err.Error()})

	case errors.Is(err, common.ErrUnsupported):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, errorBody{Error: err.Error()})

	case errors.Is(err, common.ErrNotLinked):
		c.AbortWithStatusJSON(http.StatusPreconditionFailed, errorBody{Error: err.Error()})

	default:
		// Infrastructure failures are answered opaque: the cause reaches the
		// log through c.Error above, not the caller.
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			errorBody{Error: "internal error"})
	}
}

// jsonKind names a Go type in the vocabulary of the format the caller wrote in.
// Telling someone their field must be a "[]string" answers in a language they
// were never speaking.
func jsonKind(t reflect.Type) string {
	if t == nil {
		return "of a different type"
	}

	switch t.Kind() {
	case reflect.Slice, reflect.Array:
		return "an array"
	case reflect.Map, reflect.Struct:
		return "an object"
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "a boolean"
	case reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "a number"
	default:
		return "of a different type"
	}
}
