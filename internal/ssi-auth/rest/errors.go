package rest

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/caparicio-esd/alexandria/internal/ssi-auth/wallet"
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
	var invalid wallet.ValidationError

	switch {
	case errors.As(err, &invalid):
		c.AbortWithStatusJSON(http.StatusBadRequest,
			errorBody{Error: invalid.Reason, Field: invalid.Field})

	case errors.Is(err, wallet.ErrInvalidInput):
		c.AbortWithStatusJSON(http.StatusBadRequest, errorBody{Error: err.Error()})

	case errors.Is(err, wallet.ErrNotFound):
		c.AbortWithStatusJSON(http.StatusNotFound, errorBody{Error: err.Error()})

	case errors.Is(err, wallet.ErrConflict):
		c.AbortWithStatusJSON(http.StatusConflict, errorBody{Error: err.Error()})

	case errors.Is(err, wallet.ErrUnsupported):
		c.AbortWithStatusJSON(http.StatusUnprocessableEntity, errorBody{Error: err.Error()})

	case errors.Is(err, wallet.ErrNotLinked):
		c.AbortWithStatusJSON(http.StatusPreconditionFailed, errorBody{Error: err.Error()})

	default:
		slog.ErrorContext(c.Request.Context(), "unhandled error",
			"path", c.FullPath(), "err", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			errorBody{Error: "internal error"})
	}
}
