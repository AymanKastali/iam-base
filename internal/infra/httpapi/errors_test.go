package httpapi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/AymanKastali/iam-base/internal/app"
)

func TestMapAppError_KindedError(t *testing.T) {
	cases := []struct {
		name       string
		kind       app.Kind
		wantStatus int
	}{
		{"validation", app.KindValidation, http.StatusUnprocessableEntity},
		{"conflict", app.KindConflict, http.StatusConflict},
		{"unauthorized", app.KindUnauthorized, http.StatusUnauthorized},
		{"not_found", app.KindNotFound, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := app.NewError(c.kind, "some_code", errors.New("boom"))

			mapped := mapAppError("test", err)

			statusErr, ok := mapped.(huma.StatusError)
			if !ok {
				t.Fatalf("mapAppError() = %v, want a huma.StatusError", mapped)
			}
			if statusErr.GetStatus() != c.wantStatus {
				t.Errorf("status = %d, want %d", statusErr.GetStatus(), c.wantStatus)
			}
			if statusErr.Error() != "boom" {
				t.Errorf("message = %q, want %q", statusErr.Error(), "boom")
			}
		})
	}
}

func TestMapAppError_UnclassifiedError_Returns500(t *testing.T) {
	mapped := mapAppError("test", errors.New("boom"))

	statusErr, ok := mapped.(huma.StatusError)
	if !ok {
		t.Fatalf("mapAppError() = %v, want a huma.StatusError", mapped)
	}
	if statusErr.GetStatus() != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", statusErr.GetStatus())
	}
}
