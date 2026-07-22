// internal/infra/httpapi/logout_handler_test.go
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AymanKastali/iam-base/internal/app/command"
	"github.com/AymanKastali/iam-base/internal/domain"
)

func TestLogoutHandler_ServeHTTP_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:secret", time.Now().Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: repo}}
	body, _ := json.Marshal(map[string]string{"refresh_token": "family-1.secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("logout must revoke the family")
	}
}

func TestLogoutHandler_ServeHTTP_UnknownFamily_StillNoContent(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}
	body, _ := json.Marshal(map[string]string{"refresh_token": "unknown-family.secret"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (logout is idempotent)", rec.Code)
	}
}

func TestLogoutHandler_ServeHTTP_BodyTooLarge(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}

	oversizedToken := strings.Repeat("a", maxRequestBodyBytes)
	body, _ := json.Marshal(map[string]string{"refresh_token": oversizedToken})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/logout", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
}

func newLogoutInput(refreshToken string) *LogoutInput {
	input := &LogoutInput{}
	input.Body.RefreshToken = refreshToken
	return input
}

func TestLogoutHandler_Handle_Success(t *testing.T) {
	repo := newStubRefreshTokenRepo()
	familyID, _ := domain.NewFamilyID("family-1")
	accountID, _ := domain.NewAccountID("account-1")
	family, _ := domain.IssueFamily(familyID, accountID, "hash:secret", time.Now().Add(time.Hour))
	_ = repo.Save(context.Background(), family)

	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: repo}}

	_, err := h.Handle(context.Background(), newLogoutInput("family-1.secret"))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil", err)
	}
	stored, err := repo.FindByID(context.Background(), familyID)
	if err != nil {
		t.Fatalf("FindByID() error = %v, want nil", err)
	}
	if !stored.Revoked() {
		t.Error("logout must revoke the family")
	}
}

func TestLogoutHandler_Handle_UnknownFamily_StillSucceeds(t *testing.T) {
	h := LogoutHandler{Handler: command.RevokeSessionHandler{Repo: newStubRefreshTokenRepo()}}

	_, err := h.Handle(context.Background(), newLogoutInput("unknown-family.secret"))

	if err != nil {
		t.Fatalf("Handle() error = %v, want nil (logout is idempotent)", err)
	}
}
