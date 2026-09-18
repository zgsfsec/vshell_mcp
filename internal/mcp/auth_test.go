package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testToken = "0123456789abcdef0123456789abcdef"

// newTestHandler returns the guarded handler plus a flag the inner handler sets
// when a request actually reached it.
func newTestHandler() (http.Handler, *bool) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNoContent)
	})
	return newAuthHandler(testToken, inner), &reached
}

func TestAuthHandlerRejectsMissingHeader(t *testing.T) {
	h, reached := newTestHandler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sse", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if *reached {
		t.Error("request reached the SSE transport without a token")
	}
	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

func TestAuthHandlerRejectsBadTokens(t *testing.T) {
	cases := map[string]string{
		"wrong token":          "Bearer " + "ffffffffffffffffffffffffffffffff",
		"wrong length":         "Bearer short",
		"missing scheme":       testToken,
		"wrong scheme":         "Basic " + testToken,
		"scheme without token": "Bearer",
		"empty token":          "Bearer ",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			h, reached := newTestHandler()
			req := httptest.NewRequest(http.MethodGet, "/sse", nil)
			req.Header.Set("Authorization", header)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
			}
			if *reached {
				t.Error("request reached the SSE transport with an invalid token")
			}
		})
	}
}

func TestAuthHandlerAcceptsValidToken(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		t.Run(scheme, func(t *testing.T) {
			h, reached := newTestHandler()
			req := httptest.NewRequest(http.MethodGet, "/sse", nil)
			req.Header.Set("Authorization", scheme+" "+testToken)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusNoContent {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			if !*reached {
				t.Error("valid request never reached the SSE transport")
			}
		})
	}
}
