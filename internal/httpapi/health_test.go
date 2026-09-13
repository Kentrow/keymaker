// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAnswersOK(t *testing.T) {
	rec := request(t, newTestServer(t, &fakeProvider{}), healthPath, false)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got, want := rec.Body.String(), "ok\n"; got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}

// The health endpoint only answers reads. A write is refused by the router, whether or not
// it carries the page token, and no handler runs for it.
func TestHealthRejectsWrites(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	for name, token := range map[string]string{"without the token": "", "with the token": testCSRF} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, healthPath, nil)
		if token != "" {
			req.Header.Set(csrfHeader, token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status %s = %d, want %d", name, rec.Code, http.StatusMethodNotAllowed)
		}
	}
}
