// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handoffRequestFor(t *testing.T, handler http.Handler, body string, csrf string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/handoff", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	req.Header.Set("Content-Type", "application/json")
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// The page is the one of the configured region, and every rule reaches it: the reader
// pressed one button and expects the set they assembled, not the first of each method.
func TestHandoffCarriesEveryRuleToThePageOfTheRegion(t *testing.T) {
	body := `{"rules":[
		{"method":"GET","path":"/me"},
		{"method":"GET","path":"/me/api/credential"},
		{"method":"POST","path":"/me/api/credential"},
		{"method":"DELETE","path":"/me/api/credential/*"}
	]}`

	rec := handoffRequestFor(t, newTestServer(t, inventoryFixture()), body, testCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	got := decode[handoffResponse](t, rec).URL
	if !strings.HasPrefix(got, "https://eu.api.ovh.com/createToken/?") {
		t.Fatalf("url = %q, want the page of the configured region", got)
	}
	for _, want := range []string{
		"GET=/me&",
		"GET=/me/api/credential",
		"POST=/me/api/credential",
		"DELETE=/me/api/credential/*",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the link does not carry %q: %s", want, got)
		}
	}

	// The wildcard is what makes a rule cover every identifier, so it has to arrive as one
	// rather than percent-encoded into something the page shows as text.
	if strings.Contains(got, "%2A") {
		t.Errorf("the wildcard was escaped: %s", got)
	}
}

func TestHandoffRefusesAnEmptyOrMalformedSet(t *testing.T) {
	for name, body := range map[string]string{
		"no rule":       `{"rules":[]}`,
		"bad method":    `{"rules":[{"method":"FETCH","path":"/me"}]}`,
		"bad path":      `{"rules":[{"method":"GET","path":"me"}]}`,
		"not an object": `nonsense`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := handoffRequestFor(t, newTestServer(t, inventoryFixture()), body, testCSRF)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}

// Forging the link changes nothing on the account, but it is a POST and is held to the
// same guard as every other one rather than to a judgement about its effects.
func TestHandoffNeedsBothTokens(t *testing.T) {
	body := `{"rules":[{"method":"GET","path":"/me"}]}`

	if got := handoffRequestFor(t, newTestServer(t, inventoryFixture()), body, "").Code; got != http.StatusForbidden {
		t.Errorf("without the page token = %d, want %d", got, http.StatusForbidden)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/handoff", strings.NewReader(body))
	req.Header.Set(csrfHeader, testCSRF)
	rec := httptest.NewRecorder()
	newTestServer(t, inventoryFixture()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("without the access token = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}
