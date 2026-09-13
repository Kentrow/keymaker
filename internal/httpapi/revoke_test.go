// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kentrow/keymaker/internal/credential"
)

func revokeRequest(t *testing.T, handler http.Handler, id string, csrf string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/credentials/"+id, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRevokeDeletesTheNamedCredential(t *testing.T) {
	provider := inventoryFixture()
	handler := newTestServer(t, provider)

	rec := revokeRequest(t, handler, "1", testCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(provider.revoked) != 1 || provider.revoked[0] != 1 {
		t.Errorf("revoked = %v, want [1]", provider.revoked)
	}
}

// A session cookie is attached by the browser on its own, so it cannot be the only thing
// standing between another site and a revocation.
func TestRevokeWithoutTheTokenIsRefused(t *testing.T) {
	provider := inventoryFixture()

	for name, csrf := range map[string]string{"no token": "", "wrong token": "not-the-token"} {
		t.Run(name, func(t *testing.T) {
			rec := revokeRequest(t, newTestServer(t, provider), "1", csrf)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}

			var payload errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err == nil && payload.Code != codeMissingToken {
				t.Errorf("code = %q, want %q", payload.Code, codeMissingToken)
			}
			if len(provider.revoked) != 0 {
				t.Errorf("a revocation went through anyway: %v", provider.revoked)
			}
		})
	}
}

func TestRevokeStillNeedsTheAccessToken(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/credentials/1", nil)
	req.Header.Set(csrfHeader, testCSRF)

	rec := httptest.NewRecorder()
	newTestServer(t, inventoryFixture()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// The interface words the refusal in the reader's language from the code, so that is what
// has to be right; the sentence beside it is only a fallback for whoever reads the API
// directly.
func TestRevokeReportsWhyItWasRefused(t *testing.T) {
	cases := map[string]struct {
		err    error
		status int
		code   string
	}{
		"self revocation":  {credential.ErrSelfRevocation, http.StatusConflict, codeSelfRevocation},
		"identity unknown": {fmt.Errorf("%w: refused", credential.ErrIdentityUnavailable), http.StatusBadGateway, codeIdentityUnknown},
		"missing rule":     {credential.ErrPermissionDenied, http.StatusForbidden, codePermissionDenied},
		"anything else":    {errors.New("connection reset"), http.StatusBadGateway, codeAPIFailure},
	}

	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			provider := inventoryFixture()
			provider.revokeErr = expected.err

			rec := revokeRequest(t, newTestServer(t, provider), "1", testCSRF)
			if rec.Code != expected.status {
				t.Fatalf("status = %d, want %d", rec.Code, expected.status)
			}

			var payload errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if payload.Code != expected.code {
				t.Errorf("code = %q, want %q", payload.Code, expected.code)
			}
			if strings.TrimSpace(payload.Error) == "" {
				t.Error("no fallback sentence beside the code")
			}
		})
	}
}

func TestRevokeRefusesAnIdentifierThatIsNotANumber(t *testing.T) {
	rec := revokeRequest(t, newTestServer(t, inventoryFixture()), "not-a-number", testCSRF)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestTheInventorySaysWhenRevocationIsNotOffered(t *testing.T) {
	provider := inventoryFixture()
	// The credential in use is 2; 3 is refused by the rules of the credential in use.
	provider.revocable = func(_, target credential.Credential) bool { return target.ID != 3 }

	payload := decodeInventory(t, newTestServer(t, provider))

	offers := map[int64]revokeResponse{}
	for _, c := range payload.Credentials {
		offers[c.ID] = c.Revoke
	}

	if !offers[1].Allowed {
		t.Errorf("credential 1: %+v, want it offered", offers[1])
	}
	if offers[2].Allowed || offers[2].Reason != reasonSelf {
		t.Errorf("credential 2: %+v, want it refused as the credential in use", offers[2])
	}
	if offers[3].Allowed || offers[3].Reason != reasonMissingRule {
		t.Errorf("credential 3: %+v, want it refused for a missing rule", offers[3])
	}
}

// Without knowing the rules of the credential in use there is nothing to decide from, so
// the attempt is offered and the API has the last word.
func TestRevocationIsOfferedWhenTheCredentialInUseIsUnknown(t *testing.T) {
	provider := inventoryFixture()
	provider.currentErr = credential.ErrPermissionDenied

	payload := decodeInventory(t, newTestServer(t, provider))
	for _, c := range payload.Credentials {
		if !c.Revoke.Allowed {
			t.Errorf("credential %d: %+v, want it offered", c.ID, c.Revoke)
		}
	}
}

func TestTheMutationTokenIsServedApartFromTheInventory(t *testing.T) {
	handler := newTestServer(t, inventoryFixture())

	payload := decode[sessionResponse](t, request(t, handler, "/api/session", true))
	if payload.CSRF != testCSRF {
		t.Errorf("csrf = %q, want the token the server holds", payload.CSRF)
	}
	if payload.Endpoint != "ovh-eu" {
		t.Errorf("endpoint = %q", payload.Endpoint)
	}
}

// Creating a key needs no permission on the management credential, so an account whose
// listing is refused must still be handed what a mutation has to carry.
func TestTheMutationTokenSurvivesARefusedInventory(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{listErr: credential.ErrPermissionDenied})

	if rec := request(t, handler, "/api/inventory", true); rec.Code != http.StatusForbidden {
		t.Fatalf("inventory = %d, want it refused for this test to mean anything", rec.Code)
	}
	if got := decode[sessionResponse](t, request(t, handler, "/api/session", true)).CSRF; got != testCSRF {
		t.Errorf("csrf = %q, want the token even though the listing was refused", got)
	}
}

func TestTheSessionSaysWhetherTheAddressCanBeLookedUp(t *testing.T) {
	if decode[sessionResponse](t, request(t, newTestServer(t, inventoryFixture()), "/api/session", true)).AddressLookup {
		t.Error("an instance with the lookup off offers it anyway")
	}

	handler := serverResolving(t, fakeResolver{})
	if !decode[sessionResponse](t, request(t, handler, "/api/session", true)).AddressLookup {
		t.Error("an instance that can look the address up does not say so")
	}
}

// A key revoked elsewhere since the inventory was read is reported as such, not as a failure
// of the API that sends the reader to the process log.
func TestRevokingAKeyThatIsAlreadyGoneSaysSo(t *testing.T) {
	provider := &fakeProvider{current: credential.Credential{ID: 1}, revokeErr: credential.ErrNotFound}

	rec := revokeRequest(t, newTestServer(t, provider), "2", testCSRF)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if got := decode[errorResponse](t, rec).Code; got != codeAlreadyRevoked {
		t.Errorf("code = %q, want %q", got, codeAlreadyRevoked)
	}
}
