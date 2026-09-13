// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/kentrow/keymaker/internal/credential"
)

func sweepRequest(t *testing.T, handler http.Handler, csrf string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/credentials/inactive/revocations", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func sweepFixture() *fakeProvider {
	old := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

	return &fakeProvider{
		current: credential.Credential{ID: 2, Status: credential.StatusValidated},
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated, CreatedAt: old},
			{ID: 2, Status: credential.StatusValidated, CreatedAt: old},
			{ID: 3, Status: credential.StatusExpired, CreatedAt: old},
			{ID: 4, Status: credential.StatusRefused, CreatedAt: old},
			{ID: 5, Status: credential.StatusPendingValidation, CreatedAt: old},
		},
	}
}

func TestSweepRevokesOnlyWhatIsExpiredOrRefused(t *testing.T) {
	provider := sweepFixture()

	rec := sweepRequest(t, newTestServer(t, provider), testCSRF)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	if want := []int64{3, 4}; !slices.Equal(provider.revoked, want) {
		t.Errorf("revoked = %v, want %v", provider.revoked, want)
	}

	payload := decode[sweepResponse](t, rec)
	if !slices.Equal(payload.Revoked, []int64{3, 4}) {
		t.Errorf("reported = %v, want [3 4]", payload.Revoked)
	}
	if len(payload.Failed) != 0 {
		t.Errorf("failed = %v, want none", payload.Failed)
	}
}

// A credential that is still validated, pending, or the one the tool authenticates with is
// not part of the set whatever the caller asks for: the endpoint takes no list.
func TestSweepLeavesALiveKeyAlone(t *testing.T) {
	provider := sweepFixture()
	sweepRequest(t, newTestServer(t, provider), testCSRF)

	for _, spared := range []int64{1, 2, 5} {
		if slices.Contains(provider.revoked, spared) {
			t.Errorf("credential %d was revoked", spared)
		}
	}
}

// An expired credential the tool authenticates with cannot happen through the API, but the
// guard is what makes that true rather than the status.
func TestSweepRefusesTheCredentialInUse(t *testing.T) {
	provider := sweepFixture()
	provider.current = credential.Credential{ID: 3, Status: credential.StatusExpired}

	rec := sweepRequest(t, newTestServer(t, provider), testCSRF)
	payload := decode[sweepResponse](t, rec)

	if slices.Contains(provider.revoked, 3) {
		t.Fatal("the credential in use was revoked")
	}
	if len(payload.Failed) != 1 || payload.Failed[0].ID != 3 || payload.Failed[0].Code != codeSelfRevocation {
		t.Errorf("failed = %v, want one self-revocation on 3", payload.Failed)
	}
	if !slices.Equal(payload.Revoked, []int64{4}) {
		t.Errorf("revoked = %v, want [4]", payload.Revoked)
	}
}

// Without a delete rule the single path does not offer revocation at all, and the sweep
// reports the same refusal rather than calling an API that would answer 403.
func TestSweepReportsAMissingDeleteRule(t *testing.T) {
	provider := sweepFixture()
	provider.revocable = func(_, target credential.Credential) bool { return target.ID != 4 }

	payload := decode[sweepResponse](t, sweepRequest(t, newTestServer(t, provider), testCSRF))

	if slices.Contains(provider.revoked, 4) {
		t.Error("credential 4 was revoked without the rule for it")
	}
	if len(payload.Failed) != 1 || payload.Failed[0].ID != 4 || payload.Failed[0].Code != codePermissionDenied {
		t.Errorf("failed = %v, want one permission-denied on 4", payload.Failed)
	}
}

// One refusal does not end the sweep: the reader asked for the set and is owed an account
// of all of it.
func TestSweepCarriesOnAfterAFailure(t *testing.T) {
	provider := sweepFixture()
	provider.revokeErr = credential.ErrPermissionDenied

	payload := decode[sweepResponse](t, sweepRequest(t, newTestServer(t, provider), testCSRF))

	if len(payload.Revoked) != 0 {
		t.Errorf("revoked = %v, want none", payload.Revoked)
	}
	if len(payload.Failed) != 2 {
		t.Fatalf("failed = %v, want both", payload.Failed)
	}
	for _, failure := range payload.Failed {
		if failure.Code != codePermissionDenied {
			t.Errorf("credential %d reported %q", failure.ID, failure.Code)
		}
	}
}

func TestSweepWithoutTheTokenIsRefused(t *testing.T) {
	for name, csrf := range map[string]string{"no token": "", "wrong token": "not-the-token"} {
		t.Run(name, func(t *testing.T) {
			provider := sweepFixture()

			rec := sweepRequest(t, newTestServer(t, provider), csrf)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if len(provider.revoked) != 0 {
				t.Errorf("a revocation went through anyway: %v", provider.revoked)
			}
		})
	}
}

func TestSweepStillNeedsTheAccessToken(t *testing.T) {
	provider := sweepFixture()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/credentials/inactive/revocations", nil)
	req.Header.Set(csrfHeader, testCSRF)

	rec := httptest.NewRecorder()
	newTestServer(t, provider).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if len(provider.revoked) != 0 {
		t.Errorf("a revocation went through anyway: %v", provider.revoked)
	}
}

// A listing the API refuses leaves the sweep with nothing to select from, and it says so
// instead of reporting an empty success.
func TestSweepFailsWhenTheListingFails(t *testing.T) {
	provider := sweepFixture()
	provider.listErr = credential.ErrPermissionDenied

	rec := sweepRequest(t, newTestServer(t, provider), testCSRF)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d: %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if len(provider.revoked) != 0 {
		t.Errorf("a revocation went through anyway: %v", provider.revoked)
	}
}

// The sweep identifies the credential in use once, at the start of the request, rather
// than once per key of the set; the guard is the same and the calls do not multiply.
func TestSweepReadsTheIdentityOnce(t *testing.T) {
	provider := sweepFixture()

	if rec := sweepRequest(t, newTestServer(t, provider), testCSRF); rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if provider.identities != 1 {
		t.Errorf("identity reads = %d, want 1 for the whole sweep", provider.identities)
	}
}

// A key that is gone by the time the sweep reaches it is what the sweep was asked for.
func TestSweepCountsAKeyAlreadyGoneAsRevoked(t *testing.T) {
	provider := sweepFixture()
	provider.revokeErr = credential.ErrNotFound

	payload := decode[sweepResponse](t, sweepRequest(t, newTestServer(t, provider), testCSRF))
	if len(payload.Failed) != 0 {
		t.Errorf("failed = %v, want none", payload.Failed)
	}
}
