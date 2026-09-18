// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/kentrow/keymaker/internal/credential"
)

func applicationsFixture() *fakeProvider {
	return &fakeProvider{
		current: credential.Credential{ID: 1, Status: credential.StatusValidated, Rules: []credential.AccessRule{
			{Method: "GET", Path: "/me/api/credential"},
			{Method: "GET", Path: "/me/api/credential/*"},
			{Method: "GET", Path: "/me/api/application"},
			{Method: "GET", Path: "/me/api/application/*"},
		}},
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated, Application: credential.Application{ID: 10, Name: "terraform-prod"}},
		},
		applications: []credential.Application{
			{ID: 10, Key: "aaaa", Name: "terraform-prod"},
			{ID: 11, Key: "bbbb", Name: "dns-acme", Description: "certbot"},
		},
	}
}

// Revoking a key leaves its application behind, and an application no credential points at is
// invisible to the inventory. It is the only place the reader can see one.
func TestApplicationsReportHowManyKeysEachHolds(t *testing.T) {
	payload := decode[applicationsResponse](t, request(t, newTestServer(t, applicationsFixture()), "/api/applications", true))

	if !payload.Listed || payload.Reason != "" {
		t.Fatalf("listed = %v, reason = %q, want the listing", payload.Listed, payload.Reason)
	}
	keys := map[int64]int{}
	for _, a := range payload.Applications {
		keys[a.ID] = a.Credentials
	}
	if keys[10] != 1 || keys[11] != 0 {
		t.Errorf("credentials per application = %v, want one for 10 and none for 11", keys)
	}
}

// The listing rule is optional, like the delete rule: the interface says which rule is missing
// rather than showing a call the API refused.
func TestApplicationsSayWhenTheListingRuleIsMissing(t *testing.T) {
	provider := applicationsFixture()
	provider.current.Rules = []credential.AccessRule{{Method: "GET", Path: "/me/api/credential/*"}}
	provider.applicationsErr = errors.New("this call must not be made")
	provider.applications = nil

	payload := decode[applicationsResponse](t, request(t, newTestServer(t, provider), "/api/applications", true))

	if payload.Listed || payload.Reason != reasonMissingRule {
		t.Errorf("listed = %v, reason = %q, want it refused for a missing rule", payload.Listed, payload.Reason)
	}
	if len(payload.Applications) != 0 {
		t.Errorf("applications = %v, want none", payload.Applications)
	}
}

// A listing the API refuses anyway is reported as a refusal, not as an empty account.
func TestApplicationsReportARefusedListing(t *testing.T) {
	provider := applicationsFixture()
	provider.applications = nil
	provider.applicationsErr = credential.ErrPermissionDenied

	rec := request(t, newTestServer(t, provider), "/api/applications", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decode[errorResponse](t, rec).Code; got != codePermissionDenied {
		t.Errorf("code = %q, want %q", got, codePermissionDenied)
	}
}

// An application the listing names and the detail call will not describe leaves the others
// worth showing, and the count says how many are missing.
func TestApplicationsCountWhatCouldNotBeRead(t *testing.T) {
	provider := applicationsFixture()
	provider.applicationsErr = &credential.IncompleteError{Unreadable: 3, Err: errors.New("refused")}

	payload := decode[applicationsResponse](t, request(t, newTestServer(t, provider), "/api/applications", true))
	if !payload.Listed || payload.Unreadable != 3 || len(payload.Applications) != 2 {
		t.Errorf("listed = %v, unreadable = %d, applications = %d, want the two readable ones and a count of 3",
			payload.Listed, payload.Unreadable, len(payload.Applications))
	}
}

// Deleting an application revokes every key it holds, which is never what tidying up means.
// The offer is refused for anything still holding one.
func TestDeletionIsNotOfferedForAnApplicationThatStillHoldsAKey(t *testing.T) {
	provider := applicationsFixture()
	provider.current.Rules = append(provider.current.Rules, credential.AccessRule{Method: "DELETE", Path: "/me/api/application/*"})

	payload := decode[applicationsResponse](t, request(t, newTestServer(t, provider), "/api/applications", true))

	offers := map[int64]deleteOffer{}
	for _, a := range payload.Applications {
		offers[a.ID] = a.Delete
	}
	if offers[10].Allowed || offers[10].Reason != reasonApplicationInUse {
		t.Errorf("application holding a key: %+v, want it refused as in use", offers[10])
	}
	if !offers[11].Allowed {
		t.Errorf("application holding none: %+v, want it offered", offers[11])
	}
}

func TestDeletionIsNotOfferedWithoutTheDeleteRule(t *testing.T) {
	payload := decode[applicationsResponse](t, request(t, newTestServer(t, applicationsFixture()), "/api/applications", true))

	for _, a := range payload.Applications {
		if a.ID == 11 && (a.Delete.Allowed || a.Delete.Reason != reasonMissingRule) {
			t.Errorf("application holding no key: %+v, want it refused for a missing rule", a.Delete)
		}
	}
}

func TestDeletingAnApplicationRemovesIt(t *testing.T) {
	provider := applicationsFixture()

	rec := applicationDeleteRequest(t, newTestServer(t, provider), "11", testCSRF)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}
	if len(provider.deletedApplication) != 1 || provider.deletedApplication[0] != 11 {
		t.Errorf("deleted = %v, want [11]", provider.deletedApplication)
	}
}

// The guard lives in the provider, against the API rather than against what a screen showed.
// Its refusal is named as such, not as an API failure.
func TestDeletingAnApplicationStillHoldingAKeyIsRefused(t *testing.T) {
	provider := applicationsFixture()
	provider.deleteAppErr = credential.ErrApplicationInUse

	rec := applicationDeleteRequest(t, newTestServer(t, provider), "10", testCSRF)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	if got := decode[errorResponse](t, rec).Code; got != codeApplicationInUse {
		t.Errorf("code = %q, want %q", got, codeApplicationInUse)
	}
}

func TestDeletingAnApplicationWithoutTheTokenIsRefused(t *testing.T) {
	provider := applicationsFixture()

	rec := applicationDeleteRequest(t, newTestServer(t, provider), "11", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if len(provider.deletedApplication) != 0 {
		t.Errorf("deleted = %v, want none", provider.deletedApplication)
	}
}

func applicationDeleteRequest(t *testing.T, handler http.Handler, id, csrf string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodDelete, "/api/applications/"+id, nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func keylessSweepRequest(t *testing.T, handler http.Handler, csrf, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/applications/keyless/deletions", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	if csrf != "" {
		req.Header.Set(csrfHeader, csrf)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// deletableFixture is the listing fixture with a management key that also holds the delete
// rule, which is what makes the bulk deletion something the tool offers at all.
func deletableFixture() *fakeProvider {
	provider := applicationsFixture()
	provider.current.Rules = append(provider.current.Rules, credential.AccessRule{Method: "DELETE", Path: "/me/api/application/*"})
	return provider
}

// The set is the applications holding no key. An application holding one is left exactly as
// it was: deleting it would revoke that key, which is the opposite of tidying up.
func TestDeletingEveryKeylessApplicationSparesTheOnesHoldingAKey(t *testing.T) {
	provider := deletableFixture()

	rec := keylessSweepRequest(t, newTestServer(t, provider), testCSRF, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	payload := decode[keylessSweepResponse](t, rec)
	if !slices.Equal(payload.Deleted, []int64{11}) || len(payload.Failed) != 0 {
		t.Errorf("deleted = %v, failed = %+v, want only 11 deleted", payload.Deleted, payload.Failed)
	}
	if !slices.Equal(provider.deletedApplication, []int64{11}) {
		t.Errorf("deleted = %v, want [11]", provider.deletedApplication)
	}
}

// The request names nothing, and the selection is made from what the API answers. A body
// naming an application that holds a key changes none of it.
func TestTheKeylessDeletionIgnoresWhatTheRequestNames(t *testing.T) {
	provider := deletableFixture()

	rec := keylessSweepRequest(t, newTestServer(t, provider), testCSRF, `{"applications":[10]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !slices.Equal(provider.deletedApplication, []int64{11}) {
		t.Errorf("deleted = %v, want the server selection [11]", provider.deletedApplication)
	}
}

// Holding no key grants the deletion nothing: without the delete rule the bulk path refuses
// each application, exactly as the single path does.
func TestTheKeylessDeletionRefusesWithoutTheDeleteRule(t *testing.T) {
	provider := applicationsFixture()

	payload := decode[keylessSweepResponse](t, keylessSweepRequest(t, newTestServer(t, provider), testCSRF, ""))
	if len(payload.Deleted) != 0 {
		t.Errorf("deleted = %v, want none", payload.Deleted)
	}
	if len(payload.Failed) != 1 || payload.Failed[0].ID != 11 || payload.Failed[0].Code != codePermissionDenied {
		t.Errorf("failed = %+v, want 11 refused for a missing rule", payload.Failed)
	}
	if len(provider.deletedApplication) != 0 {
		t.Errorf("deleted = %v, want no call at all", provider.deletedApplication)
	}
}

// One refusal does not end the deletion: the reader confirmed a set and is owed an account of
// what became of each of its members.
func TestTheKeylessDeletionReportsWhatItCouldNotDelete(t *testing.T) {
	provider := deletableFixture()
	provider.applications = append(provider.applications, credential.Application{ID: 12, Key: "cccc", Name: "old-backup"})
	provider.deleteAppErr = credential.ErrNotFound

	payload := decode[keylessSweepResponse](t, keylessSweepRequest(t, newTestServer(t, provider), testCSRF, ""))
	if len(payload.Deleted) != 0 || len(payload.Failed) != 2 {
		t.Fatalf("deleted = %v, failed = %+v, want both failures reported", payload.Deleted, payload.Failed)
	}
	for _, failure := range payload.Failed {
		if failure.Code != codeApplicationGone {
			t.Errorf("application %d: code = %q, want %q", failure.ID, failure.Code, codeApplicationGone)
		}
	}
}

// The deletion is a change, so the page token is required; the session cookie alone, which
// another origin could carry, is not enough.
func TestTheKeylessDeletionWithoutTheTokenIsRefused(t *testing.T) {
	provider := deletableFixture()

	rec := keylessSweepRequest(t, newTestServer(t, provider), "", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if len(provider.deletedApplication) != 0 {
		t.Errorf("deleted = %v, want none", provider.deletedApplication)
	}
}

// A listing the API refuses leaves nothing to select from, and that is reported as a refusal
// rather than as an account with no application to delete.
func TestTheKeylessDeletionReportsARefusedListing(t *testing.T) {
	provider := deletableFixture()
	provider.applications = nil
	provider.applicationsErr = credential.ErrPermissionDenied

	rec := keylessSweepRequest(t, newTestServer(t, provider), testCSRF, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// The credentials are listed once for the whole set, and so is the identity: the guard is per
// application, the reading it rests on is not.
func TestTheKeylessDeletionReadsTheIdentityOnce(t *testing.T) {
	provider := deletableFixture()
	provider.applications = append(provider.applications,
		credential.Application{ID: 12, Key: "cccc"}, credential.Application{ID: 13, Key: "dddd"})

	if rec := keylessSweepRequest(t, newTestServer(t, provider), testCSRF, ""); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if provider.identities != 1 {
		t.Errorf("identity reads = %d, want 1 for the whole set", provider.identities)
	}
}
