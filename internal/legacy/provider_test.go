// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package legacy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"

	sdk "github.com/ovh/go-ovh/ovh"

	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
)

// fakeClient stands in for the transport. Wire fidelity is covered by the fixtures of the
// ovh package; what matters here is which calls the provider makes and what it does with
// the failures, so the double is counted and locked for the concurrent detail fetch.
type fakeClient struct {
	mu sync.Mutex

	ids             []int64
	credentials     map[int64]credential.Credential
	credentialErrs  map[int64]error
	applications    map[int64]credential.Application
	applicationErr  error
	current         credential.Credential
	currentErr      error
	deleteErr       error
	listedStatus    credential.Status
	deleted         []int64
	applicationCall int

	// byCredential answers the credential route, keyed by credential identifier, which is the
	// only route that reads an application the account does not own.
	byCredential    map[int64]credential.Application
	byCredentialErr error
	byCredentialLog []int64

	identityCalls int
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

var _ ovh.Client = (*fakeClient)(nil)

func (f *fakeClient) ListCredentialIDs(_ context.Context, status credential.Status) ([]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listedStatus = status
	return f.ids, nil
}

func (f *fakeClient) Credential(_ context.Context, id int64) (credential.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.credentialErrs[id]; ok {
		return credential.Credential{}, err
	}
	return f.credentials[id], nil
}

func (f *fakeClient) Application(_ context.Context, id int64) (credential.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applicationCall++
	if f.applicationErr != nil {
		return credential.Application{}, f.applicationErr
	}
	found, ok := f.applications[id]
	if !ok {
		return credential.Application{}, apiError(http.StatusNotFound)
	}
	return found, nil
}

func (f *fakeClient) CurrentCredential(context.Context) (credential.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identityCalls++
	return f.current, f.currentErr
}

func (f *fakeClient) DeleteCredential(_ context.Context, id int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeClient) CredentialApplication(_ context.Context, id int64) (credential.Application, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byCredentialLog = append(f.byCredentialLog, id)
	if f.byCredentialErr != nil {
		return credential.Application{}, f.byCredentialErr
	}
	found, ok := f.byCredential[id]
	if !ok {
		return credential.Application{}, apiError(http.StatusNotFound)
	}
	return found, nil
}

func (f *fakeClient) Index(context.Context) ([]byte, error) {
	return nil, errors.New("not exercised")
}

func (f *fakeClient) Schema(context.Context, string) ([]byte, error) {
	return nil, errors.New("not exercised")
}

func apiError(code int) error {
	return &sdk.APIError{Code: code, Message: http.StatusText(code)}
}

func inventory() *fakeClient {
	return &fakeClient{
		ids: []int64{1, 2, 3},
		credentials: map[int64]credential.Credential{
			1: {ID: 1, Status: credential.StatusValidated, Application: credential.Application{ID: 10}},
			2: {ID: 2, Status: credential.StatusExpired, Application: credential.Application{ID: 10}},
			3: {ID: 3, Status: credential.StatusValidated, Application: credential.Application{ID: 11}},
		},
		applications: map[int64]credential.Application{
			10: {ID: 10, Key: "aaaa", Name: "terraform-prod"},
			11: {ID: 11, Key: "bbbb", Name: "dns-acme"},
		},
	}
}

func TestListResolvesEachApplicationOnce(t *testing.T) {
	client := inventory()
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), credential.StatusValidated)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(credentials) != 3 {
		t.Fatalf("len = %d, want 3", len(credentials))
	}
	if client.listedStatus != credential.StatusValidated {
		t.Errorf("status filter = %q", client.listedStatus)
	}
	if client.applicationCall != 2 {
		t.Errorf("application calls = %d, want 2 for two distinct applications", client.applicationCall)
	}
	for _, c := range credentials {
		if c.Application.Name == "" {
			t.Errorf("credential %d has an unresolved application", c.ID)
		}
	}
}

func TestListDropsACredentialRevokedWhileListing(t *testing.T) {
	client := inventory()
	client.credentialErrs = map[int64]error{2: apiError(http.StatusNotFound)}
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(credentials) != 2 {
		t.Fatalf("len = %d, want 2", len(credentials))
	}
	for _, c := range credentials {
		if c.ID == 2 {
			t.Error("the revoked credential is still listed")
		}
	}
}

func TestListFailsOnARefusedDetail(t *testing.T) {
	client := inventory()
	client.credentialErrs = map[int64]error{2: apiError(http.StatusForbidden)}
	provider := New(client, discard)

	if _, err := provider.List(context.Background(), ""); err == nil {
		t.Fatal("List succeeded, want an error")
	}
}

// A management key holding the credential rules but not the application ones still has to
// produce a usable inventory.
func TestListSurvivesUnreadableApplications(t *testing.T) {
	client := inventory()
	client.applicationErr = apiError(http.StatusForbidden)
	client.byCredentialErr = apiError(http.StatusForbidden)
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(credentials) != 3 {
		t.Fatalf("len = %d, want 3", len(credentials))
	}
	if credentials[0].Application.ID != 10 {
		t.Errorf("application identifier was lost: %+v", credentials[0].Application)
	}
	if credentials[0].Application.Name != "" {
		t.Errorf("application name appeared out of a failed call: %+v", credentials[0].Application)
	}
}

// Keys issued through the OVHcloud API console carry an application the account does not
// own, which the application route answers with a 404. They are typically the oldest keys
// with the widest rules, and showing them unnamed hides exactly what the inventory is for.
func TestAnApplicationTheAccountDoesNotOwnIsReadThroughTheCredential(t *testing.T) {
	client := inventory()
	client.ids = []int64{1, 4, 5}
	client.credentials[4] = credential.Credential{ID: 4, Status: credential.StatusValidated, Application: credential.Application{ID: 168}}
	client.credentials[5] = credential.Credential{ID: 5, Status: credential.StatusValidated, Application: credential.Application{ID: 168}}
	client.byCredential = map[int64]credential.Application{
		4: {ID: 168, Name: "Ovh_Console", Description: "OVH API console"},
		5: {ID: 168, Name: "Ovh_Console", Description: "OVH API console"},
	}
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byID := map[int64]credential.Application{}
	for _, c := range credentials {
		byID[c.ID] = c.Application
	}
	for _, id := range []int64{4, 5} {
		if byID[id].Name != "Ovh_Console" || !byID[id].External {
			t.Errorf("credential %d: application = %+v, want Ovh_Console marked external", id, byID[id])
		}
	}
	if byID[1].External {
		t.Errorf("an owned application was marked external: %+v", byID[1])
	}
	if len(client.byCredentialLog) != 1 {
		t.Errorf("credential route calls = %v, want one for the one application it resolves", client.byCredentialLog)
	}
}

// A management key without the application rules can still read an application through the
// credential rule it holds. That application is the account's own, and is not called
// external just because the other route was refused.
func TestARefusedApplicationRouteFallsBackWithoutCallingTheApplicationExternal(t *testing.T) {
	client := inventory()
	client.applicationErr = apiError(http.StatusForbidden)
	client.byCredential = map[int64]credential.Application{
		1: {ID: 10, Name: "terraform-prod"},
		2: {ID: 10, Name: "terraform-prod"},
		3: {ID: 11, Name: "dns-acme"},
	}
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, c := range credentials {
		if c.Application.Name == "" || c.Application.External {
			t.Errorf("credential %d: application = %+v, want it named and owned", c.ID, c.Application)
		}
	}
}

func TestRevokeRefusesTheCredentialInUse(t *testing.T) {
	client := inventory()
	client.current = credential.Credential{ID: 3}
	provider := New(client, discard)

	err := provider.Revoke(context.Background(), 3)
	if !errors.Is(err, credential.ErrSelfRevocation) {
		t.Fatalf("err = %v, want ErrSelfRevocation", err)
	}
	if len(client.deleted) != 0 {
		t.Errorf("a delete was issued anyway: %v", client.deleted)
	}
}

func TestRevokeDeletesAnyOtherCredential(t *testing.T) {
	client := inventory()
	client.current = credential.Credential{ID: 3}
	provider := New(client, discard)

	if err := provider.Revoke(context.Background(), 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(client.deleted) != 1 || client.deleted[0] != 1 {
		t.Errorf("deleted = %v, want [1]", client.deleted)
	}
}

// Failing to identify the credential in use must not fall through to the deletion: the
// guard would then be skipped exactly when the API is misbehaving.
func TestRevokeStopsWhenTheCurrentCredentialIsUnknown(t *testing.T) {
	client := inventory()
	client.currentErr = apiError(http.StatusForbidden)
	provider := New(client, discard)

	err := provider.Revoke(context.Background(), 1)
	if !errors.Is(err, credential.ErrIdentityUnavailable) {
		t.Fatalf("err = %v, want ErrIdentityUnavailable", err)
	}
	if len(client.deleted) != 0 {
		t.Errorf("a delete was issued anyway: %v", client.deleted)
	}
}

// A refused identity call and a refused deletion are both 403s, and they send the reader
// looking in different places.
func TestARefusedIdentityIsNotReportedAsAMissingDeleteRule(t *testing.T) {
	client := inventory()
	client.current = credential.Credential{ID: 3}
	client.deleteErr = apiError(http.StatusForbidden)
	provider := New(client, discard)

	err := provider.Revoke(context.Background(), 1)
	if !errors.Is(err, credential.ErrPermissionDenied) {
		t.Fatalf("a refused deletion: err = %v, want ErrPermissionDenied", err)
	}
	if errors.Is(err, credential.ErrIdentityUnavailable) {
		t.Error("a refused deletion was reported as a failure to identify")
	}
}

func TestRefusedCallsBecomeADomainError(t *testing.T) {
	client := inventory()
	client.currentErr = apiError(http.StatusForbidden)
	provider := New(client, discard)

	_, err := provider.Current(context.Background())
	if !errors.Is(err, credential.ErrPermissionDenied) {
		t.Fatalf("err = %v, want ErrPermissionDenied", err)
	}
}

func TestRevocableReadsTheRulesOfTheCredentialInUse(t *testing.T) {
	provider := New(inventory(), discard)
	target := credential.Credential{ID: 4210987}

	withDelete := credential.Credential{Rules: []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential/*"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
	}}
	if !provider.Revocable(withDelete, target) {
		t.Error("a credential holding the delete rule was read as unable to revoke")
	}

	readOnly := credential.Credential{Rules: []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential"},
		{Method: "GET", Path: "/me/api/credential/*"},
	}}
	if provider.Revocable(readOnly, target) {
		t.Error("a read-only credential was read as able to revoke")
	}

	if provider.Revocable(credential.Credential{}, target) {
		t.Error("a credential with no rules was read as able to revoke")
	}
}

// One key the API will not describe leaves the others worth showing. They come back with an
// error counting what is missing, so the inventory can say the list is short.
func TestListReturnsWhatItCouldReadAndCountsTheRest(t *testing.T) {
	client := inventory()
	client.credentialErrs = map[int64]error{2: apiError(http.StatusInternalServerError)}
	provider := New(client, discard)

	credentials, err := provider.List(context.Background(), "")
	var incomplete *credential.IncompleteError
	if !errors.As(err, &incomplete) {
		t.Fatalf("err = %v, want an IncompleteError", err)
	}
	if incomplete.Unreadable != 1 || len(credentials) != 2 {
		t.Errorf("unreadable = %d, credentials = %d, want 1 and 2", incomplete.Unreadable, len(credentials))
	}
	for _, c := range credentials {
		if c.Application.Name == "" {
			t.Errorf("credential %d came back without its application", c.ID)
		}
	}
}

func TestListFailsWhenNothingCouldBeRead(t *testing.T) {
	client := inventory()
	client.credentialErrs = map[int64]error{
		1: apiError(http.StatusInternalServerError),
		2: apiError(http.StatusInternalServerError),
		3: apiError(http.StatusInternalServerError),
	}

	credentials, err := New(client, discard).List(context.Background(), "")
	if err == nil || credentials != nil {
		t.Errorf("credentials = %v, err = %v, want no list and an error", credentials, err)
	}
}

// RevokeAgainst holds the same guard as Revoke without reading the identity again, which is
// what lets a sweep over many keys identify the credential in use once.
func TestRevokeAgainstRefusesTheCredentialInUseWithoutAskingAgain(t *testing.T) {
	client := inventory()
	provider := New(client, discard)
	current := credential.Credential{ID: 3}

	if err := provider.RevokeAgainst(context.Background(), current, 3); !errors.Is(err, credential.ErrSelfRevocation) {
		t.Errorf("err = %v, want ErrSelfRevocation", err)
	}
	if err := provider.RevokeAgainst(context.Background(), current, 1); err != nil {
		t.Errorf("RevokeAgainst: %v", err)
	}
	if client.identityCalls != 0 {
		t.Errorf("identity calls = %d, want none", client.identityCalls)
	}
	if len(client.deleted) != 1 || client.deleted[0] != 1 {
		t.Errorf("deleted = %v, want [1]", client.deleted)
	}
}

func TestRevokingACredentialThatIsGoneIsNamedAsSuch(t *testing.T) {
	client := inventory()
	client.current = credential.Credential{ID: 3}
	client.deleteErr = apiError(http.StatusNotFound)

	err := New(client, discard).Revoke(context.Background(), 1)
	if !errors.Is(err, credential.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
