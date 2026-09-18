// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/publicip"
)

const (
	testToken   = "test-access-token"
	testCSRF    = "test-csrf-token"
	testVersion = "1.2.3-test"
)

type fakeProvider struct {
	current     credential.Credential
	currentErr  error
	credentials []credential.Credential
	listErr     error
	revocable   func(current, target credential.Credential) bool
	revokeErr   error
	revoked     []int64

	// identities counts the calls that read the credential in use, which a sweep makes
	// once for the whole set.
	identities int

	applications       []credential.Application
	applicationsErr    error
	deletedApplication []int64
	deleteAppErr       error
	appDeletable       func(current credential.Credential, id int64) bool
}

var _ credential.Provider = (*fakeProvider)(nil)

func (f *fakeProvider) List(context.Context, credential.Status) ([]credential.Credential, error) {
	return f.credentials, f.listErr
}

func (f *fakeProvider) Get(context.Context, int64) (credential.Credential, error) {
	return credential.Credential{}, nil
}

func (f *fakeProvider) Revoke(ctx context.Context, id int64) error {
	f.identities++
	return f.RevokeAgainst(ctx, f.current, id)
}

func (f *fakeProvider) RevokeAgainst(_ context.Context, current credential.Credential, id int64) error {
	if current.ID == id {
		return credential.ErrSelfRevocation
	}
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, id)
	return nil
}

func (f *fakeProvider) Applications(context.Context) ([]credential.Application, error) {
	return f.applications, f.applicationsErr
}

func (f *fakeProvider) DeleteApplication(_ context.Context, id int64) error {
	if f.deleteAppErr != nil {
		return f.deleteAppErr
	}
	f.deletedApplication = append(f.deletedApplication, id)
	return nil
}

// DeleteApplicationAgainst carries the guard of the real provider: an application still named
// by one of the credentials the caller listed is refused, however the caller reached it.
func (f *fakeProvider) DeleteApplicationAgainst(ctx context.Context, credentials []credential.Credential, id int64) error {
	for _, c := range credentials {
		if c.Application.ID == id {
			return credential.ErrApplicationInUse
		}
	}
	return f.DeleteApplication(ctx, id)
}

func (f *fakeProvider) DeletableApplication(current credential.Credential, id int64) bool {
	if f.appDeletable != nil {
		return f.appDeletable(current, id)
	}
	return current.Permits(http.MethodDelete, "/me/api/application/"+strconv.FormatInt(id, 10))
}

func (f *fakeProvider) Current(context.Context) (credential.Credential, error) {
	f.identities++
	return f.current, f.currentErr
}

func (f *fakeProvider) Revocable(current, target credential.Credential) bool {
	if f.revocable != nil {
		return f.revocable(current, target)
	}
	return true
}

// fixedCatalog stands in for the API-backed catalogue, whose fetching and fallback have
// their own tests in the catalog package.
type fixedCatalog catalog.Snapshot

func (c fixedCatalog) Current(context.Context) catalog.Snapshot { return catalog.Snapshot(c) }

func newTestServer(t *testing.T, provider credential.Provider) http.Handler {
	t.Helper()
	return newServer(t, provider, fixedCatalog{Live: true, Branches: []string{"/me"}, Routes: []catalog.Route{
		{Path: "/me/api/credential/{credentialId}", Operations: []catalog.Operation{
			{Method: "GET", Description: "Get this credential"},
			{Method: "DELETE", Description: "Remove this credential", Deprecated: true},
		}},
		{Path: "/me", Operations: []catalog.Operation{{Method: "GET"}}},
	}})
}

func newTestServerWithCatalog(t *testing.T, routes catalog.Catalog) http.Handler {
	t.Helper()
	return newServer(t, &fakeProvider{}, routes)
}

func newServer(t *testing.T, provider credential.Provider, routes catalog.Catalog) http.Handler {
	t.Helper()
	return New(Options{
		Provider: provider,
		Catalog:  routes,
		Resolver: publicip.Disabled{},
		Assets:   emptyAssets(),
		Logger:   discardLogger(),
		Token:    testToken,
		CSRF:     testCSRF,
		Endpoint: "ovh-eu",
		Version:  testVersion,
	})
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()

	var payload T
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding %s: %v", rec.Body.String(), err)
	}
	return payload
}

func emptyAssets() fstest.MapFS {
	return fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")}}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func request(t *testing.T, handler http.Handler, target string, cookie bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if cookie {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestEverythingButHealthNeedsTheToken(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	for _, target := range []string{"/", "/api/inventory", "/app.js"} {
		if got := request(t, handler, target, false).Code; got != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want %d", target, got, http.StatusUnauthorized)
		}
	}

	if got := request(t, handler, healthPath, false).Code; got != http.StatusOK {
		t.Errorf("%s without a token = %d, want %d", healthPath, got, http.StatusOK)
	}
}

func TestTokenInTheQueryMovesToACookie(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	rec := request(t, handler, "/?token="+testToken, false)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); strings.Contains(location, testToken) {
		t.Errorf("the token stayed in the redirect target: %q", location)
	}

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	set := cookies[0]
	if set.Value != testToken {
		t.Errorf("cookie value = %q", set.Value)
	}
	if !set.HttpOnly {
		t.Error("the session cookie is readable from scripts")
	}
	if set.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want strict", set.SameSite)
	}
}

func TestAWrongTokenIsRefused(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	if got := request(t, handler, "/?token=wrong", false).Code; got != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", got, http.StatusUnauthorized)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/inventory", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "wrong"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status with a wrong cookie = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestSecurityHeadersLeaveNoRoomForExternalContent(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})
	header := request(t, handler, healthPath, false).Header()

	policy := header.Get("Content-Security-Policy")
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:"} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("the policy allows %q: %s", forbidden, policy)
		}
	}
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'"} {
		if !strings.Contains(policy, directive) {
			t.Errorf("the policy is missing %q: %s", directive, policy)
		}
	}
	if header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("X-Content-Type-Options is not set")
	}
	if header.Get("Referrer-Policy") != "no-referrer" {
		t.Error("Referrer-Policy is not set")
	}
}

func inventoryFixture() *fakeProvider {
	old := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	return &fakeProvider{
		current: credential.Credential{ID: 2},
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated, LastUsedAt: old, CreatedAt: old},
			{ID: 2, Status: credential.StatusValidated, LastUsedAt: recent, CreatedAt: old,
				Application: credential.Application{ID: 7, Name: "keymaker", Key: "aaaa"},
				Rules:       []credential.AccessRule{{Method: "GET", Path: "/me/api/credential"}},
				AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32")}},
			{ID: 3, Status: credential.StatusExpired, CreatedAt: old},
		},
	}
}

func decodeInventory(t *testing.T, handler http.Handler) inventoryResponse {
	t.Helper()
	rec := request(t, handler, "/api/inventory", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var payload inventoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return payload
}

func TestInventoryOrdersByLastUseAndMarksTheCredentialInUse(t *testing.T) {
	payload := decodeInventory(t, newTestServer(t, inventoryFixture()))

	if payload.Endpoint != "ovh-eu" {
		t.Errorf("endpoint = %q", payload.Endpoint)
	}
	if payload.Current == nil || *payload.Current != 2 {
		t.Fatalf("current = %v, want 2", payload.Current)
	}

	order := []int64{}
	for _, c := range payload.Credentials {
		order = append(order, c.ID)
	}
	// Most recent first, and the key never used last.
	if len(order) != 3 || order[0] != 2 || order[1] != 1 || order[2] != 3 {
		t.Fatalf("order = %v, want [2 1 3]", order)
	}

	for _, c := range payload.Credentials {
		if (c.ID == 2) != c.Self {
			t.Errorf("credential %d has self = %v", c.ID, c.Self)
		}
	}

	never := payload.Credentials[2]
	if never.LastUsedAt != nil || never.ExpiresAt != nil {
		t.Errorf("absent timestamps were not returned as null: %+v", never)
	}
}

func TestInventorySurvivesAnUnknownCurrentCredential(t *testing.T) {
	provider := inventoryFixture()
	provider.currentErr = credential.ErrPermissionDenied

	payload := decodeInventory(t, newTestServer(t, provider))
	if payload.Current != nil {
		t.Errorf("current = %v, want null", payload.Current)
	}
	if len(payload.Credentials) != 3 {
		t.Errorf("credentials = %d, want 3", len(payload.Credentials))
	}
	for _, c := range payload.Credentials {
		if c.Self {
			t.Errorf("credential %d was marked without a known current credential", c.ID)
		}
	}
}

func TestARefusedListIsNamedRatherThanPassedThrough(t *testing.T) {
	provider := inventoryFixture()
	provider.listErr = credential.ErrPermissionDenied

	rec := request(t, newTestServer(t, provider), "/api/inventory", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	var payload errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.Code != codePermissionDenied {
		t.Errorf("code = %q, want %q", payload.Code, codePermissionDenied)
	}
	if strings.Contains(payload.Error, credential.ErrPermissionDenied.Error()) {
		t.Errorf("the raw refusal reached the response: %q", payload.Error)
	}
}

func TestTheInterfaceIsServedFromTheBinary(t *testing.T) {
	rec := request(t, newTestServer(t, &fakeProvider{}), "/", true)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "<!doctype html>") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// The redirect that trades the token for a cookie must stay on this site. A request line
// in absolute form and a protocol-relative path both carry a host that would otherwise
// end up in the Location header.
func TestTheTokenRedirectCannotLeaveTheSite(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	for _, target := range []string{
		"http://evil.example/?token=" + testToken,
		"//evil.example/?token=" + testToken,
	} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			location := rec.Header().Get("Location")
			if strings.Contains(location, "evil.example") {
				t.Fatalf("Location = %q, want a target on this site", location)
			}
			if !strings.HasPrefix(location, "/") || strings.HasPrefix(location, "//") {
				t.Fatalf("Location = %q, want a rooted relative path", location)
			}
		})
	}
}

func TestInventoryReportsFindingsAndTheirCounts(t *testing.T) {
	long := time.Now().Add(-400 * 24 * time.Hour)

	provider := &fakeProvider{
		current: credential.Credential{ID: 1},
		credentials: []credential.Credential{
			// Reaches the whole account, from anywhere, forever, and says nothing about
			// what it is for.
			{ID: 1, Status: credential.StatusValidated, CreatedAt: long, LastUsedAt: time.Now(),
				Rules: []credential.AccessRule{{Method: "GET", Path: "/me/*"}}},
			// Restricted, described and dated: nothing to report.
			{ID: 2, Status: credential.StatusValidated, CreatedAt: long, LastUsedAt: time.Now(),
				Application: credential.Application{Name: "dns-acme", Description: "certbot"},
				Rules:       []credential.AccessRule{{Method: "GET", Path: "/domain/zone/*"}},
				AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32")},
				ExpiresAt:   time.Now().Add(24 * time.Hour)},
		},
	}

	payload := decodeInventory(t, newTestServer(t, provider))

	byID := map[int64][]string{}
	for _, c := range payload.Credentials {
		for _, finding := range c.Findings {
			byID[c.ID] = append(byID[c.ID], finding.Code)
		}
	}

	for _, want := range []string{"broad-access", "no-ip-restriction", "no-expiry", "no-description"} {
		if !slices.Contains(byID[1], want) {
			t.Errorf("findings for 1 = %v, want %s", byID[1], want)
		}
	}
	if len(byID[2]) != 0 {
		t.Errorf("findings for 2 = %v, want none", byID[2])
	}

	if payload.Summary.Total != 2 {
		t.Errorf("total = %d, want 2", payload.Summary.Total)
	}
	if payload.Summary.Examined != 2 {
		t.Errorf("examined = %d, want 2", payload.Summary.Examined)
	}
	if payload.Summary.Flagged != 1 {
		t.Errorf("flagged = %d, want 1", payload.Summary.Flagged)
	}
	if payload.Summary.AtRisk != 1 {
		t.Errorf("atRisk = %d, want 1", payload.Summary.AtRisk)
	}
	if payload.Summary.Counts["no-expiry"] != 1 {
		t.Errorf("no-expiry count = %d, want 1", payload.Summary.Counts["no-expiry"])
	}
}

// At debug level each request leaves a line. The address that opens a session carries the
// access token in its query string, and that line must not repeat it.
func TestRequestsAreLoggedAtDebugWithoutTheirQuery(t *testing.T) {
	var buffer bytes.Buffer
	handler := New(Options{
		Provider: &fakeProvider{},
		Catalog:  fixedCatalog{},
		Resolver: publicip.Disabled{},
		Assets:   emptyAssets(),
		Logger:   slog.New(slog.NewTextHandler(&buffer, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Token:    testToken,
		CSRF:     testCSRF,
		Endpoint: "ovh-eu",
	})

	request(t, handler, "/?token="+testToken, false)

	line := buffer.String()
	if !strings.Contains(line, "status=303") || !strings.Contains(line, "path=/") {
		t.Errorf("log = %q, want the path and the status of the request", line)
	}
	if strings.Contains(line, testToken) {
		t.Errorf("the access token reached the request log: %q", line)
	}
}
