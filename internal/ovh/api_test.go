// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/ovh/go-ovh/ovh"

	"github.com/kentrow/keymaker/internal/credential"
)

// recorded keeps what the fake API saw, so the tests can assert on the request as well
// as on the decoding of the response.
type recorded struct {
	method  string
	path    string
	query   string
	headers http.Header
	body    []byte
}

// newFakeAPI serves the fixtures at the routes the client calls. The clock endpoint
// is answered because the SDK resynchronises against it before signing anything.
func newFakeAPI(t *testing.T, routes map[string]string) (*APIClient, *[]recorded) {
	t.Helper()

	seen := []recorded{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read request body: %v", err)
		}
		seen = append(seen, recorded{
			method:  r.Method,
			path:    r.URL.Path,
			query:   r.URL.RawQuery,
			headers: r.Header.Clone(),
			body:    body,
		})

		if r.URL.Path == "/1.0/auth/time" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
			return
		}

		fixture, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if fixture == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		content, err := os.ReadFile(path.Join("testdata", fixture))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	endpoint := server.URL + "/1.0"
	client := &sdk.Client{
		AppKey:      "test-application-key",
		AppSecret:   "test-application-secret",
		ConsumerKey: "test-consumer-key",
		Client:      server.Client(),
		Timeout:     requestTimeout,
		UserAgent:   userAgent,
	}
	if err := client.SetEndpoint(endpoint); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}

	return &APIClient{sdk: client, endpointURL: endpoint}, &seen
}

func TestCredentialDecodesEveryDisplayedField(t *testing.T) {
	client, _ := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential/4210987": "credential_validated.json",
	})

	got, err := client.Credential(context.Background(), 4210987)
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}

	if got.ID != 4210987 {
		t.Errorf("ID = %d, want 4210987", got.ID)
	}
	if got.Application.ID != 128745 {
		t.Errorf("Application.ID = %d, want 128745", got.Application.ID)
	}
	if got.Status != credential.StatusValidated {
		t.Errorf("Status = %q, want %q", got.Status, credential.StatusValidated)
	}
	if len(got.Rules) != 3 {
		t.Fatalf("len(Rules) = %d, want 3", len(got.Rules))
	}
	if got.Rules[1] != (credential.AccessRule{Method: "POST", Path: "/domain/zone/*/record"}) {
		t.Errorf("Rules[1] = %+v", got.Rules[1])
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32"), netip.MustParsePrefix("2001:db8::/64")}
	if len(got.AllowedIPs) != len(want) || got.AllowedIPs[0] != want[0] || got.AllowedIPs[1] != want[1] {
		t.Errorf("AllowedIPs = %v, want %v", got.AllowedIPs, want)
	}
	if got.CreatedAt.IsZero() || got.ExpiresAt.IsZero() || got.LastUsedAt.IsZero() {
		t.Errorf("timestamps not decoded: %+v", got)
	}
	if got.IssuedBySupport {
		t.Error("IssuedBySupport = true for a credential the account holder created")
	}
}

// A credential the support team created carries the same shape as any other, and the one
// field that says so is easy to drop on the way through: nothing else in the payload
// distinguishes it.
func TestACredentialCreatedBySupportIsMarked(t *testing.T) {
	client, _ := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential/4210989": "credential_support.json",
	})

	got, err := client.Credential(context.Background(), 4210989)
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}
	if !got.IssuedBySupport {
		t.Errorf("IssuedBySupport = false, want true for %+v", got)
	}
}

func TestCredentialWithoutExpiryOrUse(t *testing.T) {
	client, _ := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential/4210988": "credential_unlimited.json",
	})

	got, err := client.Credential(context.Background(), 4210988)
	if err != nil {
		t.Fatalf("Credential: %v", err)
	}

	if !got.ExpiresAt.IsZero() {
		t.Errorf("ExpiresAt = %v, want zero", got.ExpiresAt)
	}
	if !got.LastUsedAt.IsZero() {
		t.Errorf("LastUsedAt = %v, want zero", got.LastUsedAt)
	}
	if len(got.AllowedIPs) != 0 {
		t.Errorf("AllowedIPs = %v, want empty", got.AllowedIPs)
	}
}

func TestListCredentialIDsFiltersOnStatus(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential": "credential_ids.json",
	})

	ids, err := client.ListCredentialIDs(context.Background(), credential.StatusValidated)
	if err != nil {
		t.Fatalf("ListCredentialIDs: %v", err)
	}
	if len(ids) != 3 || ids[0] != 4210987 {
		t.Errorf("ids = %v", ids)
	}

	last := (*seen)[len(*seen)-1]
	if last.query != "status=validated" {
		t.Errorf("query = %q, want %q", last.query, "status=validated")
	}
}

func TestListCredentialIDsWithoutFilter(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential": "credential_ids.json",
	})

	if _, err := client.ListCredentialIDs(context.Background(), ""); err != nil {
		t.Fatalf("ListCredentialIDs: %v", err)
	}
	if last := (*seen)[len(*seen)-1]; last.query != "" {
		t.Errorf("query = %q, want empty", last.query)
	}
}

func TestSignedCallsCarryASignature(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{
		"GET /1.0/auth/currentCredential": "credential_validated.json",
	})

	if _, err := client.CurrentCredential(context.Background()); err != nil {
		t.Fatalf("CurrentCredential: %v", err)
	}

	last := (*seen)[len(*seen)-1]
	for _, header := range []string{"X-Ovh-Application", "X-Ovh-Consumer", "X-Ovh-Signature", "X-Ovh-Timestamp"} {
		if last.headers.Get(header) == "" {
			t.Errorf("%s is missing on a signed call", header)
		}
	}
}

func TestApplicationDecoding(t *testing.T) {
	client, _ := newFakeAPI(t, map[string]string{
		"GET /1.0/me/api/credential/4210987/application": "application.json",
		"GET /1.0/me/api/application/128745":             "application.json",
		"GET /1.0/me/api/application":                    "application_ids.json",
	})

	fromCredential, err := client.CredentialApplication(context.Background(), 4210987)
	if err != nil {
		t.Fatalf("CredentialApplication: %v", err)
	}
	if fromCredential.Name != "terraform-prod" || fromCredential.Key != "aBcDeFgHiJkLmNoP" {
		t.Errorf("application = %+v", fromCredential)
	}

	direct, err := client.Application(context.Background(), 128745)
	if err != nil {
		t.Fatalf("Application: %v", err)
	}
	if direct != fromCredential {
		t.Errorf("Application = %+v, CredentialApplication = %+v", direct, fromCredential)
	}

	ids, err := client.ListApplicationIDs(context.Background())
	if err != nil {
		t.Fatalf("ListApplicationIDs: %v", err)
	}
	if len(ids) != 2 || ids[0] != 128745 {
		t.Errorf("ids = %v, want the two the account lists", ids)
	}
}

func TestDeleteCredentialTargetsTheIdentifiedRoute(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{
		"DELETE /1.0/me/api/credential/4210987": "",
	})

	if err := client.DeleteCredential(context.Background(), 4210987); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}

	last := (*seen)[len(*seen)-1]
	if last.method != http.MethodDelete || last.path != "/1.0/me/api/credential/4210987" {
		t.Errorf("request = %s %s", last.method, last.path)
	}
}

func TestStatusCodeExposesTheAPIStatus(t *testing.T) {
	client, _ := newFakeAPI(t, map[string]string{})

	_, err := client.Credential(context.Background(), 4210987)
	if err == nil {
		t.Fatal("Credential succeeded, want an error")
	}
	if got := StatusCode(err); got != http.StatusNotFound {
		t.Errorf("StatusCode = %d, want %d", got, http.StatusNotFound)
	}
}

func TestUnsupportedEndpointsAreRefused(t *testing.T) {
	// Kimsufi and SoYouStart resolve to hosts the outbound rule does not cover.
	for _, name := range []string{"kimsufi-eu", "soyoustart-ca", "not-an-endpoint"} {
		if _, err := endpointURL(name); err == nil {
			t.Errorf("endpointURL(%q) succeeded, want an error", name)
		}
	}
	for _, name := range supportedEndpoints {
		if _, err := endpointURL(name); err != nil {
			t.Errorf("endpointURL(%q): %v", name, err)
		}
	}
}

func TestTheCreateTokenPageIsOnTheHostOfTheRegion(t *testing.T) {
	cases := map[string]string{
		"ovh-eu": "https://eu.api.ovh.com/createToken/",
		"ovh-ca": "https://ca.api.ovh.com/createToken/",
		"ovh-us": "https://api.us.ovhcloud.com/createToken/",
	}

	for endpoint, want := range cases {
		got, err := CreateTokenURL(endpoint, nil)
		if err != nil {
			t.Fatalf("CreateTokenURL(%q): %v", endpoint, err)
		}
		if got != want {
			t.Errorf("CreateTokenURL(%q) = %q, want %q", endpoint, got, want)
		}
	}

	if _, err := CreateTokenURL("kimsufi", nil); err == nil {
		t.Error("an unsupported endpoint produced a page address")
	}
}

func TestTheCreateTokenLinkCarriesTheRulesReadably(t *testing.T) {
	got, err := CreateTokenURL("ovh-eu", ManagementRules)
	if err != nil {
		t.Fatalf("CreateTokenURL: %v", err)
	}

	want := "https://eu.api.ovh.com/createToken/" +
		"?GET=/me/api/credential" +
		"&GET=/me/api/credential/*" +
		"&GET=/me/api/application" +
		"&GET=/me/api/application/*" +
		"&DELETE=/me/api/credential/*" +
		"&DELETE=/me/api/application/*"
	if got != want {
		t.Errorf("link =\n%q\nwant\n%q", got, want)
	}
}

// The quick start of both READMEs hands out one ready-made link per endpoint, and a reader
// follows it before anything of this code runs. A rule added or removed here would leave those
// links asking for the wrong set, which is the one mistake nobody would notice: the page would
// simply issue a key the tool then reports as missing a rule.
func TestTheReadmeLinksAskForTheManagementRules(t *testing.T) {
	for _, name := range []string{"../../README.md", "../../README.fr.md"} {
		readme, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, endpoint := range supportedEndpoints {
			link, err := CreateTokenURL(endpoint, ManagementRules)
			if err != nil {
				t.Fatalf("CreateTokenURL(%q): %v", endpoint, err)
			}
			if !strings.Contains(string(readme), link) {
				t.Errorf("%s does not carry the %s link:\n%s", name, endpoint, link)
			}
		}
	}
}

// A rule is what the reader is agreeing to on that page. Anything that could change its
// meaning has to be escaped, even though nothing in the documented set contains one.
func TestAnUnusualRulePathIsEscaped(t *testing.T) {
	got, err := CreateTokenURL("ovh-eu", []credential.AccessRule{
		{Method: "GET", Path: "/me/api?x=1&y=2 z#f"},
	})
	if err != nil {
		t.Fatalf("CreateTokenURL: %v", err)
	}
	if want := "https://eu.api.ovh.com/createToken/?GET=/me/api%3Fx%3D1%26y%3D2%20z%23f"; got != want {
		t.Errorf("link = %q, want %q", got, want)
	}
}

// The rules the tool can use are the rules it actually calls, in both directions: every
// signed call under /me is covered by one of them, and every one of them covers a call the
// client makes. A rule covering nothing asks the reader for more than the tool uses.
func TestEveryManagementRuleCoversACallAndEveryCallIsCovered(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{})
	ctx := context.Background()

	_, _ = client.ListCredentialIDs(ctx, "")
	_, _ = client.Credential(ctx, 1)
	_, _ = client.CredentialApplication(ctx, 1)
	_ = client.DeleteCredential(ctx, 1)
	_ = client.SetAllowedIPs(ctx, 1, nil)
	_, _ = client.ListApplicationIDs(ctx)
	_, _ = client.Application(ctx, 1)
	_ = client.DeleteApplication(ctx, 1)

	usable := UsableRules()
	granted := credential.Credential{Rules: usable}
	covered := make([]bool, len(usable))
	for _, request := range *seen {
		route := strings.TrimPrefix(request.path, "/1.0")
		if !strings.HasPrefix(route, "/me/") {
			continue
		}
		if !granted.Permits(request.method, route) {
			t.Errorf("%s %s is called but no rule covers it", request.method, route)
		}
		for i, rule := range usable {
			if (credential.Credential{Rules: []credential.AccessRule{rule}}).Permits(request.method, route) {
				covered[i] = true
			}
		}
	}
	for i, rule := range usable {
		if !covered[i] {
			t.Errorf("rule %s %s covers no call the client makes", rule.Method, rule.Path)
		}
	}
}

func TestTheManagementRulesMatchWhatTheToolCalls(t *testing.T) {
	for _, rule := range UsableRules() {
		switch rule.Method {
		case "GET", "DELETE", "PUT":
		default:
			t.Errorf("rule %s %s names a method this tool never issues", rule.Method, rule.Path)
		}
		if !strings.HasPrefix(rule.Path, "/me/api/") {
			t.Errorf("rule %s %s reaches outside the credential and application routes", rule.Method, rule.Path)
		}
	}
}

// The link that issues a management key leaves the address rule out, so that a new key does
// not carry the account-control finding its holder never asked for.
func TestTheAddressRuleIsNotAskedForByDefault(t *testing.T) {
	if slices.Contains(ManagementRules, AddressRule) {
		t.Error("ManagementRules asks for the address rule")
	}
	if !slices.Contains(UsableRules(), AddressRule) {
		t.Error("UsableRules leaves the address rule out")
	}
}

// The API refuses any other field in this body, and reads null as no restriction at all.
func TestSetAllowedIPsSendsTheAddressesAlone(t *testing.T) {
	cases := map[string][]netip.Prefix{
		`{"allowedIPs":["192.0.2.0/24","2001:db8::/32"]}`: {netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")},
		`{"allowedIPs":null}`:                             nil,
	}
	for want, allowed := range cases {
		client, seen := newFakeAPI(t, map[string]string{"PUT /1.0/me/api/credential/42": ""})
		if err := client.SetAllowedIPs(context.Background(), 42, allowed); err != nil {
			t.Fatalf("SetAllowedIPs(%v): %v", allowed, err)
		}

		found := false
		for _, call := range *seen {
			if call.method == http.MethodPut && call.path == "/1.0/me/api/credential/42" {
				found = true
				if got := string(call.body); got != want {
					t.Errorf("body = %s, want %s", got, want)
				}
			}
		}
		if !found {
			t.Errorf("no PUT /1.0/me/api/credential/42 among %d calls", len(*seen))
		}
	}
}

// The way out calls this route with the credential it is about to end: it has to be the
// authenticated POST the API documents, signed like any other call.
func TestLogoutPostsToTheAuthRoute(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{"POST /1.0/auth/logout": ""})

	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	for _, call := range *seen {
		if call.method == http.MethodPost && call.path == "/1.0/auth/logout" {
			if call.headers.Get("X-Ovh-Signature") == "" {
				t.Error("the logout call is not signed")
			}
			return
		}
	}
	t.Errorf("no POST /1.0/auth/logout among %d calls", len(*seen))
}

// dropping serves the clock and one fixture, after closing the first connections it is given
// without a word, the way a connection lost on the way looks to the client.
func dropping(t *testing.T, drops int32, route, fixture string) (*APIClient, *atomic.Int32) {
	t.Helper()

	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= drops {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		if r.URL.Path == "/1.0/auth/time" {
			_, _ = w.Write([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
			return
		}
		if r.Method+" "+r.URL.Path != route {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		content, err := os.ReadFile(path.Join("testdata", fixture))
		if err != nil {
			t.Errorf("read fixture: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(content)
	}))
	t.Cleanup(server.Close)

	client := &sdk.Client{
		AppKey: "test-application-key", AppSecret: "test-application-secret", ConsumerKey: "test-consumer-key",
		Client: server.Client(), Timeout: requestTimeout, UserAgent: userAgent,
	}
	if err := client.SetEndpoint(server.URL + "/1.0"); err != nil {
		t.Fatalf("SetEndpoint: %v", err)
	}
	return &APIClient{sdk: client, endpointURL: server.URL + "/1.0"}, calls
}

// The first signed call starts with the clock: a connection lost there once is not a reason
// to leave the inventory without the identity of the key in use.
func TestAReadLostOnTheWayIsTriedOnceMore(t *testing.T) {
	client, _ := dropping(t, 1, "GET /1.0/auth/currentCredential", "credential_validated.json")

	got, err := client.CurrentCredential(context.Background())
	if err != nil {
		t.Fatalf("CurrentCredential: %v", err)
	}
	if got.ID != 4210987 {
		t.Errorf("ID = %d, want 4210987", got.ID)
	}
}

// Twice in a row is no longer a blip, and the failure is reported rather than retried forever.
func TestAReadIsTriedOnceMoreAndNoMore(t *testing.T) {
	client, calls := dropping(t, 10, "GET /1.0/auth/currentCredential", "credential_validated.json")

	if _, err := client.CurrentCredential(context.Background()); err == nil {
		t.Fatal("CurrentCredential succeeded on a server that drops everything")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("calls = %d, want 2", got)
	}
}

// An answer is final, a refusal included: trying again would only be refused again.
func TestARefusedReadIsNotTriedAgain(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{})

	if _, err := client.Credential(context.Background(), 1); StatusCode(err) != http.StatusNotFound {
		t.Fatalf("err = %v, want a 404", err)
	}
	asked := 0
	for _, call := range *seen {
		if call.path == "/1.0/me/api/credential/1" {
			asked++
		}
	}
	if asked != 1 {
		t.Errorf("the credential was asked %d times, want once", asked)
	}
}
