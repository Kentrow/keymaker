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
	"strconv"
	"strings"
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

// The rules asked for on that page are the rules the tool actually calls, in both
// directions: every signed call under /me is covered by one of them, and every one of them
// covers a call the client makes. A rule covering nothing asks the reader for more than the
// tool uses.
func TestEveryManagementRuleCoversACallAndEveryCallIsCovered(t *testing.T) {
	client, seen := newFakeAPI(t, map[string]string{})
	ctx := context.Background()

	_, _ = client.ListCredentialIDs(ctx, "")
	_, _ = client.Credential(ctx, 1)
	_, _ = client.CredentialApplication(ctx, 1)
	_ = client.DeleteCredential(ctx, 1)
	_, _ = client.ListApplicationIDs(ctx)
	_, _ = client.Application(ctx, 1)
	_ = client.DeleteApplication(ctx, 1)

	granted := credential.Credential{Rules: ManagementRules}
	covered := make([]bool, len(ManagementRules))
	for _, request := range *seen {
		route := strings.TrimPrefix(request.path, "/1.0")
		if !strings.HasPrefix(route, "/me/") {
			continue
		}
		if !granted.Permits(request.method, route) {
			t.Errorf("%s %s is called but no management rule covers it", request.method, route)
		}
		for i, rule := range ManagementRules {
			if (credential.Credential{Rules: []credential.AccessRule{rule}}).Permits(request.method, route) {
				covered[i] = true
			}
		}
	}
	for i, rule := range ManagementRules {
		if !covered[i] {
			t.Errorf("rule %s %s covers no call the client makes", rule.Method, rule.Path)
		}
	}
}

func TestTheManagementRulesMatchWhatTheToolCalls(t *testing.T) {
	for _, rule := range ManagementRules {
		switch rule.Method {
		case "GET", "DELETE":
		default:
			t.Errorf("rule %s %s names a method this tool never issues", rule.Method, rule.Path)
		}
		if !strings.HasPrefix(rule.Path, "/me/api/") {
			t.Errorf("rule %s %s reaches outside the credential and application routes", rule.Method, rule.Path)
		}
	}
}
