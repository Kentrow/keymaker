// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kentrow/keymaker/internal/audit"
	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
)

// A credential that cannot identify itself is not a credential missing one rule: it is
// expired, revoked, or paired with the wrong secret. Naming the wrong cause sends the
// reader to edit permissions on a key that no longer exists.
func TestARefusedIdentityMakesTheInventoryNameTheCredentialItself(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{
		currentErr: credential.ErrPermissionDenied,
		listErr:    credential.ErrPermissionDenied,
	})

	rec := request(t, handler, "/api/inventory", true)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decode[errorResponse](t, rec).Code; got != codeCredentialUnusable {
		t.Errorf("code = %q, want %q", got, codeCredentialUnusable)
	}
}

func TestACredentialThatWorksButLacksARuleIsStillNamedThatWay(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{listErr: credential.ErrPermissionDenied})

	rec := request(t, handler, "/api/inventory", true)
	if got := decode[errorResponse](t, rec).Code; got != codePermissionDenied {
		t.Errorf("code = %q, want %q", got, codePermissionDenied)
	}
}

func TestAFailureThatIsNotARefusalIsNotBlamedOnTheCredential(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{
		currentErr: errors.New("dial tcp: no route to host"),
		listErr:    errors.New("dial tcp: no route to host"),
	})

	rec := request(t, handler, "/api/inventory", true)
	if got := decode[errorResponse](t, rec).Code; got != codeAPIFailure {
		t.Errorf("code = %q, want %q", got, codeAPIFailure)
	}
}

// The footer names the build, so that a report about the interface names what it was seen
// on rather than leaving it to be guessed.
func TestTheSessionCarriesTheBuildVersion(t *testing.T) {
	got := decode[sessionResponse](t, request(t, newTestServer(t, inventoryFixture()), "/api/session", true)).Version
	if got != testVersion {
		t.Errorf("version = %q, want %q", got, testVersion)
	}
}

// The explorer warns about the rules the audit would flag, which only holds while both read
// the same list. It travels with the session, whole, with every method it names; an empty
// method list has to arrive as a list, since the interface reads it as "every method".
func TestTheSessionCarriesTheSensitiveBranchesOfTheAudit(t *testing.T) {
	got := decode[sessionResponse](t, request(t, newTestServer(t, inventoryFixture()), "/api/session", true)).Sensitive

	if len(got) != len(audit.SensitiveBranches) {
		t.Fatalf("%d branches served, want the %d the audit reads", len(got), len(audit.SensitiveBranches))
	}
	for i, branch := range audit.SensitiveBranches {
		if got[i].Path != branch.Path || got[i].Finding != string(branch.Finding) || !slices.Equal(got[i].Methods, branch.Methods) && len(branch.Methods) > 0 {
			t.Errorf("branch %d = %+v, want %+v", i, got[i], branch)
		}
		if got[i].Methods == nil {
			t.Errorf("branch %s: methods is null, want a list", branch.Path)
		}
	}
}

func TestTheSessionCarriesThePageThatIssuesAManagementKey(t *testing.T) {
	got := decode[sessionResponse](t, request(t, newTestServer(t, inventoryFixture()), "/api/session", true)).ManagementKeyURL

	if !strings.HasPrefix(got, "https://eu.api.ovh.com/createToken/?") {
		t.Fatalf("managementKeyUrl = %q, want the page of the configured region", got)
	}
	for _, rule := range []string{"GET=/me/api/credential", "DELETE=/me/api/credential/*"} {
		if !strings.Contains(got, rule) {
			t.Errorf("the link does not prefill %q", rule)
		}
	}
}

func TestTheInventorySaysWhenAnApplicationIsNotTheAccountsOwn(t *testing.T) {
	provider := &fakeProvider{credentials: []credential.Credential{
		{ID: 1, Status: credential.StatusValidated, Application: credential.Application{ID: 168, Name: "Ovh_Console", External: true}},
		{ID: 2, Status: credential.StatusValidated, Application: credential.Application{ID: 10, Name: "terraform-prod"}},
	}}

	for _, c := range decodeInventory(t, newTestServer(t, provider)).Credentials {
		if want := c.ID == 1; c.Application.External != want {
			t.Errorf("credential %d: external = %v, want %v", c.ID, c.Application.External, want)
		}
	}
}

// An expired key has no findings because the audit does not read it, not because it is
// sound. Counted among the keys with nothing flagged, it made the one reassuring figure on
// screen a key that grants nothing.
//
// A key awaiting validation is read, on the other hand, and always carries at least the
// finding that says so, so it never lands in that figure either.
func TestAnExpiredKeyIsNotCountedAsExaminedAndAPendingOneIs(t *testing.T) {
	provider := &fakeProvider{credentials: []credential.Credential{
		{ID: 1, Status: credential.StatusValidated, Application: credential.Application{Description: "dns"}},
		{ID: 2, Status: credential.StatusExpired},
		{ID: 3, Status: credential.StatusPendingValidation, Application: credential.Application{Description: "dns"}},
	}}

	payload := decodeInventory(t, newTestServer(t, provider))
	if payload.Summary.Total != 3 || payload.Summary.Examined != 2 {
		t.Errorf("total = %d, examined = %d, want 3 and 2", payload.Summary.Total, payload.Summary.Examined)
	}

	for _, c := range payload.Credentials {
		if c.ID != 3 {
			continue
		}
		var codes []string
		for _, finding := range c.Findings {
			codes = append(codes, finding.Code)
		}
		if !slices.Contains(codes, string(audit.PendingValidation)) {
			t.Errorf("the key awaiting validation: findings = %v, want %s", codes, audit.PendingValidation)
		}
	}
}

// A credential the API lists but will not describe leaves the others worth showing. The
// inventory answers with what it could read and says how many are missing.
func TestAPartialListingIsShownWithTheCountOfWhatIsMissing(t *testing.T) {
	provider := &fakeProvider{
		credentials: []credential.Credential{{ID: 1, Status: credential.StatusValidated}},
		listErr:     &credential.IncompleteError{Unreadable: 2, Err: errors.New("unreadable address")},
	}

	rec := request(t, newTestServer(t, provider), "/api/inventory", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	payload := decodeInventory(t, newTestServer(t, provider))
	if len(payload.Credentials) != 1 || payload.Summary.Unreadable != 2 {
		t.Errorf("credentials = %d, unreadable = %d, want 1 and 2", len(payload.Credentials), payload.Summary.Unreadable)
	}
}

// A method a route does not accept is the router's to refuse. Answering 403 for a missing
// token first sent the reader looking for the wrong problem.
func TestAMethodNoRouteAcceptsIsNotReportedAsAMissingToken(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/session", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
}

// Twin keys are the one finding no credential can raise on its own: it takes the whole
// listing to see that two of them are interchangeable, so the inventory is where it is
// attached.
func TestTheInventoryFlagsTwoKeysNothingTellsApart(t *testing.T) {
	same := func(id int64) credential.Credential {
		return credential.Credential{
			ID:          id,
			Status:      credential.StatusValidated,
			Application: credential.Application{ID: 10, Description: "dns"},
			Rules:       []credential.AccessRule{{Method: "GET", Path: "/domain/zone/*"}},
			AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32")},
			ExpiresAt:   time.Now().Add(24 * time.Hour),
			LastUsedAt:  time.Now().Add(-time.Hour),
		}
	}
	alone := same(3)
	alone.Application.ID = 11

	provider := &fakeProvider{credentials: []credential.Credential{same(1), same(2), alone}}
	payload := decodeInventory(t, newTestServer(t, provider))

	flagged := map[int64]bool{}
	for _, c := range payload.Credentials {
		for _, finding := range c.Findings {
			if finding.Code == string(audit.SameAsAnother) {
				flagged[c.ID] = true
			}
		}
	}
	if !flagged[1] || !flagged[2] || flagged[3] {
		t.Errorf("flagged = %v, want the pair and not the key of another application", flagged)
	}
	if got := payload.Summary.Counts[string(audit.SameAsAnother)]; got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
}

// The key the tool runs with is compared with the rules the tool asks for, and only that key:
// any other key is kept for something this process knows nothing about.
func TestTheKeyInUseIsComparedWithWhatTheToolNeeds(t *testing.T) {
	wide := append(slices.Clone(ovh.ManagementRules), credential.AccessRule{Method: "GET", Path: "/cloud/project/*"})
	provider := &fakeProvider{
		current: credential.Credential{ID: 1, Rules: wide},
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated, Rules: wide},
			{ID: 2, Status: credential.StatusValidated, Rules: wide},
		},
	}

	payload := decodeInventory(t, newTestServer(t, provider))
	for _, c := range payload.Credentials {
		flagged := false
		for _, finding := range c.Findings {
			flagged = flagged || finding.Code == string(audit.WiderThanNeeded)
		}

		switch c.ID {
		case 1:
			if !flagged || len(c.Unneeded) != 1 || c.Unneeded[0].Path != "/cloud/project/*" {
				t.Errorf("key in use: flagged = %v, unneeded = %v, want the one extra rule named", flagged, c.Unneeded)
			}
		case 2:
			if flagged || len(c.Unneeded) != 0 {
				t.Errorf("another key: flagged = %v, unneeded = %v, want neither", flagged, c.Unneeded)
			}
		}
	}
}

// A management key issued from the link this tool hands out holds exactly what it needs, and
// says nothing. The list still arrives as a list, since the interface reads its length.
func TestAManagementKeyWithExactlyTheNeededRulesIsNotFlagged(t *testing.T) {
	provider := &fakeProvider{
		current:     credential.Credential{ID: 1, Rules: ovh.ManagementRules},
		credentials: []credential.Credential{{ID: 1, Status: credential.StatusValidated, Rules: ovh.ManagementRules}},
	}

	rec := request(t, newTestServer(t, provider), "/api/inventory", true)
	if !strings.Contains(rec.Body.String(), `"unneeded":[]`) {
		t.Errorf("unneeded is not an empty list: %s", rec.Body.String())
	}
	for _, c := range decode[inventoryResponse](t, rec).Credentials {
		for _, finding := range c.Findings {
			if finding.Code == string(audit.WiderThanNeeded) {
				t.Errorf("findings = %v, want no %s", c.Findings, audit.WiderThanNeeded)
			}
		}
	}
}

// A key whose application was deleted is still listed as validated, but opens nothing. The
// interface is told so, the summary does not count it among the keys the audit read, and
// nothing but its revocation is offered.
func TestAKeyWhoseApplicationWasDeletedIsReportedAsSuch(t *testing.T) {
	provider := &fakeProvider{
		current: credential.Credential{ID: 1, Status: credential.StatusValidated, Rules: ovh.UsableRules()},
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated, Rules: ovh.UsableRules(), Application: credential.Application{ID: 7, Name: "keymaker"}},
			{ID: 2, Status: credential.StatusValidated, Application: credential.Application{ID: 476522, Deleted: true}},
		},
	}
	payload := decodeInventory(t, newTestServer(t, provider))

	if payload.Summary.Examined != 1 {
		t.Errorf("examined = %d, want 1", payload.Summary.Examined)
	}
	for _, c := range payload.Credentials {
		if c.ID != 2 {
			continue
		}
		if !c.Application.Deleted {
			t.Error("the application is not reported as deleted")
		}
		if len(c.Findings) != 0 {
			t.Errorf("findings = %v, want none", c.Findings)
		}
		if !c.Revoke.Allowed {
			t.Errorf("revocation = %+v, want it offered", c.Revoke)
		}
		if c.EditAddresses != (offerResponse{Reason: reasonInactive}) {
			t.Errorf("address editor = %+v, want it left out as inactive", c.EditAddresses)
		}
	}
}
