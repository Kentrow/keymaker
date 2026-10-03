// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
	"github.com/kentrow/keymaker/internal/publicip"
)

const seenFrom = "198.51.100.7"

// addressFixture is an account whose management key, 2, holds the address rule, beside a
// key in use, 1, and an expired one, 3.
func addressFixture() *fakeProvider {
	management := credential.Credential{ID: 2, Status: credential.StatusValidated, Rules: ovh.UsableRules()}
	return &fakeProvider{
		current: management,
		credentials: []credential.Credential{
			{ID: 1, Status: credential.StatusValidated},
			management,
			{ID: 3, Status: credential.StatusExpired},
		},
	}
}

func addressServer(t *testing.T, provider credential.Provider, resolver publicip.Resolver) http.Handler {
	t.Helper()
	return New(Options{
		Provider: provider,
		Catalog:  fixedCatalog{},
		Resolver: resolver,
		Assets:   emptyAssets(),
		Logger:   discardLogger(),
		Token:    testToken,
		CSRF:     testCSRF,
		Endpoint: "ovh-eu",
	})
}

func seen() fakeResolver {
	return fakeResolver{address: netip.MustParseAddr(seenFrom)}
}

// sendAddresses previews the list, or writes it when apply is set.
func sendAddresses(t *testing.T, handler http.Handler, id int64, body string, apply bool) *httptest.ResponseRecorder {
	t.Helper()

	method, target := http.MethodPost, "/api/credentials/"+strconv.FormatInt(id, 10)+"/addresses/preview"
	if apply {
		method, target = http.MethodPut, "/api/credentials/"+strconv.FormatInt(id, 10)+"/addresses"
	}
	req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})
	req.Header.Set(csrfHeader, testCSRF)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// The API refuses a bare address and stores host bits and repeats as sent, so the list is
// put in the form it will be stored in before anyone confirms it.
func TestTheListIsShownAsItWillBeStored(t *testing.T) {
	provider := addressFixture()
	handler := addressServer(t, provider, seen())

	rec := sendAddresses(t, handler, 1, `{"addresses":["192.0.2.7","198.51.100.7/24, 198.51.100.0/24","2001:db8::1\n"]}`, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	want := []string{"192.0.2.7/32", "198.51.100.0/24", "2001:db8::1/128"}
	if got := decode[addressesResponse](t, rec).Addresses; !slices.Equal(got, want) {
		t.Errorf("addresses = %v, want %v", got, want)
	}
	if len(provider.addressed) != 0 {
		t.Errorf("a preview wrote %v", provider.addressed)
	}
}

func TestTheListIsWrittenOnlyWhenApplied(t *testing.T) {
	provider := addressFixture()
	handler := addressServer(t, provider, seen())

	rec := sendAddresses(t, handler, 1, `{"addresses":["192.0.2.7"]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}
	if got := provider.addressed[1]; !slices.Equal(got, want) {
		t.Errorf("written = %v, want %v", got, want)
	}
}

// An empty list lifts the restriction, which the reader is allowed to choose.
func TestAnEmptyListLiftsTheRestriction(t *testing.T) {
	provider := addressFixture()

	rec := sendAddresses(t, addressServer(t, provider, seen()), 1, `{"addresses":[]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got, ok := provider.addressed[1]; !ok || len(got) != 0 {
		t.Errorf("written = %v (%v), want an empty list", got, ok)
	}
}

func TestAListTheAPIWouldRefuseIsRefusedHere(t *testing.T) {
	cases := map[string]struct {
		body, code, entry string
	}{
		"not an address":   {`{"addresses":["192.0.2.7","nas.example"]}`, codeBadAddress, "nas.example"},
		"a zone":           {`{"addresses":["fe80::1%eth0"]}`, codeBadAddress, "fe80::1%eth0"},
		"every IPv4":       {`{"addresses":["0.0.0.0/0"]}`, codeAnyAddressBlock, "0.0.0.0/0"},
		"every IPv6":       {`{"addresses":["::/0"]}`, codeAnyAddressBlock, "::/0"},
		"too many":         {`{"addresses":["` + strings.Repeat("192.0.2.1 ", maxAddresses+1) + `"]}`, codeTooManyAddresses, ""},
		"an unknown field": {`{"addresses":[],"expiration":"2027-01-01"}`, codeBadAddress, ""},
		"not an object":    {`[`, codeBadAddress, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			provider := addressFixture()
			rec := sendAddresses(t, addressServer(t, provider, seen()), 1, c.body, true)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			got := decode[addressRefusal](t, rec)
			if got.Code != c.code || got.Entry != c.entry {
				t.Errorf("refusal = %s %q, want %s %q", got.Code, got.Entry, c.code, c.entry)
			}
			if len(provider.addressed) != 0 {
				t.Errorf("a refused list was written: %v", provider.addressed)
			}
		})
	}
}

func TestOnlyAUsableKeyIsEdited(t *testing.T) {
	cases := map[int64]struct {
		status int
		code   string
	}{
		3:  {http.StatusConflict, codeInactive},
		99: {http.StatusNotFound, codeAlreadyRevoked},
	}
	for id, want := range cases {
		provider := addressFixture()
		rec := sendAddresses(t, addressServer(t, provider, seen()), id, `{"addresses":["192.0.2.7"]}`, true)

		if rec.Code != want.status || decode[errorResponse](t, rec).Code != want.code {
			t.Errorf("key %d: %d %s, want %d %s", id, rec.Code, rec.Body.String(), want.status, want.code)
		}
		if len(provider.addressed) != 0 {
			t.Errorf("key %d was written: %v", id, provider.addressed)
		}
	}
}

// A list that leaves out the address the tool is seen from locks it out for good: the key
// can then make no call at all, the one that would undo the change included.
func TestTheKeyInUseIsNeverLockedOut(t *testing.T) {
	provider := addressFixture()
	handler := addressServer(t, provider, seen())

	rec := sendAddresses(t, handler, 2, `{"addresses":["192.0.2.0/24"]}`, true)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if got := decode[addressRefusal](t, rec); got.Code != codeSelfLockout || got.Entry != seenFrom {
		t.Errorf("refusal = %s %q, want %s %q", got.Code, got.Entry, codeSelfLockout, seenFrom)
	}
	if len(provider.addressed) != 0 {
		t.Fatalf("the lockout was written: %v", provider.addressed)
	}

	rec = sendAddresses(t, handler, 2, `{"addresses":["192.0.2.0/24","198.51.100.0/24"]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("a list covering the address: status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := decode[addressesResponse](t, rec).SeenFrom; got != seenFrom {
		t.Errorf("seenFrom = %q, want %q", got, seenFrom)
	}
	if _, ok := provider.addressed[2]; !ok {
		t.Error("a list covering the address was not written")
	}
}

// Without the lookup there is nothing to check a restriction against, so none is put on the
// key in use. Lifting it cannot lock anything out and stays possible.
func TestTheKeyInUseIsNotRestrictedBlind(t *testing.T) {
	provider := addressFixture()
	handler := addressServer(t, provider, publicip.Disabled{})

	rec := sendAddresses(t, handler, 2, `{"addresses":["198.51.100.7"]}`, true)
	if rec.Code != http.StatusConflict || decode[errorResponse](t, rec).Code != codeSelfLookupOff {
		t.Fatalf("status = %d: %s, want %d %s", rec.Code, rec.Body.String(), http.StatusConflict, codeSelfLookupOff)
	}
	if len(provider.addressed) != 0 {
		t.Fatalf("written without a lookup: %v", provider.addressed)
	}

	if rec := sendAddresses(t, handler, 2, `{"addresses":[]}`, true); rec.Code != http.StatusOK {
		t.Errorf("lifting the restriction: status = %d: %s", rec.Code, rec.Body.String())
	}
	if rec := sendAddresses(t, handler, 1, `{"addresses":["192.0.2.7"]}`, true); rec.Code != http.StatusOK {
		t.Errorf("another key: status = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAFailedLookupWritesNothing(t *testing.T) {
	provider := addressFixture()
	handler := addressServer(t, provider, fakeResolver{err: errors.New("timeout")})

	rec := sendAddresses(t, handler, 2, `{"addresses":["198.51.100.7"]}`, true)
	if rec.Code != http.StatusBadGateway || decode[errorResponse](t, rec).Code != codeLookupFailed {
		t.Errorf("status = %d: %s, want %d %s", rec.Code, rec.Body.String(), http.StatusBadGateway, codeLookupFailed)
	}
	if len(provider.addressed) != 0 {
		t.Errorf("written after a failed lookup: %v", provider.addressed)
	}
}

// Without knowing which key it runs with, the tool cannot tell whether a list locks it out.
func TestNothingIsWrittenWithoutTheIdentity(t *testing.T) {
	provider := addressFixture()
	provider.currentErr = credential.ErrPermissionDenied

	rec := sendAddresses(t, addressServer(t, provider, seen()), 1, `{"addresses":["192.0.2.7"]}`, true)
	if rec.Code != http.StatusBadGateway || decode[errorResponse](t, rec).Code != codeIdentityUnknown {
		t.Errorf("status = %d: %s, want %d %s", rec.Code, rec.Body.String(), http.StatusBadGateway, codeIdentityUnknown)
	}
	if len(provider.addressed) != 0 {
		t.Errorf("written without the identity: %v", provider.addressed)
	}
}

func TestARefusedChangeIsNamedAsSuch(t *testing.T) {
	provider := addressFixture()
	provider.addressErr = credential.ErrPermissionDenied

	rec := sendAddresses(t, addressServer(t, provider, seen()), 1, `{"addresses":["192.0.2.7"]}`, true)
	if rec.Code != http.StatusForbidden || decode[errorResponse](t, rec).Code != codePermissionDenied {
		t.Errorf("status = %d: %s, want %d %s", rec.Code, rec.Body.String(), http.StatusForbidden, codePermissionDenied)
	}
}

func TestChangingAddressesNeedsTheToken(t *testing.T) {
	provider := addressFixture()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/credentials/1/addresses", strings.NewReader(`{"addresses":[]}`))
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: testToken})

	rec := httptest.NewRecorder()
	addressServer(t, provider, seen()).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || len(provider.addressed) != 0 {
		t.Errorf("status = %d, written %v, want %d and nothing written", rec.Code, provider.addressed, http.StatusForbidden)
	}
}

func TestTheInventorySaysWhereTheEditorIsOffered(t *testing.T) {
	offers := func(provider *fakeProvider, resolver publicip.Resolver) map[int64]offerResponse {
		rec := request(t, addressServer(t, provider, resolver), "/api/inventory", true)
		out := map[int64]offerResponse{}
		for _, c := range decode[inventoryResponse](t, rec).Credentials {
			out[c.ID] = c.EditAddresses
		}
		return out
	}

	got := offers(addressFixture(), seen())
	want := map[int64]offerResponse{1: {Allowed: true}, 2: {Allowed: true}, 3: {Reason: reasonInactive}}
	for id, offer := range want {
		if got[id] != offer {
			t.Errorf("key %d: offer = %+v, want %+v", id, got[id], offer)
		}
	}

	if got := offers(addressFixture(), publicip.Disabled{}); got[2] != (offerResponse{Reason: reasonLookupOff}) || !got[1].Allowed {
		t.Errorf("without the lookup: %+v, want the key in use alone left out", got)
	}

	withoutRule := addressFixture()
	withoutRule.editable = func(credential.Credential, credential.Credential) bool { return false }
	if got := offers(withoutRule, seen()); got[1] != (offerResponse{Reason: reasonMissingRule}) {
		t.Errorf("without the rule: %+v, want %s", got[1], reasonMissingRule)
	}
}

// The address rule is one the tool uses, so a management key holding it is not told it holds
// more than it needs.
func TestTheAddressRuleIsNotWiderThanNeeded(t *testing.T) {
	rec := request(t, addressServer(t, addressFixture(), seen()), "/api/inventory", true)
	for _, c := range decode[inventoryResponse](t, rec).Credentials {
		if c.ID == 2 && len(c.Unneeded) != 0 {
			t.Errorf("unneeded = %v, want none", c.Unneeded)
		}
	}
}
