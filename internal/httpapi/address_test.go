// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/kentrow/keymaker/internal/publicip"
)

type fakeResolver struct {
	address netip.Addr
	err     error
}

func (f fakeResolver) Address(context.Context) (netip.Addr, error) {
	return f.address, f.err
}

func (f fakeResolver) Enabled() bool { return true }

func serverResolving(t *testing.T, resolver publicip.Resolver) http.Handler {
	t.Helper()
	return New(Options{
		Provider: &fakeProvider{},
		Catalog:  fixedCatalog{},
		Resolver: resolver,
		Assets:   emptyAssets(),
		Logger:   discardLogger(),
		Token:    testToken,
		CSRF:     testCSRF,
		Endpoint: "ovh-eu",
	})
}

func TestTheAddressIsAnsweredWhenAsked(t *testing.T) {
	handler := serverResolving(t, fakeResolver{address: netip.MustParseAddr("203.0.113.7")})

	rec := request(t, handler, "/api/address", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := decode[addressResponse](t, rec).Address; got != "203.0.113.7" {
		t.Errorf("address = %q", got)
	}
}

func TestAnInstanceWithTheLookupOffSaysSo(t *testing.T) {
	rec := request(t, serverResolving(t, publicip.Disabled{}), "/api/address", true)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if got := decode[errorResponse](t, rec).Code; got != codeLookupDisabled {
		t.Errorf("code = %q, want %q", got, codeLookupDisabled)
	}
}

func TestAFailedLookupIsReportedWithoutItsDetail(t *testing.T) {
	handler := serverResolving(t, fakeResolver{err: errors.New("dial tcp 198.51.100.34:443: connect: refused")})

	rec := request(t, handler, "/api/address", true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadGateway)
	}
	if got := decode[errorResponse](t, rec).Code; got != codeLookupFailed {
		t.Errorf("code = %q, want %q", got, codeLookupFailed)
	}
	if strings.Contains(rec.Body.String(), "198.51.100.34") {
		t.Error("the answer repeats what the resolver said; the detail belongs to the log")
	}
}
