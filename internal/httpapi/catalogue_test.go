// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func fetchCatalogue(t *testing.T, handler http.Handler) catalogueResponse {
	t.Helper()

	rec := request(t, handler, "/api/catalogue", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	var payload catalogueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decoding the catalogue: %v", err)
	}
	return payload
}

func TestTheCatalogueNeedsTheAccessToken(t *testing.T) {
	handler := newTestServer(t, &fakeProvider{})

	if got := request(t, handler, "/api/catalogue", false).Code; got != http.StatusUnauthorized {
		t.Errorf("status without a session = %d, want %d", got, http.StatusUnauthorized)
	}
}

func TestTheCatalogueCarriesTheRuleFormOfEachRoute(t *testing.T) {
	payload := fetchCatalogue(t, newTestServer(t, &fakeProvider{}))

	byPath := make(map[string]catalogueRoute, len(payload.Routes))
	for _, route := range payload.Routes {
		byPath[route.Path] = route
	}

	parametric, ok := byPath["/me/api/credential/{credentialId}"]
	if !ok {
		t.Fatal("the parameterised route is missing from the response")
	}
	if parametric.Rule != "/me/api/credential/*" {
		t.Errorf("rule = %q, want the parameter replaced by a wildcard", parametric.Rule)
	}
	if !parametric.Wildcard {
		t.Error("the route widens into a wildcard and does not say so")
	}

	fixed, ok := byPath["/me"]
	if !ok {
		t.Fatal("the fixed route is missing from the response")
	}
	if fixed.Rule != "/me" || fixed.Wildcard {
		t.Errorf("route = %+v, want a rule identical to the path and no widening", fixed)
	}
}

func TestTheCatalogueOffersTheBranchesOfTheAPI(t *testing.T) {
	payload := fetchCatalogue(t, newTestServer(t, &fakeProvider{}))

	if len(payload.Branches) != 1 || payload.Branches[0] != "/me" {
		t.Errorf("branches = %v, want the index as the API lists it", payload.Branches)
	}
}

func TestTheCatalogueCarriesWhatEachOperationDoes(t *testing.T) {
	payload := fetchCatalogue(t, newTestServer(t, &fakeProvider{}))

	for _, route := range payload.Routes {
		if route.Path != "/me/api/credential/{credentialId}" {
			continue
		}
		if len(route.Operations) != 2 {
			t.Fatalf("operations = %d, want 2", len(route.Operations))
		}
		for _, op := range route.Operations {
			if op.Description == "" {
				t.Errorf("%s carries no description, which is what the explorer shows", op.Method)
			}
			if op.Method == "DELETE" && !op.Deprecated {
				t.Error("a deprecated operation is served as current")
			}
			if op.Method == "GET" && op.Deprecated {
				t.Error("a current operation is served as deprecated")
			}
		}
		return
	}
	t.Fatal("the route under test is missing from the response")
}

func TestTheInterfaceIsToldWhetherTheCatalogueIsLive(t *testing.T) {
	if live := fetchCatalogue(t, newTestServer(t, &fakeProvider{})); !live.Live {
		t.Error("a live catalogue is reported as a snapshot")
	}

	taken := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	stale := fetchCatalogue(t, newTestServerWithCatalog(t, fixedCatalog{Taken: taken}))
	if stale.Live {
		t.Error("the embedded snapshot is reported as live")
	}
	if !stale.Taken.Equal(taken) {
		t.Errorf("taken = %s, want %s so the interface can name the age of the fallback", stale.Taken, taken)
	}
}
