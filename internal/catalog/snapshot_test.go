// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"slices"
	"testing"
	"time"
)

func TestTheEmbeddedCatalogueDecodesAndCoversTheAPI(t *testing.T) {
	snapshot, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	if snapshot.Live {
		t.Error("the embedded catalogue reports itself as live")
	}
	if snapshot.Taken.IsZero() {
		t.Error("the embedded catalogue carries no date, so the interface cannot say how old it is")
	}
	if len(snapshot.Routes) < 1000 {
		t.Fatalf("routes = %d, want the whole API; the snapshot looks truncated", len(snapshot.Routes))
	}
	if len(snapshot.Branches) < 50 {
		t.Errorf("branches = %d, want the index of the API; the explorer offers them as a filter", len(snapshot.Branches))
	}
	if !slices.Contains(snapshot.Branches, "/me") {
		t.Error("/me is missing from the branches, and it is the one every key of this tool lives under")
	}
}

func TestTheEmbeddedCatalogueKnowsTheRoutesThisProjectUses(t *testing.T) {
	snapshot, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}

	methods := make(map[string][]string, len(snapshot.Routes))
	for _, route := range snapshot.Routes {
		for _, op := range route.Operations {
			methods[route.Path] = append(methods[route.Path], op.Method)
		}
	}

	// The endpoints the tool itself calls. A snapshot that does not describe the routes
	// the tool itself calls is one nobody could have built a management key from.
	for _, want := range []struct {
		path   string
		method string
	}{
		{"/auth/credential", "POST"},
		{"/auth/currentCredential", "GET"},
		{"/me/api/credential", "GET"},
		{"/me/api/credential/{credentialId}", "GET"},
		{"/me/api/credential/{credentialId}", "DELETE"},
		{"/me/api/credential/{credentialId}/application", "GET"},
		{"/me/api/application", "GET"},
		{"/me/api/application/{applicationId}", "GET"},
	} {
		if !slices.Contains(methods[want.path], want.method) {
			t.Errorf("%s %s is missing from the embedded catalogue", want.method, want.path)
		}
	}
}

func TestTheEmbeddedCatalogueIsRecentEnoughToBeWorthShipping(t *testing.T) {
	snapshot, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}

	// The snapshot is a fallback, not a source of truth, so age is not a failure. It is
	// worth saying out loud during a release, though, because the interface shows the
	// date to the user.
	if age := time.Since(snapshot.Taken); age > 365*24*time.Hour {
		t.Logf("the embedded catalogue is %d days old; regenerate it with go run ./tools/snapshotgen",
			int(age.Hours()/24))
	}
}
