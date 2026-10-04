// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"slices"
	"strings"
	"testing"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/credential"
)

// A branch written with a typo protects nothing and fails nowhere: the audit simply never
// raises it. Every entry is held against the published catalogue shipped with the build, for
// its path and for each method it names. The ovh-eu catalogue is the reference: it publishes
// every product the other regions do, and a branch a smaller region lacks is simply one the
// audit never raises there.
func TestEverySensitiveBranchExistsInTheCatalogue(t *testing.T) {
	snapshot, err := catalog.Embedded("ovh-eu")
	if err != nil {
		t.Fatalf("read the embedded catalogue: %v", err)
	}

	for _, branch := range SensitiveBranches {
		methods := map[string]bool{}
		for _, route := range snapshot.Routes {
			if !within(route.Path, branch.Path) {
				continue
			}
			for _, operation := range route.Operations {
				methods[strings.ToUpper(operation.Method)] = true
			}
		}

		if len(methods) == 0 {
			t.Errorf("%s is listed as sensitive and the catalogue has no route under it", branch.Path)
			continue
		}
		for _, method := range branch.Methods {
			if !methods[method] {
				t.Errorf("%s is listed as sensitive for %s and the catalogue offers no %s under it", branch.Path, method, method)
			}
		}
	}
}

func TestABranchIsReachedByTheRulesThatCoverIt(t *testing.T) {
	identity := Branch{Finding: AccountControl, Path: "/me/identity", Methods: writes}
	bill := Branch{Finding: BillingAccess, Path: "/me/bill"}

	cases := []struct {
		branch Branch
		rule   credential.AccessRule
		want   bool
	}{
		{identity, credential.AccessRule{Method: "POST", Path: "/me/identity/user"}, true},
		{identity, credential.AccessRule{Method: "POST", Path: "/me/identity/user/*"}, true},
		{identity, credential.AccessRule{Method: "POST", Path: "/me/identity/*"}, true},
		{identity, credential.AccessRule{Method: "POST", Path: "/me/i*"}, true},
		{identity, credential.AccessRule{Method: "post", Path: "/me/identity/user"}, true},

		// Reading the users is not a way in; only a write is.
		{identity, credential.AccessRule{Method: "GET", Path: "/me/identity/user"}, false},
		{identity, credential.AccessRule{Method: "POST", Path: "/me/identityProvider"}, false},
		{identity, credential.AccessRule{Method: "POST", Path: "/me/api/*"}, false},

		// Every method counts on money, reading included.
		{bill, credential.AccessRule{Method: "GET", Path: "/me/bill"}, true},
		{bill, credential.AccessRule{Method: "GET", Path: "/me/bill/*/details"}, true},
		{bill, credential.AccessRule{Method: "GET", Path: "/me/b*"}, true},

		// /me/billing is a branch of its own, not a part of /me/bill.
		{bill, credential.AccessRule{Method: "GET", Path: "/me/billing/group"}, false},
		{bill, credential.AccessRule{Method: "GET", Path: "/me/contact/*"}, false},
	}

	for _, c := range cases {
		if got := c.branch.Reaches(c.rule); got != c.want {
			t.Errorf("%s reached by %s %s = %v, want %v", c.branch.Path, c.rule.Method, c.rule.Path, got, c.want)
		}
	}
}

// The management key Keymaker runs with reads and revokes keys and applications. That is
// what it is for, and a finding raised on every management key would soon be read as noise.
func TestReadingAndRevokingKeysIsNotAccountControl(t *testing.T) {
	c := wellKept()
	c.Rules = []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential"},
		{Method: "GET", Path: "/me/api/credential/*"},
		{Method: "GET", Path: "/me/api/application"},
		{Method: "GET", Path: "/me/api/application/*"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
		{Method: "DELETE", Path: "/me/api/application/*"},
	}

	if got := codes(Inspect(c, now)); slices.Contains(got, AccountControl) {
		t.Errorf("findings = %v, want no %s", got, AccountControl)
	}
}

// Changing the addresses another key accepts changes who can use that key, which is what
// the finding is about, even though the route sits beside the ones the management key uses.
func TestEditingTheAddressesOfKeysIsAccountControl(t *testing.T) {
	c := wellKept()
	c.Rules = []credential.AccessRule{{Method: "PUT", Path: "/me/api/credential/*"}}

	if got := codes(Inspect(c, now)); !slices.Contains(got, AccountControl) {
		t.Errorf("findings = %v, want %s", got, AccountControl)
	}
}

// A broad rule reaches every sensitive branch and already says so, at the highest
// severity. Repeating it twice more on the same card adds nothing.
func TestABroadRuleIsNotAlsoReportedBranchByBranch(t *testing.T) {
	c := wellKept()
	c.Rules = []credential.AccessRule{{Method: "POST", Path: "/me/*"}}

	got := codes(Inspect(c, now))
	if !slices.Contains(got, BroadAccess) {
		t.Fatalf("findings = %v, want %s", got, BroadAccess)
	}
	for _, unwanted := range []Code{AccountControl, BillingAccess} {
		if slices.Contains(got, unwanted) {
			t.Errorf("findings = %v, want no %s beside %s", got, unwanted, BroadAccess)
		}
	}
}
