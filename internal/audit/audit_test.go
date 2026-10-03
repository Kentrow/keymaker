// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/kentrow/keymaker/internal/credential"
)

var now = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

// wellKept raises nothing: scoped rules, an IP restriction, an expiry, recent use and a
// described application.
func wellKept() credential.Credential {
	return credential.Credential{
		ID:          1,
		Status:      credential.StatusValidated,
		Application: credential.Application{Name: "dns-acme", Description: "certbot on the web servers"},
		Rules:       []credential.AccessRule{{Method: "GET", Path: "/domain/zone/*"}},
		AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32")},
		CreatedAt:   now.Add(-365 * 24 * time.Hour),
		ExpiresAt:   now.Add(90 * 24 * time.Hour),
		LastUsedAt:  now.Add(-2 * time.Hour),
	}
}

func codes(findings []Finding) []Code {
	out := make([]Code, 0, len(findings))
	for _, finding := range findings {
		out = append(out, finding.Code)
	}
	return out
}

func TestAWellKeptKeyRaisesNothing(t *testing.T) {
	if got := Inspect(wellKept(), now); len(got) != 0 {
		t.Errorf("findings = %v, want none", codes(got))
	}
}

func TestEachFindingIsRaisedOnItsOwn(t *testing.T) {
	cases := map[Code]func(c *credential.Credential){
		NoIPRestriction: func(c *credential.Credential) { c.AllowedIPs = nil },
		NoExpiry:        func(c *credential.Credential) { c.ExpiresAt = time.Time{} },
		NoDescription:   func(c *credential.Credential) { c.Application.Description = "   " },
		Dormant:         func(c *credential.Credential) { c.LastUsedAt = now.Add(-200 * 24 * time.Hour) },
		NeverUsed:       func(c *credential.Credential) { c.LastUsedAt = time.Time{} },
		BroadAccess:     func(c *credential.Credential) { c.Rules = []credential.AccessRule{{Method: "GET", Path: "/*"}} },
		SupportIssued:   func(c *credential.Credential) { c.IssuedBySupport = true },
		ExpiresSoon:     func(c *credential.Credential) { c.ExpiresAt = now.Add(5 * 24 * time.Hour) },
		AccountControl: func(c *credential.Credential) {
			c.Rules = []credential.AccessRule{{Method: "POST", Path: "/me/identity/user"}}
		},
		BillingAccess: func(c *credential.Credential) { c.Rules = []credential.AccessRule{{Method: "GET", Path: "/me/bill"}} },
	}

	for code, break_ := range cases {
		t.Run(string(code), func(t *testing.T) {
			c := wellKept()
			break_(&c)

			got := codes(Inspect(c, now))
			if !slices.Contains(got, code) {
				t.Fatalf("findings = %v, want %s", got, code)
			}
			if len(got) != 1 {
				t.Errorf("findings = %v, want %s alone", got, code)
			}
		})
	}
}

// A key issued days ago has not had the chance to be used yet.
func TestAFreshKeyIsNotReportedAsNeverUsed(t *testing.T) {
	c := wellKept()
	c.LastUsedAt = time.Time{}
	c.CreatedAt = now.Add(-3 * 24 * time.Hour)

	if got := codes(Inspect(c, now)); slices.Contains(got, NeverUsed) {
		t.Errorf("findings = %v, want no %s", got, NeverUsed)
	}
}

func TestBroadAccessLooksAtTheFixedPartOfThePath(t *testing.T) {
	broad := []string{"/*", "*", "/me/*", "/me*"}
	// Without a wildcard a rule names one route, however short its path is.
	scoped := []string{"/domain/zone/*", "/me", "/me/", "/me/api/credential", "/me/api/credential/*", "/dedicated/server/*"}

	for _, path := range broad {
		c := wellKept()
		c.Rules = []credential.AccessRule{{Method: "GET", Path: path}}
		if !slices.Contains(codes(Inspect(c, now)), BroadAccess) {
			t.Errorf("%q was not reported as broad", path)
		}
	}
	for _, path := range scoped {
		c := wellKept()
		c.Rules = []credential.AccessRule{{Method: "GET", Path: path}}
		if slices.Contains(codes(Inspect(c, now)), BroadAccess) {
			t.Errorf("%q was reported as broad", path)
		}
	}
}

// The API accepts a block of length zero, and a key restricted to it answers from anywhere.
func TestABlockOfLengthZeroRestrictsNothing(t *testing.T) {
	open := [][]string{{"0.0.0.0/0"}, {"::/0"}, {"203.0.113.4/32", "0.0.0.0/0"}}
	restricted := [][]string{{"203.0.113.0/24"}, {"2001:db8::/32", "203.0.113.4/32"}, {"128.0.0.0/1"}}

	for _, blocks := range open {
		c := wellKept()
		c.AllowedIPs = prefixes(blocks)
		if !slices.Contains(codes(Inspect(c, now)), NoIPRestriction) {
			t.Errorf("%v was taken for a restriction", blocks)
		}
	}
	for _, blocks := range restricted {
		c := wellKept()
		c.AllowedIPs = prefixes(blocks)
		if slices.Contains(codes(Inspect(c, now)), NoIPRestriction) {
			t.Errorf("%v was not taken for a restriction", blocks)
		}
	}
}

func prefixes(blocks []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(blocks))
	for _, block := range blocks {
		out = append(out, netip.MustParsePrefix(block))
	}
	return out
}

// An expired or refused key grants nothing, so reporting on it would be noise.
func TestOnlyUsableKeysAreExamined(t *testing.T) {
	for _, status := range []credential.Status{credential.StatusExpired, credential.StatusRefused} {
		c := wellKept()
		c.Status = status
		c.AllowedIPs = nil
		c.ExpiresAt = time.Time{}

		if got := Inspect(c, now); len(got) != 0 {
			t.Errorf("%s: findings = %v, want none", status, codes(got))
		}
	}
}

// The API keeps a key listed as validated after its application is deleted, but refuses every
// call made with it. Read as live, it would be reported for its address and expiry while it can
// do nothing, and counted among the keys nothing is wrong with.
func TestAKeyWhoseApplicationWasDeletedIsNotExamined(t *testing.T) {
	c := wellKept()
	c.Application.Deleted = true
	c.AllowedIPs = nil

	if Examines(c) {
		t.Error("a key whose application was deleted is examined")
	}
	if got := Inspect(c, now); len(got) != 0 {
		t.Errorf("findings = %v, want none", codes(got))
	}

	twin := c
	twin.ID = 2
	if got := Twins([]credential.Credential{c, twin}); len(got) != 0 {
		t.Errorf("twins = %v, want none", got)
	}
}

// A key nobody validated opens nothing yet, and an inventory of keys is where anyone would
// look for it. It is read rather than skipped, so that the account holder knows what sits
// there waiting for one click.
func TestAKeyAwaitingValidationIsFlagged(t *testing.T) {
	c := wellKept()
	c.Status = credential.StatusPendingValidation

	got := codes(Inspect(c, now))
	if !slices.Contains(got, PendingValidation) {
		t.Fatalf("findings = %v, want %s", got, PendingValidation)
	}
	if !Examines(c) {
		t.Error("Examines = false, so the key would be counted as unexamined")
	}
}

// What a key awaiting validation has never done says nothing about it: it could not have
// been used. Reporting it as never used would be noise on every single one of them.
func TestAKeyAwaitingValidationIsNotReportedAsUnused(t *testing.T) {
	c := wellKept()
	c.Status = credential.StatusPendingValidation
	c.LastUsedAt = time.Time{}
	c.CreatedAt = now.Add(-400 * 24 * time.Hour)

	got := codes(Inspect(c, now))
	for _, unwanted := range []Code{NeverUsed, Dormant} {
		if slices.Contains(got, unwanted) {
			t.Errorf("findings = %v, want no %s", got, unwanted)
		}
	}
}

// What it would be allowed to do the moment someone validates it is worth knowing before
// that happens, which is the whole reason it is examined at all.
func TestAKeyAwaitingValidationStillReportsWhatItWouldAllow(t *testing.T) {
	c := wellKept()
	c.Status = credential.StatusPendingValidation
	c.Rules = []credential.AccessRule{{Method: "GET", Path: "/*"}}

	if got := codes(Inspect(c, now)); !slices.Contains(got, BroadAccess) {
		t.Errorf("findings = %v, want %s", got, BroadAccess)
	}
}

func TestSummaryCountsCredentialsPerFinding(t *testing.T) {
	risky := wellKept()
	risky.Rules = []credential.AccessRule{{Method: "GET", Path: "/me/*"}}
	risky.AllowedIPs = nil

	lax := wellKept()
	lax.ExpiresAt = time.Time{}

	summary := Summarise([][]Finding{
		Inspect(risky, now),
		Inspect(lax, now),
		Inspect(wellKept(), now),
	})

	if summary.Flagged != 2 {
		t.Errorf("Flagged = %d, want 2", summary.Flagged)
	}
	if summary.AtRisk != 1 {
		t.Errorf("AtRisk = %d, want 1", summary.AtRisk)
	}
	// The risky key raises broad access and no IP restriction; counting must not stop at
	// the first one.
	if summary.Counts[BroadAccess] != 1 {
		t.Errorf("broad access = %d, want 1", summary.Counts[BroadAccess])
	}
	if summary.Counts[NoIPRestriction] != 1 {
		t.Errorf("no IP restriction = %d, want 1", summary.Counts[NoIPRestriction])
	}
	if summary.Counts[NoExpiry] != 1 {
		t.Errorf("no expiry = %d, want 1", summary.Counts[NoExpiry])
	}
}

// twin builds a credential of the given identity: same application, same rules and same
// addresses as its sibling unless a case changes one of them.
func twin(id int64) credential.Credential {
	c := wellKept()
	c.ID = id
	c.Application = credential.Application{ID: 10, Name: "dns-acme", Description: "certbot"}
	return c
}

func TestTwinsFindKeysNothingTellsApart(t *testing.T) {
	got := Twins([]credential.Credential{twin(1), twin(2), func() credential.Credential {
		other := twin(3)
		other.Application.ID = 11
		return other
	}()})

	if !got[1] || !got[2] {
		t.Errorf("twins = %v, want 1 and 2 paired", got)
	}
	if got[3] {
		t.Errorf("twins = %v, want the key of another application left out", got)
	}
}

// The API returns both lists in the order it pleases, and two keys created the same way
// would otherwise look different for no reason.
func TestTwinsIgnoreTheOrderOfRulesAndAddresses(t *testing.T) {
	first, second := twin(1), twin(2)
	first.Rules = []credential.AccessRule{
		{Method: "GET", Path: "/domain/zone/*"},
		{Method: "POST", Path: "/domain/zone/*/record"},
	}
	second.Rules = []credential.AccessRule{
		{Method: "POST", Path: "/domain/zone/*/record"},
		{Method: "GET", Path: "/domain/zone/*"},
	}
	first.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.4/32"), netip.MustParsePrefix("203.0.113.9/32")}
	second.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32"), netip.MustParsePrefix("203.0.113.4/32")}

	if got := Twins([]credential.Credential{first, second}); !got[1] || !got[2] {
		t.Errorf("twins = %v, want both", got)
	}
}

// One rule apart, or one address apart, and the two keys are not interchangeable: whichever
// is dropped, something loses an access.
func TestTwinsRequireEveryRuleAndAddressToMatch(t *testing.T) {
	cases := map[string]func(c *credential.Credential){
		"one rule more": func(c *credential.Credential) {
			c.Rules = append(c.Rules, credential.AccessRule{Method: "DELETE", Path: "/domain/zone/*"})
		},
		"another address": func(c *credential.Credential) {
			c.AllowedIPs = []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")}
		},
		"no address at all": func(c *credential.Credential) { c.AllowedIPs = nil },
	}

	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			second := twin(2)
			change(&second)

			if got := Twins([]credential.Credential{twin(1), second}); len(got) != 0 {
				t.Errorf("twins = %v, want none", got)
			}
		})
	}
}

// An expired key grants nothing, so it is nobody's twin: reporting a live key as a duplicate
// of a dead one would send the reader to revoke the wrong one.
func TestAnExpiredKeyIsNobodysTwin(t *testing.T) {
	dead := twin(2)
	dead.Status = credential.StatusExpired

	if got := Twins([]credential.Credential{twin(1), dead}); len(got) != 0 {
		t.Errorf("twins = %v, want none", got)
	}
}

// An application that could not be read leaves every credential pointing at the same zero
// identifier, which would pair keys that have nothing to do with each other.
func TestCredentialsWithAnUnreadableApplicationAreNotPaired(t *testing.T) {
	first, second := twin(1), twin(2)
	first.Application = credential.Application{}
	second.Application = credential.Application{}

	if got := Twins([]credential.Credential{first, second}); len(got) != 0 {
		t.Errorf("twins = %v, want none", got)
	}
}

// The window is inclusive at a week and says nothing about a key that is already past its
// date: that key is expired, whatever status the listing gave it a moment ago.
func TestAnExpiryIsReportedWithinAMonthAndNotBeyond(t *testing.T) {
	cases := map[string]struct {
		expires time.Time
		want    bool
	}{
		"in an hour":        {now.Add(time.Hour), true},
		"in exactly 7 days": {now.Add(7 * 24 * time.Hour), true},
		"in 8 days":         {now.Add(8 * 24 * time.Hour), false},
		"an hour ago":       {now.Add(-time.Hour), false},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			key := wellKept()
			key.ExpiresAt = c.expires

			if got := slices.Contains(codes(Inspect(key, now)), ExpiresSoon); got != c.want {
				t.Errorf("expires-soon = %v, want %v", got, c.want)
			}
		})
	}
}

// The OVHcloud page offers a 30-day validity, and a key issued with it must not be flagged
// from the day it is issued: a finding raised for the whole life of a normal key is noise.
func TestAKeyIssuedForThirtyDaysIsNotFlaggedWhenIssued(t *testing.T) {
	key := wellKept()
	key.CreatedAt = now
	key.ExpiresAt = now.Add(30 * 24 * time.Hour)

	if got := codes(Inspect(key, now)); slices.Contains(got, ExpiresSoon) {
		t.Errorf("findings = %v, want no %s on a 30-day key the day it is issued", got, ExpiresSoon)
	}
}

// A key with no expiry is reported for that, and only that: it cannot also be about to expire.
func TestAKeyWithoutExpiryIsNotAlsoExpiringSoon(t *testing.T) {
	key := wellKept()
	key.ExpiresAt = time.Time{}

	got := codes(Inspect(key, now))
	if !slices.Contains(got, NoExpiry) || slices.Contains(got, ExpiresSoon) {
		t.Errorf("findings = %v, want %s alone of the two", got, NoExpiry)
	}
}

func TestSurplusNamesTheRulesBeyondWhatIsNeeded(t *testing.T) {
	needed := []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
	}
	c := wellKept()
	c.Rules = []credential.AccessRule{
		{Method: "get", Path: "/me/api/credential"},
		{Method: "GET", Path: "/cloud/project/*"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
		{Method: "GET", Path: "/me/api/*"},
	}

	got := Surplus(c, needed)
	want := []credential.AccessRule{
		{Method: "GET", Path: "/cloud/project/*"},
		{Method: "GET", Path: "/me/api/*"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("surplus = %v, want %v, in the order the key holds them", got, want)
	}
}

func TestAKeyHoldingExactlyWhatIsNeededHasNoSurplus(t *testing.T) {
	needed := []credential.AccessRule{{Method: "GET", Path: "/me/api/credential"}}
	c := wellKept()
	c.Rules = needed

	if got := Surplus(c, needed); len(got) != 0 {
		t.Errorf("surplus = %v, want none", got)
	}
}
