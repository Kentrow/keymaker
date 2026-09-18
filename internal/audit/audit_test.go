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
		ExpiresAt:   now.Add(30 * 24 * time.Hour),
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
