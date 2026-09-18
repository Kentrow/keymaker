// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package audit names what is wrong with a credential.
//
// It is an analysis layer over what the inventory already holds and makes no API call of
// its own. Findings carry a code and a severity; their wording belongs
// to the interface, which is translated.
package audit

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kentrow/keymaker/internal/credential"
)

type Severity string

const (
	SeverityRisk    Severity = "risk"
	SeverityCaution Severity = "caution"
	SeverityNote    Severity = "note"
)

type Code string

const (
	BroadAccess     Code = "broad-access"
	NoIPRestriction Code = "no-ip-restriction"
	NoExpiry        Code = "no-expiry"
	NeverUsed       Code = "never-used"
	Dormant         Code = "dormant"
	NoDescription   Code = "no-description"
	SupportIssued   Code = "support-issued"

	// SameAsAnother is raised over a set rather than over one credential, which is why
	// Inspect cannot raise it: see Twins.
	SameAsAnother Code = "same-as-another"

	// PendingValidation is raised on a key nobody ever validated. It is the one finding
	// about a key that grants nothing yet, which is why the others are read differently
	// for it: see Inspect.
	PendingValidation Code = "pending-validation"
)

// unusedGrace keeps a key that was only just issued out of the never-used count: it has
// not had the chance to be used yet, and flagging it would train the reader to ignore the
// finding.
const unusedGrace = 30 * 24 * time.Hour

// dormantAfter is where a key stops looking merely idle and starts looking forgotten.
const dormantAfter = 180 * 24 * time.Hour

type Finding struct {
	Code     Code
	Severity Severity
}

// Inspect reports what is wrong with one credential.
//
// An expired or refused credential grants nothing and is not examined: reporting that it has
// no expiry or no IP restriction would be noise.
//
// A credential awaiting validation is examined, with one difference. It grants nothing until
// the account holder validates it on the provider's page, so what it has never done says
// nothing about it, and the checks that read its use are skipped. What it would be allowed to
// do the moment it is validated is worth knowing before that happens, so the rest are not.
func Inspect(c credential.Credential, now time.Time) []Finding {
	if !Examines(c) {
		return nil
	}

	findings := []Finding{}
	add := func(code Code, severity Severity) {
		findings = append(findings, Finding{Code: code, Severity: severity})
	}

	if c.Status == credential.StatusPendingValidation {
		add(PendingValidation, SeverityCaution)
	}

	if hasBroadRule(c.Rules) {
		add(BroadAccess, SeverityRisk)
	}
	if len(c.AllowedIPs) == 0 {
		add(NoIPRestriction, SeverityCaution)
	}
	if c.ExpiresAt.IsZero() {
		add(NoExpiry, SeverityCaution)
	}

	if c.Status != credential.StatusPendingValidation {
		switch {
		case c.LastUsedAt.IsZero():
			if !c.CreatedAt.IsZero() && now.Sub(c.CreatedAt) > unusedGrace {
				add(NeverUsed, SeverityCaution)
			}
		case now.Sub(c.LastUsedAt) > dormantAfter:
			add(Dormant, SeverityCaution)
		}
	}

	if strings.TrimSpace(c.Application.Description) == "" {
		add(NoDescription, SeverityNote)
	}

	// A key the account holder did not issue is not wrong in itself: support creates one to
	// work on a ticket. It is flagged because it outlives the ticket, and because it is the
	// one kind of key nobody on this side decided to keep.
	if c.IssuedBySupport {
		add(SupportIssued, SeverityCaution)
	}

	return findings
}

// Examines reports whether Inspect reads a credential at all. A credential it does not read
// has no findings, which is not the same as having nothing wrong with it, and a summary has to
// be able to tell the two apart.
//
// A credential awaiting validation is read: it is one click on the provider's page away from
// working, and that click belongs to the account holder, who is better told beforehand what
// they would be validating.
func Examines(c credential.Credential) bool {
	return c.Status == credential.StatusValidated || c.Status == credential.StatusPendingValidation
}

// hasBroadRule reports whether any rule reaches everything, or the whole account.
//
// Only the fixed part of a path counts, the part before the first wildcard: /domain/zone/*
// is scoped to one product, while /* and /me/* reach the account itself, billing and
// contact details included.
func hasBroadRule(rules []credential.AccessRule) bool {
	for _, rule := range rules {
		// Without a wildcard the rule names one route, however short its path is.
		star := strings.Index(rule.Path, "*")
		if star < 0 {
			continue
		}

		switch strings.TrimSuffix(rule.Path[:star], "/") {
		case "", "/me":
			return true
		}
	}
	return false
}

// Twins reports the credentials that another credential of the set is indistinguishable
// from: same application, same access rules, same allowed addresses. Nothing tells them
// apart, so whatever one of them can do, the other can do too.
//
// Two such keys are almost always a first attempt nobody revoked, and one of them is an
// access nobody is watching. Which one to keep is not a decision this can make: the dates on
// the cards are what settles it, and they belong to the reader.
//
// It takes the whole set, which is why it sits beside Inspect rather than inside it. Only
// credentials Inspect examines are compared; an expired key is nobody's twin.
func Twins(credentials []credential.Credential) map[int64]bool {
	seen := map[string][]int64{}
	for _, c := range credentials {
		if !Examines(c) || c.Application.ID == 0 {
			continue
		}
		key := fingerprint(c)
		seen[key] = append(seen[key], c.ID)
	}

	twins := map[int64]bool{}
	for _, ids := range seen {
		if len(ids) < 2 {
			continue
		}
		for _, id := range ids {
			twins[id] = true
		}
	}
	return twins
}

// fingerprint is what makes two credentials interchangeable. Order carries no meaning in
// either list, so both are sorted before they are read: the API returns them in the order it
// pleases, and two keys created the same way would otherwise look different.
func fingerprint(c credential.Credential) string {
	rules := make([]string, 0, len(c.Rules))
	for _, rule := range c.Rules {
		rules = append(rules, strings.ToUpper(rule.Method)+" "+rule.Path)
	}
	slices.Sort(rules)

	addresses := make([]string, 0, len(c.AllowedIPs))
	for _, prefix := range c.AllowedIPs {
		addresses = append(addresses, prefix.String())
	}
	slices.Sort(addresses)

	return fmt.Sprintf("%d\n%s\n%s", c.Application.ID, strings.Join(rules, "\n"), strings.Join(addresses, "\n"))
}

// Summary counts how many credentials raised each finding, so that the interface can offer
// them as filters without recomputing anything.
type Summary struct {
	// Counts is how many credentials raised each finding, not how many findings were
	// raised: the interface turns each one into a filter over the list.
	Counts map[Code]int

	// Flagged is how many credentials raised at least one finding, AtRisk how many raised
	// one of the risk severity.
	Flagged int
	AtRisk  int
}

func Summarise(findings [][]Finding) Summary {
	summary := Summary{Counts: map[Code]int{}}

	for _, list := range findings {
		if len(list) == 0 {
			continue
		}
		summary.Flagged++

		risky := false
		for _, finding := range list {
			summary.Counts[finding.Code]++
			risky = risky || finding.Severity == SeverityRisk
		}
		if risky {
			summary.AtRisk++
		}
	}
	return summary
}
