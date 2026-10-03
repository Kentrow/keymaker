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
	"net/netip"
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
	ExpiresSoon     Code = "expires-soon"
	NeverUsed       Code = "never-used"
	Dormant         Code = "dormant"
	NoDescription   Code = "no-description"
	SupportIssued   Code = "support-issued"

	// AccountControl and BillingAccess are raised on a scoped rule that reaches one of the
	// SensitiveBranches. A broad rule reaches all of them and says so already, so neither is
	// raised beside BroadAccess.
	AccountControl Code = "account-control"
	BillingAccess  Code = "billing-access"

	// WiderThanNeeded is raised on the credential the tool authenticates with when it holds
	// rules the tool never asks for. Only the caller knows what it needs, so Inspect cannot
	// raise it: see Surplus.
	WiderThanNeeded Code = "wider-than-needed"

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

// expiringWithin is how far ahead an expiry is worth a finding.
//
// The page that issues keys offers five validities: five minutes, an hour, a day, 30 days, or
// none. A window of a month would flag every 30-day key from the moment it is issued and for
// its whole life, which is how a finding teaches its reader to ignore it. A week flags such a
// key in its last week only, still leaves time to issue and deploy a replacement, and flags a
// one-day key from the start, which is right: it does expire tomorrow.
const expiringWithin = 7 * 24 * time.Hour

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

	broad := hasBroadRule(c.Rules)
	if broad {
		add(BroadAccess, SeverityRisk)
	} else {
		if reaches(c.Rules, AccountControl) {
			add(AccountControl, SeverityRisk)
		}
		if reaches(c.Rules, BillingAccess) {
			add(BillingAccess, SeverityCaution)
		}
	}
	if !restrictsAddresses(c.AllowedIPs) {
		add(NoIPRestriction, SeverityCaution)
	}
	// An expiry is not a risk: it is the opposite of one. It is a date after which whatever
	// uses the key stops working without a word, the tool's own management key included,
	// and it is worth seeing while there is still time to act.
	switch {
	case c.ExpiresAt.IsZero():
		add(NoExpiry, SeverityCaution)
	case c.ExpiresAt.After(now) && c.ExpiresAt.Sub(now) <= expiringWithin:
		add(ExpiresSoon, SeverityCaution)
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
//
// A credential whose application was deleted is not read either, whatever its status says: the
// API refuses every call made with it, so it is dead weight, like an expired key.
func Examines(c credential.Credential) bool {
	if c.Application.Deleted {
		return false
	}
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

// Branch is a part of the API that deserves a warning even under a narrow rule.
type Branch struct {
	// Finding is the code raised on a key holding a rule that reaches the branch.
	Finding Code
	Path    string

	// Methods limits the branch to these methods. Empty means every method: reading
	// invoices is already exposure, while reading the list of IAM users is not a way in.
	Methods []string
}

var writes = []string{"POST", "PUT", "DELETE"}

// SensitiveBranches are the parts of the account a narrow rule can still reach at a cost.
//
// The first group manages who can get into the account: IAM users, groups and tokens,
// OAuth2 clients, sub-account consumer keys, the addresses another key accepts, two-factor
// authentication and the login restrictions, password and email changes, and the SSH keys
// new servers trust. A write there can let someone in or lock the owner out, beyond the
// key's own rules, and a method cannot tell the two apart: enabling and disabling a user are
// both a POST. Every write counts, then, with one exception. Revoking API credentials is what
// the management key this tool runs with does, and a finding raised on every management key
// would soon be read as noise.
//
// The second group is money: invoices, orders, payment means and balances. Read, it
// exposes financial data; written, it can pay an order with a registered payment mean.
//
// The interface receives this list rather than keeping a copy, so that the explorer warns
// about the same rules the audit flags.
var SensitiveBranches = []Branch{
	{Finding: AccountControl, Path: "/me/accessRestriction", Methods: writes},
	{Finding: AccountControl, Path: "/me/identity", Methods: writes},
	{Finding: AccountControl, Path: "/me/subAccount", Methods: []string{"POST", "PUT"}},
	{Finding: AccountControl, Path: "/me/api/oauth2/client", Methods: []string{"POST", "PUT"}},
	{Finding: AccountControl, Path: "/me/api/credential", Methods: []string{"PUT"}},
	{Finding: AccountControl, Path: "/me/changeEmail", Methods: []string{"POST"}},
	{Finding: AccountControl, Path: "/me/changePassword", Methods: []string{"POST"}},
	{Finding: AccountControl, Path: "/me/passwordRecover", Methods: []string{"POST"}},
	{Finding: AccountControl, Path: "/me/sshKey", Methods: []string{"POST", "DELETE"}},

	{Finding: BillingAccess, Path: "/me/autorenew"},
	{Finding: BillingAccess, Path: "/me/availableAutomaticPaymentMeans"},
	{Finding: BillingAccess, Path: "/me/bill"},
	{Finding: BillingAccess, Path: "/me/billing"},
	{Finding: BillingAccess, Path: "/me/consumption"},
	{Finding: BillingAccess, Path: "/me/correctiveInvoice"},
	{Finding: BillingAccess, Path: "/me/credit"},
	{Finding: BillingAccess, Path: "/me/debtAccount"},
	{Finding: BillingAccess, Path: "/me/deposit"},
	{Finding: BillingAccess, Path: "/me/downPaymentInvoice"},
	{Finding: BillingAccess, Path: "/me/fidelityAccount"},
	{Finding: BillingAccess, Path: "/me/order"},
	{Finding: BillingAccess, Path: "/me/ovhAccount"},
	{Finding: BillingAccess, Path: "/me/payment"},
	{Finding: BillingAccess, Path: "/me/paymentMean"},
	{Finding: BillingAccess, Path: "/me/refund"},
	{Finding: BillingAccess, Path: "/me/reverseBill"},
	{Finding: BillingAccess, Path: "/me/voucher"},
	{Finding: BillingAccess, Path: "/me/withdrawal"},
}

// Reaches reports whether a rule covers at least one route of the branch.
//
// A rule without a wildcard names one route, which belongs to the branch when its path is
// the branch or lies under it. A wildcard covers every path starting with the fixed part
// before it, so it also reaches a branch that fixed part is only the beginning of: /me/i*
// covers /me/identity as surely as /me/identity/* does.
func (b Branch) Reaches(rule credential.AccessRule) bool {
	if len(b.Methods) > 0 && !slices.ContainsFunc(b.Methods, func(m string) bool { return strings.EqualFold(m, rule.Method) }) {
		return false
	}

	star := strings.Index(rule.Path, "*")
	if star < 0 {
		// Without a wildcard a rule names one route exactly, and no route ends in a slash:
		// tried on a real account, PUT /me/api/credential/ opened nothing at all.
		if len(rule.Path) > 1 && strings.HasSuffix(rule.Path, "/") {
			return false
		}
		return within(rule.Path, b.Path)
	}
	fixed := rule.Path[:star]
	return within(strings.TrimSuffix(fixed, "/"), b.Path) || strings.HasPrefix(b.Path, fixed)
}

// within reports whether a path is the branch or lies under it. The separator matters:
// /me/billing is a branch of its own and not a part of /me/bill.
func within(path, branch string) bool {
	return path == branch || strings.HasPrefix(path, branch+"/")
}

// restrictsAddresses reports whether a list of allowed addresses keeps any source out. An
// empty list lets every address in, and so does a block of length zero: the API takes
// 0.0.0.0/0 and ::/0 as written, and a key holding one answers from anywhere.
func restrictsAddresses(allowed []netip.Prefix) bool {
	return len(allowed) > 0 && !slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Bits() == 0 })
}

// reaches reports whether any of the rules reaches a branch raising the finding.
func reaches(rules []credential.AccessRule, finding Code) bool {
	for _, branch := range SensitiveBranches {
		if branch.Finding != finding {
			continue
		}
		for _, rule := range rules {
			if branch.Reaches(rule) {
				return true
			}
		}
	}
	return false
}

// Surplus returns the rules of a credential that are not among the ones needed, in the order
// the credential holds them.
//
// The comparison is by rule and not by reach. A rule wider than a needed one, such as
// GET /me/api/* where GET /me/api/credential/* would do, is surplus as surely as a rule on an
// unrelated product: either way the key can do more than what it is kept for, and the remedy
// is the same, a key issued with the needed rules and nothing else.
func Surplus(c credential.Credential, needed []credential.AccessRule) []credential.AccessRule {
	var extra []credential.AccessRule
	for _, rule := range c.Rules {
		if !slices.ContainsFunc(needed, func(n credential.AccessRule) bool {
			return strings.EqualFold(n.Method, rule.Method) && n.Path == rule.Path
		}) {
			extra = append(extra, rule)
		}
	}
	return extra
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
