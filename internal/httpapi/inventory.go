// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/kentrow/keymaker/internal/audit"
	"github.com/kentrow/keymaker/internal/credential"
)

type inventoryResponse struct {
	Endpoint string `json:"endpoint"`

	// Current is the credential the tool authenticates with, null when it could not be
	// identified. The interface marks it and offers no revocation for it.
	Current *int64 `json:"current"`

	Summary summaryResponse `json:"summary"`

	Credentials []credentialResponse `json:"credentials"`
}

// summaryResponse lets the interface offer each finding as a filter without walking the
// list to count them.
type summaryResponse struct {
	Total int `json:"total"`

	// Examined is how many credentials the audit read, the usable ones. An expired, refused
	// or pending key is not examined, so it belongs to none of the bands the interface draws
	// from these counts; without this figure it could only be told apart as "nothing flagged".
	Examined int `json:"examined"`

	// Unreadable is how many credentials the API listed but would not describe. They are
	// missing from the list, and the interface says so rather than showing a short list as
	// if it were the whole account.
	Unreadable int            `json:"unreadable"`
	Flagged    int            `json:"flagged"`
	AtRisk     int            `json:"atRisk"`
	Counts     map[string]int `json:"counts"`
}

// findingResponse carries a code and a severity, never a sentence: the wording belongs to
// the interface, which is translated.
type findingResponse struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
}

type credentialResponse struct {
	ID          int64               `json:"id"`
	Self        bool                `json:"self"`
	Status      string              `json:"status"`
	Application applicationResponse `json:"application"`
	Rules       []ruleResponse      `json:"rules"`
	AllowedIPs  []string            `json:"allowedIps"`
	Findings    []findingResponse   `json:"findings"`
	Revoke      revokeResponse      `json:"revoke"`
	CreatedAt   *time.Time          `json:"createdAt"`
	ExpiresAt   *time.Time          `json:"expiresAt"`
	LastUsedAt  *time.Time          `json:"lastUsedAt"`
}

type applicationResponse struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// External says the application is not the account's own, typically the OVHcloud API
	// console, so the interface can say where a key came from rather than show it unnamed.
	External bool `json:"external"`
}

type ruleResponse struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// errorResponse carries a code beside its sentence. The sentence is a fallback for
// whoever reads the API directly; the interface renders the code in the reader's language,
// the way it does for audit findings.
type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Codes the interface knows how to word.
const (
	codePermissionDenied = "permission-denied"
	codeAPIFailure       = "api-failure"
	codeSelfRevocation   = "self-revocation"
	codeIdentityUnknown  = "identity-unknown"
	codeBadIdentifier    = "bad-identifier"
	codeMissingToken     = "missing-token"
	codeAlreadyRevoked   = "already-revoked"
	// #nosec G101 -- an error code the interface words in the reader's language, not a
	// credential. The name matches the pattern gosec looks for, the value is a constant
	// string sent in a JSON field.
	codeCredentialUnusable = "credential-unusable"
)

func (s *server) inventory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// The inventory is still worth showing when the tool cannot identify its own
	// credential; it just cannot mark it. Revocation stays safe either way, because the
	// guard runs again in the provider rather than relying on what was shown here.
	var current *credential.Credential
	own, identity := s.provider.Current(ctx)
	if identity == nil {
		current = &own
	} else {
		s.logger.WarnContext(ctx, "cannot identify the credential in use", "error", identity)
	}

	credentials, unreadable, err := s.list(ctx)
	if err != nil {
		s.failInventory(w, r, err, identity)
		return
	}

	now := time.Now()
	findings := make([][]audit.Finding, 0, len(credentials))

	response := inventoryResponse{
		Endpoint:    s.endpoint,
		Credentials: make([]credentialResponse, 0, len(credentials)),
	}
	if current != nil {
		response.Current = &current.ID
	}

	for _, c := range credentials {
		found := audit.Inspect(c, now)
		findings = append(findings, found)
		response.Credentials = append(response.Credentials, describe(c, current, found, s.revocationOffer(current, c)))
	}
	response.Summary = summarise(credentials, findings)
	response.Summary.Unreadable = unreadable

	// Most recently used first, keys never used last, so that what is live comes first
	// and what is forgotten collects at the bottom.
	slices.SortFunc(response.Credentials, func(a, b credentialResponse) int {
		if order := compareUse(a.LastUsedAt, b.LastUsedAt); order != 0 {
			return order
		}
		return cmp.Compare(b.ID, a.ID)
	})

	writeJSON(w, http.StatusOK, response)
}

// list reads every credential, accepting a partial answer. What could not be read is logged
// and counted; only a listing that produced nothing usable is an error.
func (s *server) list(ctx context.Context) ([]credential.Credential, int, error) {
	credentials, err := s.provider.List(ctx, "")
	var incomplete *credential.IncompleteError
	if errors.As(err, &incomplete) && credentials != nil {
		s.logger.WarnContext(ctx, "some credentials could not be read", "unreadable", incomplete.Unreadable, "error", incomplete.Err)
		return credentials, incomplete.Unreadable, nil
	}
	return credentials, 0, err
}

func summarise(credentials []credential.Credential, findings [][]audit.Finding) summaryResponse {
	counted := audit.Summarise(findings)

	examined := 0
	for _, c := range credentials {
		if audit.Examines(c) {
			examined++
		}
	}

	counts := make(map[string]int, len(counted.Counts))
	for code, count := range counted.Counts {
		counts[string(code)] = count
	}

	return summaryResponse{
		Total:    len(credentials),
		Examined: examined,
		Flagged:  counted.Flagged,
		AtRisk:   counted.AtRisk,
		Counts:   counts,
	}
}

func describe(c credential.Credential, current *credential.Credential, found []audit.Finding, offer revokeResponse) credentialResponse {
	rules := make([]ruleResponse, 0, len(c.Rules))
	for _, rule := range c.Rules {
		rules = append(rules, ruleResponse{Method: rule.Method, Path: rule.Path})
	}

	allowed := make([]string, 0, len(c.AllowedIPs))
	for _, prefix := range c.AllowedIPs {
		allowed = append(allowed, prefix.String())
	}

	reported := make([]findingResponse, 0, len(found))
	for _, finding := range found {
		reported = append(reported, findingResponse{
			Code:     string(finding.Code),
			Severity: string(finding.Severity),
		})
	}

	return credentialResponse{
		ID:     c.ID,
		Self:   current != nil && current.ID == c.ID,
		Status: string(c.Status),
		Application: applicationResponse{
			ID:          c.Application.ID,
			Key:         c.Application.Key,
			Name:        c.Application.Name,
			Description: c.Application.Description,
			External:    c.Application.External,
		},
		Rules:      rules,
		AllowedIPs: allowed,
		Findings:   reported,
		Revoke:     offer,
		CreatedAt:  optional(c.CreatedAt),
		ExpiresAt:  optional(c.ExpiresAt),
		LastUsedAt: optional(c.LastUsedAt),
	}
}

func compareUse(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	default:
		return b.Compare(*a)
	}
}

func optional(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// failInventory tells a credential that no longer works apart from one that works but was
// never granted a rule.
//
// GET /auth/currentCredential needs no access rule of its own: any valid credential can
// call it. So a refusal there is not about permissions, it is the credential itself being
// expired, revoked, or paired with the wrong secret. Reporting that as a missing rule sends
// the reader to edit permissions on a key that no longer exists.
func (s *server) failInventory(w http.ResponseWriter, r *http.Request, listing, identity error) {
	if errors.Is(listing, credential.ErrPermissionDenied) && errors.Is(identity, credential.ErrPermissionDenied) {
		s.logger.ErrorContext(r.Context(), "the configured credential is not usable",
			"listing", listing, "identity", identity)
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codeCredentialUnusable,
			Error: "the OVHcloud API refused the configured credential itself; it is expired, revoked, or paired with the wrong secret",
		})
		return
	}
	s.fail(w, r, listing)
}

// fail answers with what the reader can act on and keeps the detail for the log, which
// is redacted. A refusal is named as a missing permission rather than passed through as
// the API returned it.
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "error", err)

	if errors.Is(err, credential.ErrPermissionDenied) {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codePermissionDenied,
			Error: "the OVHcloud API refused the call; the usual cause is an access rule the management key does not hold",
		})
		return
	}
	writeJSON(w, http.StatusBadGateway, errorResponse{
		Code:  codeAPIFailure,
		Error: "the OVHcloud API call failed, see the process log",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
