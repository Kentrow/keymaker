// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package credential holds the provider-neutral representation of an API credential
// and the abstraction over the mechanisms that can issue one.
//
// Nothing here may name a legacy AK/AS/CK concept. An OAuth2/IAM provider would reuse this
// model unchanged, and the interface layer is written against it rather than against the
// wire format of any single provider.
package credential

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Status is the lifecycle state of a credential. These are the values of the published
// auth.CredentialStateEnum, which is also what the status filter of
// GET /me/api/credential accepts.
type Status string

const (
	StatusExpired           Status = "expired"
	StatusPendingValidation Status = "pendingValidation"
	StatusRefused           Status = "refused"
	StatusValidated         Status = "validated"
)

// AccessRule is one method-and-path pair. A credential carries a set of them, fixed
// at creation: no endpoint exists to change them afterwards.
type AccessRule struct {
	Method string
	Path   string
}

// Application is the carrier an API credential is issued under.
type Application struct {
	ID          int64
	Key         string
	Name        string
	Description string

	// External marks an application this account does not own, such as the OVHcloud API
	// console: a credential was issued to the account through it, but the application
	// belongs to someone else and cannot be read or managed from here.
	External bool
}

// Credential is an issued key as the inventory displays it.
// A zero ExpiresAt means no expiry, a zero LastUsedAt means never used.
type Credential struct {
	ID          int64
	Application Application
	Status      Status
	Rules       []AccessRule
	AllowedIPs  []netip.Prefix
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
}

// Permits reports whether the rules of this credential cover a call.
//
// The wildcard semantics here are read off the shape of the rules the API returns, not off
// a documented grammar, so this decides what the interface offers and never whether a call
// is made. Read as forbidding, an action is not offered; read as permitted, the call still
// goes to the API, which has the last word and whose refusal surfaces as
// ErrPermissionDenied.
func (c Credential) Permits(method, path string) bool {
	for _, rule := range c.Rules {
		if strings.EqualFold(rule.Method, method) && matchPath(rule.Path, path) {
			return true
		}
	}
	return false
}

// Provider is the credential mechanism the rest of the application talks to.
// The legacy AK/AS/CK provider is the only implementation; an OAuth2/IAM one would sit
// beside it.
type Provider interface {
	List(ctx context.Context, status Status) ([]Credential, error)
	Get(ctx context.Context, id int64) (Credential, error)
	Revoke(ctx context.Context, id int64) error

	// RevokeAgainst revokes id on behalf of a caller that has already identified current,
	// the credential the tool authenticates with, in the same request. It refuses current
	// exactly as Revoke does, without reading the identity again for every key of a set.
	RevokeAgainst(ctx context.Context, current Credential, id int64) error

	// Current returns the credential the tool itself authenticates with. The revocation
	// path refuses it and the inventory marks it.
	Current(ctx context.Context) (Credential, error)

	// Revocable reports whether current, the credential the tool authenticates with, holds
	// what revoking target needs. It reads rules already fetched and makes no call, so the
	// interface can disable an action instead of offering one that comes back refused. What
	// "what it needs" means belongs to the provider.
	Revocable(current, target Credential) bool
}

// ErrSelfRevocation is returned when a revocation targets the credential the tool
// authenticates with. Carrying it out would disconnect the user from their own tool,
// with no way back through the interface.
var ErrSelfRevocation = errors.New("the credential in use cannot revoke itself")

// ErrPermissionDenied is returned when the API refuses a call because the credential in
// use lacks the matching access rule. The interface names the missing permission and
// disables the action rather than surfacing the refusal as it came.
var ErrPermissionDenied = errors.New("the credential in use lacks a permission for this call")

// matchPath matches a rule path against a call path, taking * for any run of characters,
// separators included: /me/api/credential/* covers /me/api/credential/4210987.
func matchPath(pattern, path string) bool {
	segments := strings.Split(pattern, "*")
	if len(segments) == 1 {
		return pattern == path
	}

	if !strings.HasPrefix(path, segments[0]) {
		return false
	}
	path = path[len(segments[0]):]

	last := len(segments) - 1
	for _, segment := range segments[1:last] {
		found := strings.Index(path, segment)
		if found < 0 {
			return false
		}
		path = path[found+len(segment):]
	}
	return strings.HasSuffix(path, segments[last])
}

// ErrNotFound is returned when the API no longer knows a credential, typically because it
// was revoked between the moment it was listed and the call about it.
var ErrNotFound = errors.New("the credential no longer exists")

// IncompleteError is returned by List beside the credentials that could be read when some
// could not. The inventory is still worth showing, and the reader is told how many keys it
// is missing rather than being shown nothing at all.
type IncompleteError struct {
	Unreadable int
	Err        error
}

func (e *IncompleteError) Error() string {
	return fmt.Sprintf("%d credentials could not be read: %v", e.Unreadable, e.Err)
}

func (e *IncompleteError) Unwrap() error { return e.Err }

// ErrIdentityUnavailable is returned when the tool cannot establish which credential it
// authenticates with. Revocation depends on that answer, so it stops here rather than
// going ahead without the guard. It is distinct from ErrPermissionDenied so
// that a failure to identify is not reported as a missing delete rule.
var ErrIdentityUnavailable = errors.New("the credential in use could not be identified")
