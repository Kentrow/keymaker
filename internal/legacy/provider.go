// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package legacy implements the credential provider backed by an AK/AS/CK application
// credential, the only authentication scheme the credential routes accept today. The
// OAuth2/IAM provider would sit beside it rather than replace this one.
package legacy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"

	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
)

// fanOut bounds the number of detail calls in flight. Listing returns identifiers only,
// so an inventory of fifty keys means fifty round trips; running them one after another
// makes the first screen slow, running them all at once hammers the API.
const fanOut = 8

// Provider turns the endpoint-level client into the credential lifecycle the rest of the
// application works with.
type Provider struct {
	client ovh.Client
	logger *slog.Logger
}

var _ credential.Provider = (*Provider)(nil)

func New(client ovh.Client, logger *slog.Logger) *Provider {
	return &Provider{client: client, logger: logger}
}

func (p *Provider) List(ctx context.Context, status credential.Status) ([]credential.Credential, error) {
	ids, err := p.client.ListCredentialIDs(ctx, status)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", translate(err))
	}

	credentials, err := p.fetchAll(ctx, ids)
	if credentials == nil {
		return nil, err
	}
	p.resolveApplications(ctx, credentials)
	return credentials, err
}

func (p *Provider) Get(ctx context.Context, id int64) (credential.Credential, error) {
	found, err := p.client.Credential(ctx, id)
	if err != nil {
		return credential.Credential{}, fmt.Errorf("credential %d: %w", id, translate(err))
	}

	one := []credential.Credential{found}
	p.resolveApplications(ctx, one)
	return one[0], nil
}

// Applications lists the applications of the account.
//
// Revoking a credential leaves its application behind, and an application holds the key and
// the secret a new credential can be requested under. The credential routes only ever name an
// application a credential already points at, so this listing is the only way to see the ones
// left with no key at all.
func (p *Provider) Applications(ctx context.Context) ([]credential.Application, error) {
	ids, err := p.client.ListApplicationIDs(ctx)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", translate(err))
	}

	fetched := make([]credential.Application, len(ids))
	failures := make([]error, len(ids))

	work := make(chan int)
	var workers sync.WaitGroup
	for range min(fanOut, len(ids)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				found, err := p.client.Application(ctx, ids[i])
				if err != nil {
					failures[i] = fmt.Errorf("application %d: %w", ids[i], translate(err))
					continue
				}
				fetched[i] = found
			}
		}()
	}
	for i := range ids {
		work <- i
	}
	close(work)
	workers.Wait()

	applications := make([]credential.Application, 0, len(ids))
	unreadable := 0
	for i := range ids {
		if failures[i] != nil {
			unreadable++
			continue
		}
		applications = append(applications, fetched[i])
	}

	if joined := errors.Join(failures...); joined != nil {
		if len(applications) == 0 {
			return nil, joined
		}
		return applications, &credential.IncompleteError{Unreadable: unreadable, Err: joined}
	}
	return applications, nil
}

// DeleteApplication deletes an application that holds no credential.
//
// The API revokes every credential of an application along with it, so the count is read from
// the API at the moment of the call rather than taken from what a screen was showing: an
// application that gained a key since the listing must not be deleted by a click meant for an
// empty one.
func (p *Provider) DeleteApplication(ctx context.Context, id int64) error {
	credentials, err := p.List(ctx, "")
	if credentials == nil {
		return fmt.Errorf("check what the application holds: %w", err)
	}
	return p.DeleteApplicationAgainst(ctx, credentials, id)
}

// DeleteApplicationAgainst is DeleteApplication for a caller that listed the credentials at the
// start of the same request. Deleting a set of applications then reads that listing once rather
// than once per application; the guard itself is unchanged.
func (p *Provider) DeleteApplicationAgainst(ctx context.Context, credentials []credential.Credential, id int64) error {
	for _, c := range credentials {
		if c.Application.ID == id {
			return credential.ErrApplicationInUse
		}
	}

	if err := p.client.DeleteApplication(ctx, id); err != nil {
		return fmt.Errorf("delete application %d: %w", id, translate(err))
	}
	return nil
}

// DeletableApplication reads the rules of the credential in use against the very route the
// deletion would take.
func (p *Provider) DeletableApplication(current credential.Credential, id int64) bool {
	return current.Permits(http.MethodDelete, ovh.ApplicationPath(id))
}

func (p *Provider) Current(ctx context.Context) (credential.Credential, error) {
	found, err := p.client.CurrentCredential(ctx)
	if err != nil {
		return credential.Credential{}, fmt.Errorf("identify the credential in use: %w", translate(err))
	}

	one := []credential.Credential{found}
	p.resolveApplications(ctx, one)
	return one[0], nil
}

// Revoke refuses to delete the credential the tool authenticates with.
//
// The identity is read from the API on every call rather than cached at startup. A cached
// value would be the one thing standing between a click and the user losing access to
// their own tool, and it would be wrong the moment the configuration changed underneath.
func (p *Provider) Revoke(ctx context.Context, id int64) error {
	current, err := p.client.CurrentCredential(ctx)
	if err != nil {
		// Named apart from the deletion itself: this call and the deletion can both be
		// refused, and blaming the delete rule for a failure to identify sends the reader
		// looking for the wrong thing.
		return fmt.Errorf("%w: %w", credential.ErrIdentityUnavailable, translate(err))
	}
	return p.RevokeAgainst(ctx, current, id)
}

// RevokeAgainst is Revoke for a caller that identified the credential in use at the start of
// the same request. A sweep over a set of keys reads the identity once rather than once per
// key; the guard itself is unchanged.
func (p *Provider) RevokeAgainst(ctx context.Context, current credential.Credential, id int64) error {
	if current.ID == id {
		return credential.ErrSelfRevocation
	}

	if err := p.client.DeleteCredential(ctx, id); err != nil {
		return fmt.Errorf("revoke credential %d: %w", id, translate(err))
	}
	return nil
}

// Revocable reads the rules of the credential in use rather than trying the call, against
// the very route Revoke would take.
func (p *Provider) Revocable(current, target credential.Credential) bool {
	return current.Permits(http.MethodDelete, ovh.CredentialPath(target.ID))
}

// fetchAll reads the detail of every identifier. A credential that disappears between the
// listing and its detail call was revoked in the meantime and is dropped rather than
// failing the whole inventory.
//
// A credential that cannot be read for another reason does not fail the inventory either:
// the others are returned with an *IncompleteError counting the missing ones. A refusal is
// the exception. It means the management key lacks a rule, which the reader has to be told
// plainly rather than handed a list that is silently short.
func (p *Provider) fetchAll(ctx context.Context, ids []int64) ([]credential.Credential, error) {
	fetched := make([]credential.Credential, len(ids))
	revoked := make([]bool, len(ids))
	failures := make([]error, len(ids))

	work := make(chan int)
	var workers sync.WaitGroup
	for range min(fanOut, len(ids)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				found, err := p.client.Credential(ctx, ids[i])
				switch {
				case err == nil:
					fetched[i] = found
				case ovh.StatusCode(err) == http.StatusNotFound:
					revoked[i] = true
				default:
					failures[i] = fmt.Errorf("credential %d: %w", ids[i], translate(err))
				}
			}
		}()
	}
	for i := range ids {
		work <- i
	}
	close(work)
	workers.Wait()

	credentials := make([]credential.Credential, 0, len(ids))
	unreadable := 0
	for i := range ids {
		switch {
		case failures[i] != nil:
			unreadable++
		case !revoked[i]:
			credentials = append(credentials, fetched[i])
		}
	}

	joined := errors.Join(failures...)
	switch {
	case joined == nil:
		return credentials, nil
	case errors.Is(joined, credential.ErrPermissionDenied), len(credentials) == 0:
		return nil, joined
	default:
		return credentials, &credential.IncompleteError{Unreadable: unreadable, Err: joined}
	}
}

// resolveApplications fills in the application each credential belongs to, reading each
// one once however many credentials share it.
//
// A management key granted the credential rules but not the application rules of
// ovh.ManagementRules still gets a usable inventory: the application stays reduced to its
// identifier instead of the whole screen failing.
func (p *Provider) resolveApplications(ctx context.Context, credentials []credential.Credential) {
	// One representative credential per application: the fallback route reads an
	// application through a credential, so each application needs one to go through.
	var representatives []credential.Credential
	seen := map[int64]bool{}
	for _, c := range credentials {
		if id := c.Application.ID; id != 0 && !seen[id] {
			seen[id] = true
			representatives = append(representatives, c)
		}
	}

	resolved := make([]credential.Application, len(representatives))
	work := make(chan int)
	var workers sync.WaitGroup
	for range min(fanOut, len(representatives)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				resolved[i] = p.application(ctx, representatives[i])
			}
		}()
	}
	for i := range representatives {
		work <- i
	}
	close(work)
	workers.Wait()

	known := make(map[int64]credential.Application, len(representatives))
	for i, c := range representatives {
		known[c.Application.ID] = resolved[i]
	}
	for i := range credentials {
		if application, ok := known[credentials[i].Application.ID]; ok {
			credentials[i].Application = application
		}
	}
}

// application reads the application one credential belongs to.
//
// The application route only answers for applications the account owns. A credential issued
// through one it does not own, the OVHcloud API console or its mobile application among them,
// gets a 404 there, and those tend to be the oldest keys with the widest rules. The credential
// route answers for both, so it is the fallback; it costs one call per such application, since
// the caller reads each application once.
func (p *Provider) application(ctx context.Context, c credential.Credential) credential.Application {
	found, err := p.client.Application(ctx, c.Application.ID)
	if err == nil {
		return found
	}

	viaCredential, fallback := p.client.CredentialApplication(ctx, c.ID)
	if fallback != nil {
		p.logger.WarnContext(ctx, "the application of a credential could not be read",
			"credential", c.ID, "application", c.Application.ID, "error", errors.Join(err, fallback))
		return c.Application
	}

	viaCredential.External = ovh.StatusCode(err) == http.StatusNotFound
	return viaCredential
}

// translate turns a refused call into a domain error, so that the layers above can tell a
// missing permission from a broken call without knowing anything about HTTP status codes
// or about which provider produced the failure.
func translate(err error) error {
	switch ovh.StatusCode(err) {
	case http.StatusForbidden:
		return fmt.Errorf("%w: %w", credential.ErrPermissionDenied, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", credential.ErrNotFound, err)
	}
	return err
}
