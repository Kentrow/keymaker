// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package ovh is the transport boundary to the OVHcloud API.
//
// Client exists as an interface so the test suite runs on JSON fixtures, without an
// OVHcloud account. The wire structs and their JSON mapping are
// declared alongside those fixtures rather than guessed here.
//
// The methods below are the complete set of API interactions this project performs.
// They map one to one onto the endpoints listed in docs/ARCHITECTURE.md, which is a closed
// list: an interaction that has no method here has no endpoint either. In particular
// there is no method to change the access rules of a credential and none to create an
// application, because neither endpoint exists.
//
// GET /auth/time is absent on purpose. Clock drift resynchronisation and request
// signing belong to go-ovh and are never reimplemented.
package ovh

import (
	"context"

	"github.com/kentrow/keymaker/internal/credential"
)

// Client performs the API calls listed above and nothing else. Callers never
// supply a URL: the route of each call is fixed by the method that makes it, which is
// what keeps the frontend from reaching an arbitrary host.
type Client interface {
	// CurrentCredential issues GET /auth/currentCredential.
	CurrentCredential(ctx context.Context) (credential.Credential, error)

	// ListCredentialIDs issues GET /me/api/credential, narrowed by the status filter
	// when status is non-empty.
	ListCredentialIDs(ctx context.Context, status credential.Status) ([]int64, error)

	// Credential issues GET /me/api/credential/{id}.
	Credential(ctx context.Context, id int64) (credential.Credential, error)

	// CredentialApplication issues GET /me/api/credential/{id}/application.
	CredentialApplication(ctx context.Context, id int64) (credential.Application, error)

	// DeleteCredential issues DELETE /me/api/credential/{id}.
	DeleteCredential(ctx context.Context, id int64) error

	// ListApplicationIDs issues GET /me/api/application. It is the only call that sees an
	// application no credential points at.
	ListApplicationIDs(ctx context.Context) ([]int64, error)

	// Application issues GET /me/api/application/{id}.
	Application(ctx context.Context, id int64) (credential.Application, error)

	// DeleteApplication issues DELETE /me/api/application/{id}. The API revokes every
	// credential of that application with it, which is why the caller has to know there is
	// none before asking.
	DeleteApplication(ctx context.Context, id int64) error

	// Index issues GET /1.0/ and returns the response unparsed. The catalogue package
	// owns its interpretation.
	Index(ctx context.Context) ([]byte, error)

	// Schema fetches one of the *.json schemas advertised by the index, unparsed.
	// The path comes from the index response, never from a client request.
	Schema(ctx context.Context, path string) ([]byte, error)
}
