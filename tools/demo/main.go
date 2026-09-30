// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Command demo runs the interface on invented data.
//
// It puts the real server and the real interface in front of a fixed set of invented keys and
// applications, one of each finding among them, so that a change to the interface can be seen
// and reviewed without an OVHcloud account whose keys happen to show it. It never calls the
// API. Revocations and deletions apply to its memory only and are forgotten on restart.
//
//	go run ./tools/demo
//
// It is not part of the binary nor of the image: the Docker build context only lets cmd/ and
// internal/ in.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/httpapi"
	"github.com/kentrow/keymaker/internal/ovh"
	"github.com/kentrow/keymaker/internal/publicip"
	"github.com/kentrow/keymaker/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8081", "address to listen on")
	flag.Parse()

	token, err := httpapi.NewToken()
	if err != nil {
		log.Fatal(err)
	}
	csrf, err := httpapi.NewToken()
	if err != nil {
		log.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	handler, err := newHandler(newStore(time.Now()), token, csrf, logger)
	if err != nil {
		log.Fatal(err)
	}

	logger.Info("invented data, nothing reaches the API: open this address", "url", fmt.Sprintf("http://%s/?token=%s", *addr, token))
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

// newHandler assembles the real server around the store, the way cmd/keymaker does around
// the API client.
func newHandler(store *store, token, csrf string, logger *slog.Logger) (http.Handler, error) {
	snapshot, err := catalog.Embedded()
	if err != nil {
		return nil, fmt.Errorf("read the embedded catalogue: %w", err)
	}

	return httpapi.New(httpapi.Options{
		Provider: store,
		Catalog:  fixedCatalog(snapshot),
		Assets:   web.Assets(),
		Resolver: publicip.Disabled{},
		Logger:   logger,
		Token:    token,
		CSRF:     csrf,
		Endpoint: "ovh-eu",
		Version:  "demo",
	}), nil
}

type fixedCatalog catalog.Snapshot

func (c fixedCatalog) Current(context.Context) catalog.Snapshot { return catalog.Snapshot(c) }

// store is an account held in memory. It keeps the guards of the real provider, so that the
// interface shows the refusals a real account would give: the key in use cannot revoke itself,
// an application still holding a key cannot be deleted, and nothing is offered that the rules
// of the key in use do not cover.
type store struct {
	mu           sync.Mutex
	current      credential.Credential
	credentials  []credential.Credential
	applications []credential.Application
}

var _ credential.Provider = (*store)(nil)

func (s *store) List(_ context.Context, status credential.Status) ([]credential.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]credential.Credential, 0, len(s.credentials))
	for _, c := range s.credentials {
		if status == "" || c.Status == status {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *store) Get(_ context.Context, id int64) (credential.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.credentials {
		if c.ID == id {
			return c, nil
		}
	}
	return credential.Credential{}, credential.ErrNotFound
}

func (s *store) Current(context.Context) (credential.Credential, error) {
	return s.current, nil
}

func (s *store) Revoke(ctx context.Context, id int64) error {
	return s.RevokeAgainst(ctx, s.current, id)
}

func (s *store) RevokeAgainst(_ context.Context, current credential.Credential, id int64) error {
	if current.ID == id {
		return credential.ErrSelfRevocation
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	before := len(s.credentials)
	s.credentials = slices.DeleteFunc(s.credentials, func(c credential.Credential) bool { return c.ID == id })
	if len(s.credentials) == before {
		return credential.ErrNotFound
	}
	return nil
}

func (s *store) Revocable(current, target credential.Credential) bool {
	return current.Permits(http.MethodDelete, ovh.CredentialPath(target.ID))
}

func (s *store) Applications(context.Context) ([]credential.Application, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.applications), nil
}

func (s *store) DeleteApplication(ctx context.Context, id int64) error {
	credentials, err := s.List(ctx, "")
	if err != nil {
		return err
	}
	return s.DeleteApplicationAgainst(ctx, credentials, id)
}

func (s *store) DeleteApplicationAgainst(_ context.Context, credentials []credential.Credential, id int64) error {
	for _, c := range credentials {
		if c.Application.ID == id {
			return credential.ErrApplicationInUse
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	before := len(s.applications)
	s.applications = slices.DeleteFunc(s.applications, func(a credential.Application) bool { return a.ID == id })
	if len(s.applications) == before {
		return credential.ErrNotFound
	}
	return nil
}

func (s *store) DeletableApplication(current credential.Credential, id int64) bool {
	return current.Permits(http.MethodDelete, ovh.ApplicationPath(id))
}

// newStore builds the invented account, dated from now so that relative dates read the same
// on every run. Identifiers are made up, and every address comes from the ranges reserved for
// documentation.
func newStore(now time.Time) *store {
	day := 24 * time.Hour
	ip := func(prefix string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(prefix)} }

	demo := credential.Application{ID: 7101, Key: "demo0000000000a1", Name: "keymaker", Description: "the key this demo runs with"}
	dns := credential.Application{ID: 7110, Key: "demo0000000000b2", Name: "dns-renewal", Description: "certbot on the web servers"}
	iam := credential.Application{ID: 7111, Key: "demo0000000000c3", Name: "iam-bot", Description: "onboarding script"}
	ticket := credential.Application{ID: 7112, Key: "demo0000000000d4", Name: "support-ticket", Description: "ticket 4242"}
	draft := credential.Application{ID: 7113, Key: "demo0000000000e5", Name: "draft", Description: "first try"}
	backup := credential.Application{ID: 7114, Key: "demo0000000000f6", Name: "backup-agent"}
	cron := credential.Application{ID: 7115, Key: "demo0000000000a7", Name: "legacy-cron", Description: "nightly export"}
	console := credential.Application{ID: 7190, Name: "API console", Description: "the web console of the API", External: true}
	leftover := credential.Application{ID: 7116, Key: "demo0000000000b8", Name: "old-backup", Description: "left behind by a revoked key"}

	zone := []credential.AccessRule{
		{Method: http.MethodGet, Path: "/domain/zone/*"},
		{Method: http.MethodPost, Path: "/domain/zone/*/record"},
	}

	// The key in use holds one rule more than the tool needs, and expires within the week.
	current := credential.Credential{
		ID: 118820001, Status: credential.StatusValidated, Application: demo,
		Rules:      append(slices.Clone(ovh.ManagementRules), credential.AccessRule{Method: http.MethodGet, Path: "/cloud/project/*"}),
		AllowedIPs: ip("198.51.100.7/32"),
		CreatedAt:  now.Add(-25 * day), ExpiresAt: now.Add(5 * day), LastUsedAt: now,
	}

	return &store{
		current: current,
		credentials: []credential.Credential{
			current,
			// Two keys nothing tells apart, the older one idle for months.
			{ID: 118820304, Status: credential.StatusValidated, Application: dns, Rules: zone, AllowedIPs: ip("203.0.113.4/32"),
				CreatedAt: now.Add(-300 * day), ExpiresAt: now.Add(90 * day), LastUsedAt: now.Add(-2 * time.Hour)},
			{ID: 118820517, Status: credential.StatusValidated, Application: dns, Rules: zone, AllowedIPs: ip("203.0.113.4/32"),
				CreatedAt: now.Add(-310 * day), ExpiresAt: now.Add(90 * day), LastUsedAt: now.Add(-200 * day)},
			// Narrow rules that still reach account access and billing, from any address.
			{ID: 118821001, Status: credential.StatusValidated, Application: iam,
				Rules: []credential.AccessRule{
					{Method: http.MethodPost, Path: "/me/identity/user"},
					{Method: http.MethodGet, Path: "/me/bill"},
				},
				CreatedAt: now.Add(-40 * day), ExpiresAt: now.Add(200 * day), LastUsedAt: now.Add(-day)},
			{ID: 118821050, Status: credential.StatusValidated, Application: ticket, IssuedBySupport: true,
				Rules:      []credential.AccessRule{{Method: http.MethodGet, Path: "/me"}},
				AllowedIPs: ip("192.0.2.10/32"),
				CreatedAt:  now.Add(-60 * day), ExpiresAt: now.Add(120 * day), LastUsedAt: now.Add(-50 * day)},
			// Never validated, and asking for the whole account.
			{ID: 118821099, Status: credential.StatusPendingValidation, Application: draft,
				Rules:     []credential.AccessRule{{Method: http.MethodGet, Path: "/*"}},
				CreatedAt: now.Add(-3 * day)},
			// Issued months ago for an application nobody described, and never used.
			{ID: 118821200, Status: credential.StatusValidated, Application: backup,
				Rules:      []credential.AccessRule{{Method: http.MethodGet, Path: "/dedicated/server/*"}},
				AllowedIPs: ip("192.0.2.20/32"),
				CreatedAt:  now.Add(-90 * day), ExpiresAt: now.Add(300 * day)},
			{ID: 118821300, Status: credential.StatusExpired, Application: cron,
				Rules:      []credential.AccessRule{{Method: http.MethodGet, Path: "/me/order"}},
				AllowedIPs: ip("192.0.2.30/32"),
				CreatedAt:  now.Add(-400 * day), ExpiresAt: now.Add(-40 * day), LastUsedAt: now.Add(-41 * day)},
			// Issued through an application the account does not own, with nothing to report.
			{ID: 118821400, Status: credential.StatusValidated, Application: console,
				Rules:      []credential.AccessRule{{Method: http.MethodGet, Path: "/me"}},
				AllowedIPs: ip("192.0.2.40/32"),
				CreatedAt:  now.Add(-20 * day), ExpiresAt: now.Add(60 * day), LastUsedAt: now.Add(-5 * day)},
		},
		applications: []credential.Application{demo, dns, iam, ticket, draft, backup, cron, leftover},
	}
}
