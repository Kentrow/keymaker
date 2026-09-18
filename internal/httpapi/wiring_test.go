// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/httpapi"
	"github.com/kentrow/keymaker/internal/legacy"
	"github.com/kentrow/keymaker/internal/ovh"
	"github.com/kentrow/keymaker/internal/publicip"
)

// readOnlyClient answers with the read rules of the management key the README hands out,
// with no delete rule among them.
type readOnlyClient struct {
	rules []credential.AccessRule
}

var _ ovh.Client = (*readOnlyClient)(nil)

func (c *readOnlyClient) CurrentCredential(context.Context) (credential.Credential, error) {
	return credential.Credential{ID: 100, Status: credential.StatusValidated, Rules: c.rules}, nil
}

func (c *readOnlyClient) ListCredentialIDs(context.Context, credential.Status) ([]int64, error) {
	return []int64{100, 200}, nil
}

func (c *readOnlyClient) Credential(_ context.Context, id int64) (credential.Credential, error) {
	if id == 100 {
		return credential.Credential{ID: 100, Status: credential.StatusValidated, Rules: c.rules}, nil
	}
	return credential.Credential{ID: id, Status: credential.StatusValidated}, nil
}

func (c *readOnlyClient) Application(context.Context, int64) (credential.Application, error) {
	return credential.Application{}, nil
}

func (c *readOnlyClient) DeleteCredential(context.Context, int64) error { return nil }

func (c *readOnlyClient) CredentialApplication(context.Context, int64) (credential.Application, error) {
	return credential.Application{}, nil
}

func (c *readOnlyClient) DeleteApplication(context.Context, int64) error      { return nil }
func (c *readOnlyClient) ListApplicationIDs(context.Context) ([]int64, error) { return nil, nil }
func (c *readOnlyClient) Index(context.Context) ([]byte, error)               { return nil, nil }
func (c *readOnlyClient) Schema(context.Context, string) ([]byte, error)      { return nil, nil }

// emptyCatalog satisfies the option; this test is about the revocation offer, which the
// catalogue plays no part in.
type emptyCatalog struct{}

func (emptyCatalog) Current(context.Context) catalog.Snapshot { return catalog.Snapshot{} }

// The whole chain is assembled here rather than stubbed, because the defect this guards
// against is one of wiring: every piece was right on its own and the interface still
// offered an action the rules forbade.
func inventoryThrough(t *testing.T, client ovh.Client) map[string]any {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.New(httpapi.Options{
		Provider: legacy.New(client, logger),
		Catalog:  emptyCatalog{},
		Resolver: publicip.Disabled{},
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")}},
		Logger:   logger,
		Token:    "token",
		CSRF:     "csrf",
		Endpoint: "ovh-eu",
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/inventory", nil)
	req.AddCookie(&http.Cookie{Name: "keymaker_session", Value: "token"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return payload
}

func offers(t *testing.T, payload map[string]any) map[float64]map[string]any {
	t.Helper()

	out := map[float64]map[string]any{}
	for _, entry := range payload["credentials"].([]any) {
		item := entry.(map[string]any)
		out[item["id"].(float64)] = item["revoke"].(map[string]any)
	}
	return out
}

func TestAReadOnlyManagementKeyIsOfferedNoRevocation(t *testing.T) {
	client := &readOnlyClient{rules: []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential"},
		{Method: "GET", Path: "/me/api/credential/*"},
		{Method: "GET", Path: "/me/api/application/*"},
	}}

	found := offers(t, inventoryThrough(t, client))

	if found[100]["reason"] != "self" {
		t.Errorf("the credential in use: %+v, want it refused as self", found[100])
	}
	if found[200]["allowed"] != false || found[200]["reason"] != "missing-rule" {
		t.Errorf("another credential: %+v, want it refused for a missing rule", found[200])
	}
}

func TestAManagementKeyHoldingTheDeleteRuleIsOfferedRevocation(t *testing.T) {
	client := &readOnlyClient{rules: []credential.AccessRule{
		{Method: "GET", Path: "/me/api/credential/*"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
	}}

	found := offers(t, inventoryThrough(t, client))

	if found[200]["allowed"] != true {
		t.Errorf("another credential: %+v, want it offered", found[200])
	}
	if found[100]["reason"] != "self" {
		t.Errorf("the credential in use: %+v, want it refused as self", found[100])
	}
}
