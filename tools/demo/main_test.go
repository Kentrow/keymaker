// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/kentrow/keymaker/internal/credential"
)

func get(t *testing.T, handler http.Handler, path string, into any) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: "keymaker_session", Value: "token"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
}

// The demo is where a change to the interface is looked at, so it has to show every finding
// the audit can raise. A finding added without a key to show it would go unseen there, and
// this names it.
func TestTheDemoShowsEveryFinding(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "internal", "audit", "audit.go"))
	if err != nil {
		t.Fatalf("read the audit source: %v", err)
	}
	declared := regexp.MustCompile(`(?m)^\t[A-Z][A-Za-z]*\s+Code = "([a-z-]+)"`).FindAllStringSubmatch(string(source), -1)
	if len(declared) == 0 {
		t.Fatal("no finding code found in internal/audit")
	}

	handler, err := newHandler(newStore(time.Now()), "token", "csrf", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	var inventory struct {
		Credentials []struct {
			Status      string `json:"status"`
			Application struct {
				Deleted bool `json:"deleted"`
			} `json:"application"`
			Findings []struct {
				Code string `json:"code"`
			} `json:"findings"`
		} `json:"credentials"`
		Summary struct {
			Examined int `json:"examined"`
			Flagged  int `json:"flagged"`
		} `json:"summary"`
	}
	get(t, handler, "/api/inventory", &inventory)

	shown := map[string]bool{}
	inactive, orphaned := false, false
	for _, c := range inventory.Credentials {
		orphaned = orphaned || c.Application.Deleted
		for _, finding := range c.Findings {
			shown[finding.Code] = true
		}
		inactive = inactive || c.Status == string(credential.StatusExpired) || c.Status == string(credential.StatusRefused)
	}
	for _, match := range declared {
		if !shown[match[1]] {
			t.Errorf("no key of the demo raises %q", match[1])
		}
	}
	if !inactive {
		t.Error("no inactive key in the demo, so the sweep that revokes them never shows")
	}
	if !orphaned {
		t.Error("no key whose application was deleted in the demo, so how one reads never shows")
	}
	if inventory.Summary.Examined-inventory.Summary.Flagged < 1 {
		t.Error("every key of the demo is flagged, so it never shows what a sound key looks like")
	}

	var applications struct {
		Applications []struct {
			Credentials int `json:"credentials"`
		} `json:"applications"`
	}
	get(t, handler, "/api/applications", &applications)

	keyless := false
	for _, a := range applications.Applications {
		keyless = keyless || a.Credentials == 0
	}
	if !keyless {
		t.Error("no application without a key in the demo, so that banner never shows")
	}
}

// The demo refuses what a real account refuses, or it would show an interface that offers
// things the real one never does.
func TestTheDemoKeepsTheGuardsOfTheRealProvider(t *testing.T) {
	ctx := context.Background()
	store := newStore(time.Now())

	if err := store.Revoke(ctx, store.current.ID); !errors.Is(err, credential.ErrSelfRevocation) {
		t.Errorf("revoking the key in use: %v, want ErrSelfRevocation", err)
	}
	if err := store.DeleteApplication(ctx, store.current.Application.ID); !errors.Is(err, credential.ErrApplicationInUse) {
		t.Errorf("deleting the application of a key: %v, want ErrApplicationInUse", err)
	}

	if err := store.Revoke(ctx, 118821300); err != nil {
		t.Fatalf("revoking an expired key: %v", err)
	}
	if _, err := store.Get(ctx, 118821300); !errors.Is(err, credential.ErrNotFound) {
		t.Errorf("the revoked key is still there: %v", err)
	}
	if err := store.Revoke(ctx, 118821300); !errors.Is(err, credential.ErrNotFound) {
		t.Errorf("revoking it twice: %v, want ErrNotFound", err)
	}

	// Its application now holds no key and can go.
	if err := store.DeleteApplication(ctx, 7115); err != nil {
		t.Errorf("deleting the application left without a key: %v", err)
	}

	// The way out takes the key in use, as a key holding the delete rule would be taken.
	retired, err := store.Retire(ctx)
	if err != nil || !retired.Deleted || retired.ID != store.current.ID {
		t.Fatalf("Retire = %+v, %v, want the key in use deleted", retired, err)
	}
	if _, err := store.Get(ctx, store.current.ID); !errors.Is(err, credential.ErrNotFound) {
		t.Errorf("the retired key is still listed: %v", err)
	}
}

// A large account is a few hundred more keys of the same kind, which the server lists and the
// audit reads like the others.
func TestTheDemoGrowsToALargeAccount(t *testing.T) {
	store := newStore(time.Now())
	before := len(store.credentials)
	store.pad(500, time.Now())

	handler, err := newHandler(store, "token", "csrf", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Credentials []struct {
			ID int64 `json:"id"`
		} `json:"credentials"`
	}
	get(t, handler, "/api/inventory", &inventory)

	if got := len(inventory.Credentials); got != before+500 {
		t.Errorf("credentials = %d, want %d", got, before+500)
	}
}
