// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClient struct {
	index   func(ctx context.Context) ([]byte, error)
	schemas map[string][]byte
	failOn  string
}

func (f *fakeClient) Index(ctx context.Context) ([]byte, error) {
	return f.index(ctx)
}

func (f *fakeClient) Schema(ctx context.Context, path string) ([]byte, error) {
	if path == f.failOn {
		return nil, errors.New("upstream refused")
	}
	document, ok := f.schemas[path]
	if !ok {
		return nil, errors.New("no such schema")
	}
	return document, nil
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func twoBranchClient(t *testing.T) *fakeClient {
	t.Helper()
	return &fakeClient{
		index: func(context.Context) ([]byte, error) {
			return []byte(`{"apis":[{"path":"/auth"},{"path":"/dedicated/cluster"}]}`), nil
		},
		schemas: map[string][]byte{
			"/auth.json":              fixture(t, "auth.json"),
			"/dedicated/cluster.json": fixture(t, "dedicated-cluster.json"),
		},
	}
}

func staleSnapshot() Snapshot {
	return Snapshot{
		Routes: []Route{{Path: "/me", Operations: []Operation{{Method: "GET"}}}},
		Taken:  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}
}

func TestARefreshReplacesTheSnapshotWithEveryBranch(t *testing.T) {
	remote := NewRemote(twoBranchClient(t), staleSnapshot(), discardLogger())

	if err := remote.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	got := remote.Current(t.Context())
	if !got.Live {
		t.Error("the catalogue is not reported as live after a successful refresh")
	}
	if len(got.Routes) != 14 {
		t.Fatalf("routes = %d, want 14 across the two branches", len(got.Routes))
	}
	if got.Routes[0].Path != "/auth/credential" {
		t.Errorf("first route = %q, want the catalogue ordered by path", got.Routes[0].Path)
	}
	if want := []string{"/auth", "/dedicated/cluster"}; !slices.Equal(got.Branches, want) {
		t.Errorf("branches = %v, want %v as the index lists them", got.Branches, want)
	}
	if got.Taken.Before(staleSnapshot().Taken) {
		t.Error("the refresh kept the date of the snapshot it replaced")
	}
}

func TestABranchThatFailsLeavesTheSnapshotInPlace(t *testing.T) {
	client := twoBranchClient(t)
	client.failOn = "/dedicated/cluster.json"
	remote := NewRemote(client, staleSnapshot(), discardLogger())

	if err := remote.Refresh(t.Context()); err == nil {
		t.Fatal("expected an error, got none")
	}

	got := remote.Current(t.Context())
	if got.Live {
		t.Error("a half-fetched catalogue was published as live")
	}
	if len(got.Routes) != 1 || got.Routes[0].Path != "/me" {
		t.Errorf("routes = %+v, want the snapshot untouched", got.Routes)
	}
}

func TestAnUnreadableIndexLeavesTheSnapshotInPlace(t *testing.T) {
	remote := NewRemote(&fakeClient{
		index: func(context.Context) ([]byte, error) { return nil, errors.New("unreachable") },
	}, staleSnapshot(), discardLogger())

	if err := remote.Refresh(t.Context()); err == nil {
		t.Fatal("expected an error, got none")
	}
	if remote.Current(t.Context()).Live {
		t.Error("the snapshot was reported as live")
	}
}

func TestASnapshotIsNeverReportedAsLive(t *testing.T) {
	stale := staleSnapshot()
	stale.Live = true

	remote := NewRemote(twoBranchClient(t), stale, discardLogger())
	if remote.current.Live {
		t.Error("a fallback claiming to be live was taken at its word")
	}
}

func TestARequestArrivingBeforeTheFirstRefreshWaitsForIt(t *testing.T) {
	release := make(chan struct{})
	client := twoBranchClient(t)
	held := client.index
	client.index = func(ctx context.Context) ([]byte, error) {
		<-release
		return held(ctx)
	}
	remote := NewRemote(client, staleSnapshot(), discardLogger())

	answered := make(chan Snapshot, 1)
	go func() { answered <- remote.Current(t.Context()) }()

	go func() {
		if err := remote.Refresh(t.Context()); err != nil {
			t.Errorf("Refresh: %v", err)
		}
	}()

	select {
	case got := <-answered:
		t.Fatalf("Current answered before the refresh finished, with %d routes", len(got.Routes))
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	if got := <-answered; !got.Live {
		t.Error("Current waited for the refresh and still answered from the snapshot")
	}
}

func TestARequestIsNotHeldBeyondItsOwnDeadline(t *testing.T) {
	remote := NewRemote(twoBranchClient(t), staleSnapshot(), discardLogger())

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got := remote.Current(ctx)
	if got.Live || len(got.Routes) != 1 {
		t.Errorf("snapshot = %+v, want the fallback returned at once", got)
	}
}

// The startup refresh can outlast what the server keeps a request open for. A request
// gets the snapshot after a bounded wait rather than a timeout with nothing.
func TestARequestIsNotHeldBeyondTheFirstRefreshWait(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	client := twoBranchClient(t)
	client.index = func(context.Context) ([]byte, error) {
		<-release
		return nil, errors.New("released")
	}
	remote := NewRemote(client, staleSnapshot(), discardLogger())
	remote.wait = 20 * time.Millisecond
	go func() { _ = remote.Refresh(t.Context()) }()

	started := time.Now()
	got := remote.Current(t.Context())
	if got.Live || len(got.Routes) != 1 {
		t.Errorf("snapshot = %+v, want the fallback", got)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("Current waited %v, want it bounded by the first refresh wait", waited)
	}
}

// A container often starts before its network is usable. A refresh that fails at that
// moment is tried again, and the live catalogue replaces the snapshot once one succeeds.
func TestAFailedRefreshIsRetriedUntilOneSucceeds(t *testing.T) {
	client := twoBranchClient(t)
	working := client.index
	var calls atomic.Int32
	client.index = func(ctx context.Context) ([]byte, error) {
		if calls.Add(1) < 3 {
			return nil, errors.New("network not ready")
		}
		return working(ctx)
	}
	remote := NewRemote(client, staleSnapshot(), discardLogger())
	remote.delays = []time.Duration{time.Millisecond}

	remote.RefreshInBackground(t.Context())

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if remote.Current(t.Context()).Live {
			if got := calls.Load(); got != 3 {
				t.Errorf("index calls = %d, want 3", got)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the catalogue never became live after %d attempts", calls.Load())
}

func TestRefreshingWhileTheCatalogueIsReadIsSafe(t *testing.T) {
	remote := NewRemote(twoBranchClient(t), staleSnapshot(), discardLogger())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			remote.Current(t.Context())
		}
	}()
	for range 5 {
		if err := remote.Refresh(t.Context()); err != nil {
			t.Errorf("Refresh: %v", err)
		}
	}
	<-done
}
