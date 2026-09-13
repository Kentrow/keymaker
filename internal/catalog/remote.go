// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Source supplies the two documents a catalogue is built from. The API client
// satisfies it; the snapshot generator implements it over a bare HTTP request, so that
// producing the embedded copy uses the same parsing as a live refresh.
type Source interface {
	Index(ctx context.Context) ([]byte, error)
	Schema(ctx context.Context, path string) ([]byte, error)
}

// fanOut bounds the number of schema documents in flight. The API publishes seventy
// branches and roughly ten megabytes of schema; fetching them one after another makes
// the explorer wait, fetching all seventy at once is a burst nobody asked for.
const fanOut = 8

// firstRefreshWait bounds how long a request waits for the startup refresh. The fetch can
// take minutes on a slow network, longer than the server would keep the request open, and
// a dated catalogue on screen is better than a request that times out with nothing.
const firstRefreshWait = 15 * time.Second

// attemptTimeout bounds one refresh. The whole catalogue is close to ten megabytes, and
// giving up only costs the freshness of a fallback that is already on board.
const attemptTimeout = 2 * time.Minute

// retryDelays space the attempts after a failed refresh. A container often starts before
// its network is usable, and a single attempt at that moment would leave the snapshot in
// place for the whole run. The last delay repeats until a refresh succeeds.
var retryDelays = []time.Duration{10 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute}

// Remote is the catalogue backed by the API, with an embedded snapshot standing in
// until the fetch succeeds and for as long as it keeps failing.
type Remote struct {
	source   Source
	log      *slog.Logger
	fallback Snapshot

	// ready is closed once the first refresh has finished, successfully or not. A
	// request arriving during that window waits for it rather than being handed a dated
	// catalogue that a reload would silently replace.
	ready     chan struct{}
	closeOnce sync.Once

	mu      sync.RWMutex
	current Snapshot

	// wait and delays are firstRefreshWait and retryDelays, held per instance so that tests
	// can shorten them.
	wait   time.Duration
	delays []time.Duration
}

var _ Catalog = (*Remote)(nil)

// NewRemote serves fallback until a refresh replaces it.
func NewRemote(source Source, fallback Snapshot, log *slog.Logger) *Remote {
	fallback.Live = false
	return &Remote{
		source:   source,
		log:      log,
		fallback: fallback,
		ready:    make(chan struct{}),
		current:  fallback,
		wait:     firstRefreshWait,
		delays:   retryDelays,
	}
}

// Current is the catalogue to browse. It waits for the first refresh while ctx allows, and
// for firstRefreshWait at most, then answers with whatever is available, which is the
// embedded snapshot when the refresh has not finished or did not succeed.
func (r *Remote) Current(ctx context.Context) Snapshot {
	timer := time.NewTimer(r.wait)
	defer timer.Stop()

	select {
	case <-r.ready:
	case <-ctx.Done():
	case <-timer.C:
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// Refresh fetches the catalogue and publishes it. A failure leaves the previous
// catalogue in place: the caller decides whether to try again, and the interface keeps
// working from the snapshot in the meantime.
func (r *Remote) Refresh(ctx context.Context) error {
	defer r.closeOnce.Do(func() { close(r.ready) })

	fetched, err := Fetch(ctx, r.source)
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = fetched
	return nil
}

// Fetch builds a catalogue from one source. It is exported so that the embedded
// snapshot is produced by the same code that refreshes it at runtime, rather than by a
// generator whose parsing could drift from the parsing the application uses.
func Fetch(ctx context.Context, source Source) (Snapshot, error) {
	raw, err := source.Index(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read the API index: %w", err)
	}
	branches, err := parseIndex(raw)
	if err != nil {
		return Snapshot{}, err
	}

	batches := make([][]Route, len(branches))
	failures := make([]error, len(branches))

	work := make(chan int)
	var workers sync.WaitGroup
	for range min(fanOut, len(branches)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range work {
				document, err := source.Schema(ctx, schemaPath(branches[i]))
				if err != nil {
					failures[i] = fmt.Errorf("schema of %s: %w", branches[i], err)
					continue
				}
				if batches[i], failures[i] = parseSchema(document); failures[i] != nil {
					failures[i] = fmt.Errorf("schema of %s: %w", branches[i], failures[i])
				}
			}
		}()
	}
	for i := range branches {
		work <- i
	}
	close(work)
	workers.Wait()

	// A branch that failed would leave a hole nothing on screen could point at, and a
	// user would read the absence of a route as the API not offering it. The catalogue
	// is therefore all of the API or none of it: an incomplete answer is discarded in
	// favour of the snapshot, which is at least complete and dated.
	for _, err := range failures {
		if err != nil {
			return Snapshot{}, err
		}
	}
	return Snapshot{
		Routes:   merge(batches...),
		Branches: branches,
		Taken:    time.Now().UTC(),
		Live:     true,
	}, nil
}

// RefreshInBackground starts the startup refresh without holding the interface back, and
// keeps trying until one succeeds or ctx ends. The catalogue is a browsing aid: the
// inventory, the revocation path and the health endpoint all work without it, so a failure
// is logged and the snapshot serves on in the meantime.
func (r *Remote) RefreshInBackground(ctx context.Context) {
	go func() {
		for attempt := 0; ; attempt++ {
			attemptCtx, cancel := context.WithTimeout(ctx, attemptTimeout)
			err := r.Refresh(attemptCtx)
			cancel()
			if err == nil {
				r.log.Info("route catalogue loaded", "routes", len(r.Current(ctx).Routes))
				return
			}

			delay := r.delays[min(attempt, len(r.delays)-1)]
			r.log.Warn("route catalogue unavailable, serving the embedded snapshot",
				"error", err, "snapshot", r.fallback.Taken.Format(time.DateOnly), "retry_in", delay)

			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()
}
