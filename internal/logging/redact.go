// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package logging keeps secrets out of the logs.
//
// The guarantee is placed in the logging pipeline rather than at every call site,
// because the call site that leaks a secret is by definition the one nobody thought
// about. Values registered on a Redactor are replaced wherever they appear in a record:
// in the message, in an attribute key, in an attribute value, and inside groups.
package logging

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Placeholder is what a registered value is replaced with.
const Placeholder = "[redacted]"

// Redactor holds the values that must never reach a log line. It is safe for concurrent
// use, so registering a value never has to be ordered against the requests being logged.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// Add registers a value. Empty values are ignored, since replacing an empty string would
// match everywhere.
func (r *Redactor) Add(secrets ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range secrets {
		if s == "" || r.known(s) {
			continue
		}
		r.secrets = append(r.secrets, s)
	}
}

func (r *Redactor) known(secret string) bool {
	for _, s := range r.secrets {
		if s == secret {
			return true
		}
	}
	return false
}

// Scrub replaces every registered value found in s.
func (r *Redactor) Scrub(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, Placeholder)
	}
	return s
}

// NewHandler wraps next so that everything it writes has been scrubbed first.
func NewHandler(next slog.Handler, r *Redactor) slog.Handler {
	return handler{next: next, redactor: r}
}

type handler struct {
	next     slog.Handler
	redactor *Redactor
}

func (h handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h handler) Handle(ctx context.Context, record slog.Record) error {
	scrubbed := slog.NewRecord(record.Time, record.Level, h.redactor.Scrub(record.Message), record.PC)
	record.Attrs(func(a slog.Attr) bool {
		scrubbed.AddAttrs(h.scrub(a))
		return true
	})
	return h.next.Handle(ctx, scrubbed)
}

func (h handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = h.scrub(a)
	}
	return handler{next: h.next.WithAttrs(scrubbed), redactor: h.redactor}
}

func (h handler) WithGroup(name string) slog.Handler {
	return handler{next: h.next.WithGroup(h.redactor.Scrub(name)), redactor: h.redactor}
}

// scrub keeps the original value when it holds no secret, so that a number stays a
// number for the underlying handler and only a tainted value degrades to a string.
func (h handler) scrub(a slog.Attr) slog.Attr {
	key := h.redactor.Scrub(a.Key)
	value := a.Value.Resolve()

	if value.Kind() == slog.KindGroup {
		group := value.Group()
		scrubbed := make([]slog.Attr, len(group))
		for i, member := range group {
			scrubbed[i] = h.scrub(member)
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(scrubbed...)}
	}

	rendered := value.String()
	if clean := h.redactor.Scrub(rendered); clean != rendered {
		return slog.String(key, clean)
	}
	return slog.Attr{Key: key, Value: value}
}
