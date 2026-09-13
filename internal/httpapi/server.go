// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the local web interface and the JSON it reads.
package httpapi

import (
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/kentrow/keymaker/internal/catalog"
	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
	"github.com/kentrow/keymaker/internal/publicip"
)

// contentSecurityPolicy allows nothing the binary does not serve itself. It carries no
// unsafe-inline and no unsafe-eval, which is why the frontend uses the CSP build of
// Alpine and keeps its scripts and styles in files rather than in attributes.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

// Options is what the server needs to answer.
type Options struct {
	Provider credential.Provider
	Catalog  catalog.Catalog
	Assets   fs.FS
	Logger   *slog.Logger

	// Token is required on every request but the health endpoint.
	Token string

	// CSRF is handed to the page with its inventory and required back on every mutation.
	// It is separate from Token: the access token travels in a cookie the browser attaches
	// on its own, which is exactly what a cross-site request would rely on.
	CSRF string

	// Endpoint names the region the inventory belongs to, shown in the interface so that
	// an instance pointed at the wrong account is obvious.
	Endpoint string

	// Version is what this build calls itself, shown in the footer. A reader reporting a
	// problem is reporting it about a build, and the interface is where they are.
	Version string

	// Resolver answers what address this process is seen from, when the reader asks for
	// it. publicip.Disabled makes the instance refuse rather than call out.
	Resolver publicip.Resolver
}

type server struct {
	provider credential.Provider
	// managementKeyURL is resolved once at startup: the endpoint cannot change while the
	// process runs, and a request is a poor moment to discover it is unsupported.
	managementKeyURL string

	catalog  catalog.Catalog
	resolver publicip.Resolver
	token    string
	csrf     string
	endpoint string
	version  string
	logger   *slog.Logger
}

func New(opts Options) http.Handler {
	s := &server{
		provider: opts.Provider,
		catalog:  opts.Catalog,
		resolver: opts.Resolver,
		token:    opts.Token,
		csrf:     opts.CSRF,
		endpoint: opts.Endpoint,
		version:  opts.Version,
		logger:   opts.Logger,
	}

	// An endpoint the table does not know cannot reach the API either, so the process
	// would already have stopped. The link is simply left out rather than guessed at.
	if link, err := ovh.CreateTokenURL(opts.Endpoint, ovh.ManagementRules); err == nil {
		s.managementKeyURL = link
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+healthPath, health)
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("GET /api/inventory", s.inventory)
	mux.HandleFunc("GET /api/catalogue", s.catalogue)
	mux.HandleFunc("DELETE /api/credentials/{id}", s.revoke)
	mux.HandleFunc("POST /api/credentials/inactive/revocations", s.revokeInactive)
	mux.HandleFunc("GET /api/address", s.publicAddress)
	mux.HandleFunc("POST /api/handoff", s.handoff)
	mux.Handle("GET /", http.FileServerFS(opts.Assets))

	return s.logRequests(securityHeaders(s.authenticate(s.guardMutations(mux))))
}

// logRequests records each request at debug level: method, path, status and duration. The
// query string is left out on purpose, since the address that opens a session carries the
// access token in it.
func (s *server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.logger.Enabled(r.Context(), slog.LevelDebug) {
			next.ServeHTTP(w, r)
			return
		}

		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		next.ServeHTTP(recorder, r)
		s.logger.DebugContext(r.Context(), "request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", recorder.status,
			"duration", time.Since(started).Round(time.Millisecond))
	})
}

// statusRecorder remembers the status a handler answered with, for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(status int) {
	if !r.written {
		r.status, r.written = status, true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("Content-Security-Policy", contentSecurityPolicy)
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("Referrer-Policy", "no-referrer")
		header.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
