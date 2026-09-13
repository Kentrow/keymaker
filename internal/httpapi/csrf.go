// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/subtle"
	"net/http"
)

// csrfHeader carries the token the page was handed with its inventory. A cross-site page
// cannot read that token, and cannot set a custom header on a simple request either, so
// requiring it here is what stops another site from driving a revocation through a
// session this browser already holds.
const csrfHeader = "X-Keymaker-Csrf"

// guardMutations lets read requests through and requires the token on everything else.
// The list of safe methods is fixed here rather than left to each handler, so a route
// added later is covered by default instead of on remembering to cover it.
//
// A request no route accepts is left to the router, which answers 404 or 405 and runs no
// handler. Checking the token first answered 403 to a method the route does not take, which
// read as a missing token rather than as the wrong method.
func (s *server) guardMutations(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			mux.ServeHTTP(w, r)
			return
		}
		if _, pattern := mux.Handler(r); pattern == "" {
			mux.ServeHTTP(w, r)
			return
		}

		if subtle.ConstantTimeCompare([]byte(r.Header.Get(csrfHeader)), []byte(s.csrf)) != 1 {
			writeJSON(w, http.StatusForbidden, errorResponse{
				Code:  codeMissingToken,
				Error: "this request did not carry the token handed to the page",
			})
			return
		}
		mux.ServeHTTP(w, r)
	})
}
