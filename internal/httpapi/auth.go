// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

const (
	sessionCookie  = "keymaker_session"
	tokenParameter = "token"

	tokenBytes = 32
)

// NewToken returns the access token the process prints at startup. It is generated on
// every start and never stored, so closing the tool ends every session it handed out.
func NewToken() (string, error) {
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// authenticate gates everything but the health endpoint.
//
// The token arrives once in the URL the process printed, is moved into a cookie, and is
// then stripped from the address bar by a redirect, so it stops appearing in history and
// in whatever the browser hands to a page opened afterwards.
func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath {
			next.ServeHTTP(w, r)
			return
		}

		if cookie, err := r.Cookie(sessionCookie); err == nil && s.tokenMatches(cookie.Value) {
			next.ServeHTTP(w, r)
			return
		}

		if s.tokenMatches(r.URL.Query().Get(tokenParameter)) {
			s.grant(w, r)
			return
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func (s *server) tokenMatches(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.token)) == 1
}

func (s *server) grant(w http.ResponseWriter, r *http.Request) {
	// The cookie carries no Secure attribute. The tool is reached over plain HTTP on
	// loopback, and an operator who opts into a routable bind address would otherwise get
	// a cookie the browser drops, leaving the interface unusable rather than safer.
	// #nosec G124 -- HttpOnly and SameSite are set; Secure cannot apply over plain HTTP.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	query := r.URL.Query()
	query.Del(tokenParameter)

	// The target is rebuilt from the path alone rather than reusing the request URL. A
	// request line in absolute form carries a scheme and a host, and a path starting with
	// two slashes is protocol-relative; either would turn this redirect into one that
	// leaves the site.
	target := url.URL{Path: "/", RawQuery: query.Encode()}
	if path := r.URL.EscapedPath(); strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
		target.Path = path
	}

	http.Redirect(w, r, target.RequestURI(), http.StatusSeeOther)
}
