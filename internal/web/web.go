// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package web holds the interface served from the binary.
//
// Everything the browser loads is embedded here. Nothing is fetched at runtime: no CDN,
// no font, no analytics, which is what makes the outbound claim of S8 checkable rather
// than a promise.
//
// alpine-csp.min.js is the CSP build of Alpine 3.17.2, taken from
// https://cdn.jsdelivr.net/npm/@alpinejs/csp@3.17.2/dist/cdn.min.js, sha256
// 34a9a402fb8cc4904f411f17321a43fb3c55b825d3f57e9103c0e10cbb7ed8be, MIT, licence beside
// it. That build evaluates no expression string, which is what lets the content security
// policy keep script-src 'self' with no unsafe-eval. It also constrains the markup:
// directives may only name a property path or a method, so anything the templates would
// otherwise compute is prepared in app.js.
package web

import (
	"embed"
	"io/fs"
)

// The brand mark and the favicon are served from here like everything else: no icon is
// fetched from outside the binary, and the browser asks for the favicon with the session
// it already holds rather than through the implicit /favicon.ico, which the access token
// would refuse.
//
//go:embed static
var embedded embed.FS

// Assets is the interface, rooted so that index.html sits at the root of the site.
func Assets() fs.FS {
	assets, err := fs.Sub(embedded, "static")
	if err != nil {
		// The directory is embedded above; reaching this means the binary is malformed.
		panic(err)
	}
	return assets
}
