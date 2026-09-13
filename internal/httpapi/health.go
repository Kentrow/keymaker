// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"io"
	"net/http"
)

const healthPath = "/healthz"

// health answers container healthchecks and orchestrator probes.
//
// The response is fixed. It reports neither version, nor configuration, nor operational
// state, so that the one route reachable without the access token cannot be used to
// fingerprint the instance.
func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "ok\n")
}
