// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import "net/http"

// sessionResponse is what the page needs before it can do anything, and nothing more.
//
// It is served apart from the inventory because the two do not depend on the same
// permissions: creating a key needs none at all, while listing keys needs the read rules
// of the management credential. An account whose inventory is refused can still create,
// and would not be able to if the token it has to send back only ever arrived with a
// successful listing.
type sessionResponse struct {
	Endpoint string `json:"endpoint"`

	// Version is what this build calls itself. The footer shows it, so that a report about
	// the interface names the build it was seen on.
	Version string `json:"version"`

	// CSRF is required on every mutation. It is separate from the access token, which
	// travels in a cookie the browser attaches on its own.
	CSRF string `json:"csrf"`

	// AddressLookup says whether this instance may look its public address up, so that
	// the interface offers the shortcut only when it leads somewhere.
	AddressLookup bool `json:"addressLookup"`

	// ManagementKeyURL opens the OVHcloud page that issues a management credential, with
	// the management rules prefilled, on the host of the configured region. It is
	// served here rather than only in the documentation because the moment it is needed is
	// the moment the credential stopped working, and every other screen is refused.
	ManagementKeyURL string `json:"managementKeyUrl"`
}

func (s *server) session(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, sessionResponse{
		Endpoint:         s.endpoint,
		Version:          s.version,
		CSRF:             s.csrf,
		AddressLookup:    s.resolver.Enabled(),
		ManagementKeyURL: s.managementKeyURL,
	})
}
