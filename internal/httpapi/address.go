// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"

	"github.com/kentrow/keymaker/internal/publicip"
)

const codeLookupDisabled = "lookup-disabled"
const codeLookupFailed = "lookup-failed"

type addressResponse struct {
	Address string `json:"address"`
}

// publicAddress answers what address this process is seen from, so that a reader
// restricting a key to one address does not have to go and find it elsewhere.
//
// The answer is the address of the process, not of the browser. They are the same when
// the tool runs on the machine the key will be used from, which is the documented way to
// run it, and the interface says which one it is showing rather than letting the reader
// assume.
//
// This is the one call Keymaker makes outside the OVHcloud API. It happens only when
// asked, never on its own, and an instance started with the lookup off refuses here.
func (s *server) publicAddress(w http.ResponseWriter, r *http.Request) {
	address, err := s.resolver.Address(r.Context())
	if errors.Is(err, publicip.ErrDisabled) {
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codeLookupDisabled,
			Error: "this instance was started with the address lookup switched off",
		})
		return
	}
	if err != nil {
		s.logger.WarnContext(r.Context(), "public address lookup failed", "error", err)
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeLookupFailed,
			Error: "the address could not be looked up",
		})
		return
	}

	writeJSON(w, http.StatusOK, addressResponse{Address: address.String()})
}
