// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/kentrow/keymaker/internal/credential"
)

// Reasons the interface is not offered a revocation. They are codes rather than sentences:
// the wording belongs to the interface, which is translated.
const (
	reasonSelf        = "self"
	reasonMissingRule = "missing-rule"
)

type revokeResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Code:  codeBadIdentifier,
			Error: "the credential identifier is not a number",
		})
		return
	}

	if err := s.provider.Revoke(r.Context(), id); err != nil {
		s.failRevocation(w, r, err)
		return
	}

	s.logger.InfoContext(r.Context(), "credential revoked", "credential", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) failRevocation(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "revocation failed", "path", r.URL.Path, "error", err)

	switch {
	case errors.Is(err, credential.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{
			Code:  codeAlreadyRevoked,
			Error: "the OVHcloud API no longer knows this credential; it was already revoked",
		})
	// Checked before the refusal below, which it wraps: the reader has to be told the
	// identity call failed, not that a delete rule is missing.
	case errors.Is(err, credential.ErrIdentityUnavailable):
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeIdentityUnknown,
			Error: "the tool could not establish which credential it authenticates with, so it did not go ahead",
		})
	case errors.Is(err, credential.ErrSelfRevocation):
		// The interface disables this, but the guard that matters is the one here: it holds
		// whoever reaches the API directly, and it holds when the interface is wrong about
		// which credential is in use.
		writeJSON(w, http.StatusConflict, errorResponse{
			Code:  codeSelfRevocation,
			Error: "the credential this tool authenticates with cannot revoke itself",
		})
	case errors.Is(err, credential.ErrPermissionDenied):
		// Named as a refusal rather than as a diagnosis. A 403 most often means a missing
		// access rule, but it is the API saying no, not this tool knowing why, and the
		// process log carries what the API actually said.
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codePermissionDenied,
			Error: "the OVHcloud API refused this revocation; the usual cause is an access rule the management key does not hold",
		})
	default:
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeAPIFailure,
			Error: "the OVHcloud API refused the revocation, see the process log",
		})
	}
}

// revocationOffer says whether the interface should offer revoking target, and why not
// when it should not.
func (s *server) revocationOffer(current *credential.Credential, target credential.Credential) revokeResponse {
	switch {
	case current == nil:
		// The rules of the credential in use could not be read, so there is nothing to
		// decide from. The attempt is offered and the API has the last word.
		return revokeResponse{Allowed: true}
	case current.ID == target.ID:
		return revokeResponse{Reason: reasonSelf}
	case !s.provider.Revocable(*current, target):
		return revokeResponse{Reason: reasonMissingRule}
	default:
		return revokeResponse{Allowed: true}
	}
}
