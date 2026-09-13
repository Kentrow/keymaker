// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/kentrow/keymaker/internal/credential"
)

// sweepResponse reports what the sweep did, key by key. A revocation that fails does not
// stop the ones after it: the reader asked for the set, and a set half revoked with no
// account of which half would be worse than either outcome.
type sweepResponse struct {
	Revoked []int64        `json:"revoked"`
	Failed  []sweepFailure `json:"failed"`
}

type sweepFailure struct {
	ID   int64  `json:"id"`
	Code string `json:"code"`
}

// revokeInactive revokes every expired or refused credential on the account.
//
// The request carries no list, and that is the point. A bulk revocation that took its
// targets from the browser would let anything reaching this endpoint name any key; here the
// selection is made from what the API answers, which is the same source the interface was
// shown. The reader confirms a set, not a list of identifiers.
//
// The set is also the only one where revoking in bulk is defensible: an expired or refused
// credential opens nothing, so nothing stops working. A validated key is somebody's running
// integration and keeps its own confirmation, typed identifier and all.
func (s *server) revokeInactive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var current *credential.Credential
	own, identity := s.provider.Current(ctx)
	if identity == nil {
		current = &own
	} else {
		s.logger.WarnContext(ctx, "cannot identify the credential in use", "error", identity)
	}

	credentials, _, err := s.list(ctx)
	if err != nil {
		s.failInventory(w, r, err, identity)
		return
	}

	response := sweepResponse{Revoked: []int64{}, Failed: []sweepFailure{}}
	for _, target := range credentials {
		if !inactive(target.Status) {
			continue
		}

		// The status alone does not grant the sweep anything: a credential the tool
		// authenticates with, or one the management key holds no delete rule for, is
		// refused here exactly as it is on the single path.
		if offer := s.revocationOffer(current, target); !offer.Allowed {
			response.Failed = append(response.Failed, sweepFailure{ID: target.ID, Code: sweepCode(offer.Reason)})
			continue
		}

		err := s.revokeOne(ctx, current, target.ID)
		switch {
		case errors.Is(err, credential.ErrNotFound):
			// Gone already, which is what the sweep was asked to achieve.
			s.logger.InfoContext(ctx, "credential was already revoked", "credential", target.ID)
		case err != nil:
			s.logger.ErrorContext(ctx, "revocation failed", "credential", target.ID, "error", err)
			response.Failed = append(response.Failed, sweepFailure{ID: target.ID, Code: revocationCode(err)})
			continue
		}

		s.logger.InfoContext(ctx, "credential revoked", "credential", target.ID)
		response.Revoked = append(response.Revoked, target.ID)
	}

	writeJSON(w, http.StatusOK, response)
}

// revokeOne reads the identity again only when the start of the request could not. When it
// could, the credential in use is already known, and reading it once per key of the set
// would multiply the calls without strengthening the guard.
func (s *server) revokeOne(ctx context.Context, current *credential.Credential, id int64) error {
	if current == nil {
		return s.provider.Revoke(ctx, id)
	}
	return s.provider.RevokeAgainst(ctx, *current, id)
}

func inactive(status credential.Status) bool {
	return status == credential.StatusExpired || status == credential.StatusRefused
}

func sweepCode(reason string) string {
	if reason == reasonSelf {
		return codeSelfRevocation
	}
	return codePermissionDenied
}

func revocationCode(err error) string {
	switch {
	case errors.Is(err, credential.ErrIdentityUnavailable):
		return codeIdentityUnknown
	case errors.Is(err, credential.ErrSelfRevocation):
		return codeSelfRevocation
	case errors.Is(err, credential.ErrPermissionDenied):
		return codePermissionDenied
	default:
		return codeAPIFailure
	}
}
