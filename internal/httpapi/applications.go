// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/kentrow/keymaker/internal/credential"
)

// applicationsResponse lists the applications of the account with how many credentials point
// at each, so the interface can show the ones holding no key at all.
//
// Revoking a key leaves its application behind, and an application is a key and a secret a new
// credential can still be requested under, on a page the account holder has to validate. The
// inventory cannot show them: it reads credentials, and these have none.
type applicationsResponse struct {
	// Listed says whether the listing could be read. It is false when the management
	// credential holds no rule for it, which is a legitimate way to run the tool.
	Listed bool   `json:"listed"`
	Reason string `json:"reason"`

	Applications []applicationUse `json:"applications"`

	// Unreadable counts the applications the listing named and the detail call would not
	// describe, the same way the inventory counts unreadable credentials.
	Unreadable int `json:"unreadable"`
}

type applicationUse struct {
	ID          int64  `json:"id"`
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// Credentials is how many keys of the account were issued under this application.
	Credentials int `json:"credentials"`

	// Delete says whether deleting this application is offered, and why not when it is not.
	Delete deleteOffer `json:"delete"`
}

type deleteOffer struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// Reasons an application is not offered for deletion. Codes rather than sentences: the
// wording belongs to the interface, which is translated.
const (
	reasonApplicationInUse = "in-use"
)

// applicationListingPath is the route the listing takes, and what a rule has to cover for the
// interface to offer it.
const applicationListingPath = "/me/api/application"

func (s *server) applications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Read before asking: a management key without the listing rule would be refused by the
	// API, and the reader is better told which rule is missing than shown a failed call.
	if own, err := s.provider.Current(ctx); err == nil && !own.Permits(http.MethodGet, applicationListingPath) {
		writeJSON(w, http.StatusOK, applicationsResponse{Reason: reasonMissingRule, Applications: []applicationUse{}})
		return
	}

	applications, err := s.provider.Applications(ctx)
	if applications == nil {
		s.fail(w, r, err)
		return
	}

	unreadable := 0
	var incomplete *credential.IncompleteError
	if errors.As(err, &incomplete) {
		unreadable = incomplete.Unreadable
		s.logger.WarnContext(ctx, "some applications could not be read", "unreadable", unreadable, "error", incomplete.Err)
	}

	// The count comes from the same listing the inventory shows, so both screens agree on
	// which application a key belongs to.
	used := map[int64]int{}
	if credentials, _, listErr := s.list(ctx); listErr == nil {
		for _, c := range credentials {
			used[c.Application.ID]++
		}
	} else {
		s.logger.WarnContext(ctx, "applications listed without their credentials", "error", listErr)
	}

	var current *credential.Credential
	if own, err := s.provider.Current(ctx); err == nil {
		current = &own
	}

	response := applicationsResponse{Listed: true, Applications: make([]applicationUse, 0, len(applications)), Unreadable: unreadable}
	for _, a := range applications {
		response.Applications = append(response.Applications, applicationUse{
			ID:          a.ID,
			Key:         a.Key,
			Name:        a.Name,
			Description: a.Description,
			Credentials: used[a.ID],
			Delete:      s.deletionOffer(current, a.ID, used[a.ID]),
		})
	}

	writeJSON(w, http.StatusOK, response)
}

// deletionOffer says whether the interface should offer deleting an application, and why not
// when it should not. An application still holding a key is never offered: the API would
// revoke that key along with it.
func (s *server) deletionOffer(current *credential.Credential, id int64, credentials int) deleteOffer {
	switch {
	case credentials > 0:
		return deleteOffer{Reason: reasonApplicationInUse}
	case current == nil:
		// The rules of the credential in use could not be read, so there is nothing to decide
		// from. The attempt is offered and the API has the last word.
		return deleteOffer{Allowed: true}
	case !s.provider.DeletableApplication(*current, id):
		return deleteOffer{Reason: reasonMissingRule}
	default:
		return deleteOffer{Allowed: true}
	}
}

// deleteApplication removes an application that holds no key.
//
// The guard that matters is in the provider, which counts the credentials of the application
// against the API rather than against what a screen was showing. This handler only turns its
// refusals into something the interface can word.
func (s *server) deleteApplication(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Code:  codeBadIdentifier,
			Error: "the application identifier is not a number",
		})
		return
	}

	if err := s.provider.DeleteApplication(r.Context(), id); err != nil {
		s.failApplicationDeletion(w, r, err)
		return
	}

	s.logger.InfoContext(r.Context(), "application deleted", "application", id)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) failApplicationDeletion(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "application deletion failed", "path", r.URL.Path, "error", err)

	switch {
	case errors.Is(err, credential.ErrApplicationInUse):
		writeJSON(w, http.StatusConflict, errorResponse{
			Code:  codeApplicationInUse,
			Error: "this application still holds a key, and deleting it would revoke that key",
		})
	case errors.Is(err, credential.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{
			Code:  codeApplicationGone,
			Error: "the OVHcloud API no longer knows this application; it was already deleted",
		})
	case errors.Is(err, credential.ErrPermissionDenied):
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codePermissionDenied,
			Error: "the OVHcloud API refused this deletion; the usual cause is an access rule the management key does not hold",
		})
	default:
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeAPIFailure,
			Error: "the OVHcloud API refused the deletion, see the process log",
		})
	}
}

// keylessSweepResponse reports what the deletion did, application by application. One that
// fails does not stop the ones after it: the reader confirmed a set, and a set half deleted
// with no account of which half would be worse than either outcome.
type keylessSweepResponse struct {
	Deleted []int64            `json:"deleted"`
	Failed  []applicationError `json:"failed"`
}

type applicationError struct {
	ID   int64  `json:"id"`
	Code string `json:"code"`
}

// deleteKeylessApplications deletes every application of the account that holds no key.
//
// The request carries no list, and that is the point. A deletion that took its targets from the
// browser would let anything reaching this endpoint name any application; here the selection is
// made from what the API answers, which is the same source the interface was shown. The reader
// confirms a set, not a list of identifiers.
//
// It is also the only set where deleting in bulk is defensible: an application holding no key
// grants nothing on its own, so nothing stops working. An application with a key keeps its own
// guard, and is refused here as it is on the single path.
func (s *server) deleteKeylessApplications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	applications, err := s.provider.Applications(ctx)
	if applications == nil {
		s.fail(w, r, err)
		return
	}

	credentials, _, err := s.list(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	used := map[int64]int{}
	for _, c := range credentials {
		used[c.Application.ID]++
	}

	var current *credential.Credential
	if own, identity := s.provider.Current(ctx); identity == nil {
		current = &own
	} else {
		s.logger.WarnContext(ctx, "cannot identify the credential in use", "error", identity)
	}

	response := keylessSweepResponse{Deleted: []int64{}, Failed: []applicationError{}}
	for _, application := range applications {
		if used[application.ID] > 0 {
			continue
		}

		// Holding no key does not grant the deletion anything: an application the management
		// key holds no delete rule for is refused here exactly as on the single path.
		if offer := s.deletionOffer(current, application.ID, 0); !offer.Allowed {
			response.Failed = append(response.Failed, applicationError{ID: application.ID, Code: codePermissionDenied})
			continue
		}

		if err := s.provider.DeleteApplicationAgainst(ctx, credentials, application.ID); err != nil {
			s.logger.ErrorContext(ctx, "application deletion failed", "application", application.ID, "error", err)
			response.Failed = append(response.Failed, applicationError{ID: application.ID, Code: applicationErrorCode(err)})
			continue
		}

		s.logger.InfoContext(ctx, "application deleted", "application", application.ID)
		response.Deleted = append(response.Deleted, application.ID)
	}

	writeJSON(w, http.StatusOK, response)
}

func applicationErrorCode(err error) string {
	switch {
	case errors.Is(err, credential.ErrApplicationInUse):
		return codeApplicationInUse
	case errors.Is(err, credential.ErrNotFound):
		return codeApplicationGone
	case errors.Is(err, credential.ErrPermissionDenied):
		return codePermissionDenied
	default:
		return codeAPIFailure
	}
}
