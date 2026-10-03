// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/publicip"
)

// maxAddresses bounds the list a request may carry. The API documents no limit, and a key
// is restricted to the few hosts it runs from, not to a routing table.
const maxAddresses = 64

// Reasons the interface is not offered the address editor, beside reasonMissingRule.
const (
	reasonInactive  = "inactive"
	reasonLookupOff = "lookup-off"
)

// Codes the interface words for a list of addresses it would refuse.
const (
	codeBadAddress       = "bad-address"
	codeAnyAddressBlock  = "any-address-block"
	codeTooManyAddresses = "too-many-addresses"
	codeInactive         = "credential-inactive"
	codeSelfLookupOff    = "self-lookup-off"
	codeSelfLockout      = "self-lockout"
)

type addressesRequest struct {
	Addresses []string `json:"addresses"`
}

// addressesResponse is the list as the API will store it, so the reader confirms what is
// written rather than what was typed.
type addressesResponse struct {
	Addresses []string `json:"addresses"`

	// SeenFrom is the address this process is seen from, set when the credential is the one
	// the tool runs with: the list was checked against it.
	SeenFrom string `json:"seenFrom"`
}

// addressRefusal names the entry a list was refused for, beside the code.
type addressRefusal struct {
	errorResponse
	Entry string `json:"entry"`
}

// previewAddresses answers what a list would become, and whether it would be refused,
// without writing anything.
func (s *server) previewAddresses(w http.ResponseWriter, r *http.Request) {
	s.addresses(w, r, false)
}

// setAddresses replaces the addresses a credential accepts.
func (s *server) setAddresses(w http.ResponseWriter, r *http.Request) {
	s.addresses(w, r, true)
}

// addresses runs every check on a list, and writes it when apply is set. The preview and
// the write share this path, so what the reader confirmed is what is checked again at the
// moment of writing: the credential may have expired and the address of the process may
// have changed in between.
//
// The credential in use gets one more check. A list that leaves out the address this process
// is seen from locks the tool out of the account for good: the key can then make no call at
// all, not even the one that would undo the change. That address is looked up at the moment,
// and without the lookup the credential in use is not restricted.
func (s *server) addresses(w http.ResponseWriter, r *http.Request, apply bool) {
	ctx := r.Context()

	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Code:  codeBadIdentifier,
			Error: "the credential identifier is not a number",
		})
		return
	}

	var body addressesRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, addressRefusal{errorResponse: errorResponse{
			Code:  codeBadAddress,
			Error: "the request could not be read",
		}})
		return
	}

	allowed, failure := readAddresses(body.Addresses)
	if failure != nil {
		writeJSON(w, http.StatusBadRequest, failure)
		return
	}

	current, err := s.provider.Current(ctx)
	if err != nil {
		s.failAddresses(w, r, fmt.Errorf("%w: %w", credential.ErrIdentityUnavailable, err))
		return
	}
	target := current
	if id != current.ID {
		if target, err = s.provider.Get(ctx, id); err != nil {
			s.failAddresses(w, r, err)
			return
		}
	}
	if target.Status != credential.StatusValidated {
		writeJSON(w, http.StatusConflict, errorResponse{
			Code:  codeInactive,
			Error: "only a usable credential can have its addresses changed",
		})
		return
	}

	response := addressesResponse{Addresses: make([]string, 0, len(allowed))}
	for _, prefix := range allowed {
		response.Addresses = append(response.Addresses, prefix.String())
	}

	// An empty list lets the tool in from anywhere, so only a restriction can lock it out.
	if target.ID == current.ID && len(allowed) > 0 {
		seenFrom, err := s.resolver.Address(ctx)
		switch {
		case errors.Is(err, publicip.ErrDisabled):
			writeJSON(w, http.StatusConflict, errorResponse{
				Code:  codeSelfLookupOff,
				Error: "this instance cannot look up the address it is seen from, so it does not restrict the credential it runs with",
			})
			return
		case err != nil:
			s.logger.WarnContext(ctx, "public address lookup failed", "error", err)
			writeJSON(w, http.StatusBadGateway, errorResponse{
				Code:  codeLookupFailed,
				Error: "the address could not be looked up",
			})
			return
		}
		response.SeenFrom = seenFrom.String()
		if !slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(seenFrom) }) {
			writeJSON(w, http.StatusConflict, addressRefusal{
				errorResponse: errorResponse{
					Code:  codeSelfLockout,
					Error: "this list leaves out the address this instance is seen from, and would lock the tool out of the account",
				},
				Entry: seenFrom.String(),
			})
			return
		}
	}

	if !apply {
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := s.provider.SetAddresses(ctx, target.ID, allowed); err != nil {
		s.failAddresses(w, r, err)
		return
	}

	s.logger.InfoContext(ctx, "credential addresses changed", "credential", target.ID, "addresses", len(allowed))
	writeJSON(w, http.StatusOK, response)
}

// readAddresses turns what was typed into the list the API will store: a bare address gets
// the mask of a single host, host bits are cleared, and a repeated block is kept once. The
// API refuses a bare address and stores the rest as sent, so doing it here is what lets the
// reader see the result before it is written.
func readAddresses(sent []string) ([]netip.Prefix, *addressRefusal) {
	var entries []string
	for _, line := range sent {
		entries = append(entries, strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		})...)
	}
	if len(entries) > maxAddresses {
		return nil, &addressRefusal{errorResponse: errorResponse{
			Code:  codeTooManyAddresses,
			Error: "a key accepts at most " + strconv.Itoa(maxAddresses) + " address blocks here",
		}}
	}

	allowed := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, ok := readAddress(entry)
		if !ok {
			return nil, &addressRefusal{errorResponse: errorResponse{
				Code:  codeBadAddress,
				Error: "an entry is not an address or an address block",
			}, Entry: entry}
		}
		// Such a block lets every address of its family in, which the API accepts and the
		// audit reports as no restriction at all.
		if prefix.Bits() == 0 {
			return nil, &addressRefusal{errorResponse: errorResponse{
				Code:  codeAnyAddressBlock,
				Error: "a block of length zero restricts nothing",
			}, Entry: entry}
		}
		if !slices.Contains(allowed, prefix) {
			allowed = append(allowed, prefix)
		}
	}
	return allowed, nil
}

func readAddress(entry string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		if prefix.Addr().Is4In6() {
			return netip.Prefix{}, false
		}
		return prefix.Masked(), true
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func (s *server) failAddresses(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.ErrorContext(r.Context(), "address change failed", "path", r.URL.Path, "error", err)

	switch {
	case errors.Is(err, credential.ErrIdentityUnavailable):
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeIdentityUnknown,
			Error: "the tool could not establish which credential it authenticates with, so it did not go ahead",
		})
	case errors.Is(err, credential.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{
			Code:  codeAlreadyRevoked,
			Error: "the OVHcloud API no longer knows this credential; it was already revoked",
		})
	case errors.Is(err, credential.ErrPermissionDenied):
		writeJSON(w, http.StatusForbidden, errorResponse{
			Code:  codePermissionDenied,
			Error: "the OVHcloud API refused this change; the usual cause is an access rule the management key does not hold",
		})
	default:
		writeJSON(w, http.StatusBadGateway, errorResponse{
			Code:  codeAPIFailure,
			Error: "the OVHcloud API refused the change, see the process log",
		})
	}
}

// addressOffer says whether the interface should offer editing the addresses of target, and
// why not when it should not.
func (s *server) addressOffer(current *credential.Credential, target credential.Credential) offerResponse {
	switch {
	case target.Status != credential.StatusValidated:
		return offerResponse{Reason: reasonInactive}
	case current == nil:
		// Nothing to decide from; the attempt is offered and the checks above have the last
		// word, the identity among them.
		return offerResponse{Allowed: true}
	case !s.provider.AddressesEditable(*current, target):
		return offerResponse{Reason: reasonMissingRule}
	case current.ID == target.ID && !s.resolver.Enabled():
		return offerResponse{Reason: reasonLookupOff}
	default:
		return offerResponse{Allowed: true}
	}
}
