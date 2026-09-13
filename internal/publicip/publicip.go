// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package publicip resolves the address this process is seen from on the Internet.
//
// It is the one outbound call Keymaker makes outside the OVHcloud API, and it exists
// because no OVHcloud endpoint reports the caller's address: auth.Details carries the
// account, the allowed routes, the method and the roles, and nothing in the published
// catalogue answers the question. It is documented in SECURITY.md.
//
// The call is never made on its own. It happens when the reader asks for it, and the
// whole feature can be switched off, so that an instance can be run with nothing but
// api.ovh.com on its outbound path.
package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// service is the address of the resolver. It is a constant rather than a setting: a
// resolver named by configuration would be one more place a request could point the
// process at, and the outbound guarantee is only worth stating if the destination is
// fixed and readable here.
const service = "https://api.ipify.org"

const timeout = 5 * time.Second

// limit is what the answer is allowed to weigh. An address is a few dozen bytes; the
// cap is what keeps a service answering something else from being read at all.
const limit = 64

// ErrDisabled is returned when the instance was started with the lookup switched off.
var ErrDisabled = errors.New("public address lookup is disabled on this instance")

// Resolver reports the address this process is seen from.
type Resolver interface {
	Address(ctx context.Context) (netip.Addr, error)

	// Enabled says whether asking would lead anywhere, so that an interface can leave the
	// shortcut out rather than offer one that always refuses.
	Enabled() bool
}

// Service resolves through the configured third party.
type Service struct {
	client   *http.Client
	endpoint string
}

var _ Resolver = (*Service)(nil)

func New(client *http.Client) *Service {
	return &Service{client: client, endpoint: service}
}

// Disabled is the resolver of an instance that must make no outbound call other than to
// the OVHcloud API. It refuses rather than answering an address it did not look up.
type Disabled struct{}

var _ Resolver = Disabled{}

func (Disabled) Address(context.Context) (netip.Addr, error) {
	return netip.Addr{}, ErrDisabled
}

func (Disabled) Enabled() bool { return false }

func (s *Service) Enabled() bool { return true }

func (s *Service) Address(ctx context.Context) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return netip.Addr{}, err
	}

	response, err := s.client.Do(request)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reach the address resolver: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("the address resolver answered %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, limit))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read the address resolver: %w", err)
	}

	// Parsed strictly: whatever comes back is either an address or it is discarded. The
	// value goes on to prefill a rule that decides which machines a key answers to, so a
	// resolver returning an error page must not turn into a restriction nobody chose.
	address, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, errors.New("the address resolver answered something that is not an address")
	}
	return address, nil
}
