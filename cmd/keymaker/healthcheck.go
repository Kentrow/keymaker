// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// healthTimeout bounds the whole check. An orchestrator gives it a few seconds, and a server
// that does not answer within this one is not healthy.
const healthTimeout = 3 * time.Second

// healthcheck asks the instance listening on addr for GET /healthz, so that the image can
// declare a HEALTHCHECK although it carries no shell and no HTTP client. It reads no
// configuration and holds no credential, and the one call it makes stays on the loopback.
func healthcheck(addr string) error {
	target, err := probeURL(addr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}

	// No proxy: the check is about this container, and a proxy from the environment would
	// answer for something else.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("health check: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health check: %s answered %s", target, response.Status)
	}
	return nil
}

// probeURL turns the address the server listens on into one to dial. A host left unspecified
// listens on every interface, and is reached on the loopback of its family.
func probeURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("KEYMAKER_ADDR %q: %w", addr, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
