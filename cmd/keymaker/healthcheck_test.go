// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTheProbeDialsTheLoopbackOfAnUnspecifiedHost(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:8080":   "http://127.0.0.1:8080/healthz",
		":8080":          "http://127.0.0.1:8080/healthz",
		"[::]:8080":      "http://[::1]:8080/healthz",
		"127.0.0.1:9000": "http://127.0.0.1:9000/healthz",
		"[::1]:9000":     "http://[::1]:9000/healthz",
	}
	for addr, want := range cases {
		got, err := probeURL(addr)
		if err != nil || got != want {
			t.Errorf("probeURL(%q) = %q, %v; want %q", addr, got, err, want)
		}
	}
	if _, err := probeURL("8080"); err == nil {
		t.Error("an address without a port was accepted")
	}
}

func serving(t *testing.T, status int) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func TestAHealthyServerPassesTheCheck(t *testing.T) {
	if err := healthcheck(serving(t, http.StatusOK)); err != nil {
		t.Errorf("healthcheck: %v", err)
	}
}

func TestAnUnhealthyOrSilentServerFailsTheCheck(t *testing.T) {
	if err := healthcheck(serving(t, http.StatusServiceUnavailable)); err == nil {
		t.Error("a server answering 503 passed the check")
	}

	var config net.ListenConfig
	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().String()
	_ = listener.Close()
	if err := healthcheck(closed); err == nil {
		t.Error("a port nothing listens on passed the check")
	}
}

// The check runs beside a server that holds the configuration; it must not need any itself,
// nor print anything a log collector would keep.
func TestTheCheckNeedsNoConfiguration(t *testing.T) {
	t.Setenv("KEYMAKER_ADDR", serving(t, http.StatusOK))
	t.Setenv("KEYMAKER_CONFIG", "/nowhere/ovh.conf")

	var out strings.Builder
	if err := run([]string{"healthcheck"}, &out); err != nil {
		t.Fatalf("run healthcheck: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("the check printed %q", out.String())
	}
}
