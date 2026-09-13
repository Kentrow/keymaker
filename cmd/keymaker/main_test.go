// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func entry(t *testing.T, addr, public, token string) (string, error) {
	t.Helper()

	base, err := baseURL(addr, public)
	if err != nil {
		return "", err
	}
	return entryPoint(base, token), nil
}

func TestEntryPointFallsBackToLoopback(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:8080": "http://127.0.0.1:8080/?token=t",
		"0.0.0.0:8080":   "http://127.0.0.1:8080/?token=t",
		"[::]:8080":      "http://127.0.0.1:8080/?token=t",
	}

	for addr, want := range cases {
		got, err := entry(t, addr, "", "t")
		if err != nil {
			t.Fatalf("entry(%q): %v", addr, err)
		}
		if got != want {
			t.Errorf("entry(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestEntryPointPrefersThePublishedAddress(t *testing.T) {
	got, err := entry(t, "0.0.0.0:8080", "http://127.0.0.1:8124", "t")
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	if got != "http://127.0.0.1:8124/?token=t" {
		t.Errorf("entry = %q", got)
	}
}

// A published address that cannot be used has to stop the process: it is also where the
// SSO validation return lands, and a silent fallback would fail much later and elsewhere.
func TestAnUnusablePublishedAddressStopsTheProcess(t *testing.T) {
	for _, public := range []string{"127.0.0.1:8124", "/callback", "not a url"} {
		if _, err := baseURL("0.0.0.0:8080", public); err == nil {
			t.Errorf("baseURL(%q) succeeded, want an error", public)
		}
	}
}

func TestBindsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true,
		"[::1]:8080":     true,
		"0.0.0.0:8080":   false,
		"192.0.2.4:80":   false,
		"localhost:8080": false,
		"nonsense":       false,
	} {
		if got := bindsLoopback(addr); got != want {
			t.Errorf("bindsLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestTheLogLevelIsReadFromTheEnvironment(t *testing.T) {
	cases := map[string]slog.Level{"": slog.LevelInfo, "info": slog.LevelInfo, "DEBUG": slog.LevelDebug, " warn ": slog.LevelWarn, "error": slog.LevelError}
	for value, want := range cases {
		got, err := logLevel(value)
		if err != nil || got != want {
			t.Errorf("logLevel(%q) = %v, %v, want %v", value, got, err, want)
		}
	}
	if _, err := logLevel("verbose"); err == nil {
		t.Error("an unknown level was accepted")
	}
}

// --version answers before anything else is read, so it works without a configuration file.
func TestTheVersionFlagPrintsTheBuildAndReadsNothingElse(t *testing.T) {
	t.Setenv("KEYMAKER_CONFIG", "/nonexistent/ovh.conf")
	version, commit, date = "1.2.3", "abc1234", "2026-01-02T03:04:05Z"
	t.Cleanup(func() { version, commit, date = "dev", "unknown", "unknown" })

	var out bytes.Buffer
	if err := run([]string{"--version"}, &out); err != nil {
		t.Fatalf("run --version: %v", err)
	}
	if got, want := strings.TrimSpace(out.String()), "keymaker 1.2.3 (commit abc1234, built 2026-01-02T03:04:05Z)"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestAnUnknownFlagIsRefused(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"--nope"}, &out); err == nil {
		t.Error("an unknown flag was accepted")
	}
}
