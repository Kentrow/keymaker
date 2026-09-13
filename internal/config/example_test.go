// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

func TestTheShippedExampleParses(t *testing.T) {
	body, err := os.ReadFile("../../ovh.conf.example")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	cfg, err := parse(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	account, err := cfg.Account()
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if account.Endpoint != "ovh-eu" {
		t.Errorf("Endpoint = %q", account.Endpoint)
	}
	if account.Management.Complete() {
		t.Error("the example ships with a complete credential")
	}
}
