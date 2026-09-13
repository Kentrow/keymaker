// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReadsTheDocumentedFormat(t *testing.T) {
	cfg, err := Load("testdata/ovh.conf")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Default != "ovh-eu" {
		t.Errorf("Default = %q, want %q", cfg.Default, "ovh-eu")
	}

	account, err := cfg.Account()
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if account.Endpoint != "ovh-eu" {
		t.Errorf("Endpoint = %q, want %q", account.Endpoint, "ovh-eu")
	}
	if !account.Management.Complete() {
		t.Error("management credential reported incomplete")
	}
	if got, want := account.Management.ConsumerKey, "cccccccccccccccccccccccccccccccc"; got != want {
		t.Errorf("ConsumerKey = %q, want %q", got, want)
	}
}

// An ovh.conf written for a version that issued keys under a named application still
// carries that section. It is skipped rather than read as an endpoint, so a file that
// worked before keeps working.
func TestAnApplicationsSectionIsNotAnEndpoint(t *testing.T) {
	cfg, err := parse(strings.NewReader("[default]\nendpoint=ovh-eu\n[ovh-eu]\napplication_key=k\n[applications]\nterraform-prod=AK\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(cfg.Accounts) != 1 || cfg.Accounts[0].Endpoint != "ovh-eu" {
		t.Fatalf("accounts = %+v, want the endpoint alone", cfg.Accounts)
	}
}

func TestParseKeepsValuesLiteral(t *testing.T) {
	// A secret may contain a character that introduces a comment elsewhere in the
	// format. Cutting the value there would silently truncate it.
	cfg, err := parse(strings.NewReader("[ovh-eu]\napplication_secret=abc#def;ghi\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	account, err := cfg.Account()
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if got, want := account.Management.ApplicationSecret, "abc#def;ghi"; got != want {
		t.Errorf("ApplicationSecret = %q, want %q", got, want)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"no endpoint section":  "[default]\nendpoint=ovh-eu\n",
		"default without body": "[default]\nendpoint=ovh-ca\n\n[ovh-eu]\napplication_key=a\n",
		"key outside section":  "application_key=a\n", // gitleaks:allow
		"unterminated section": "[ovh-eu\n",
		"missing separator":    "[ovh-eu]\napplication_key\n",
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(strings.NewReader(input)); err == nil {
				t.Fatal("parse succeeded, want error")
			}
		})
	}
}

func TestParseErrorsCarryNoValue(t *testing.T) {
	secret := "s3cr3t-value"
	_, err := parse(strings.NewReader("[ovh-eu]\napplication_secret=" + secret + "\nbroken line\n"))
	if err == nil {
		t.Fatal("parse succeeded, want error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message carries a configured value: %v", err)
	}
}

func TestAnUnreadableFileNamesTheIdentityTheProcessRunsAs(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a file whatever its mode, so there is nothing to refuse")
	}

	path := filepath.Join(t.TempDir(), "ovh.conf")
	if err := os.WriteFile(path, []byte("[ovh-eu]\n"), 0o000); err != nil {
		t.Fatalf("writing the fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("error = %v, want a permission failure", err)
	}
	if want := fmt.Sprintf("uid %d", os.Getuid()); !strings.Contains(err.Error(), want) {
		t.Errorf("error = %q, want it to carry %q; without it the reader cannot tell which user was refused", err, want)
	}
}

func TestAMissingFileIsNotDressedUpAsAPermissionProblem(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.conf"))
	if err == nil {
		t.Fatal("expected an error, got none")
	}
	if strings.Contains(err.Error(), "uid ") {
		t.Errorf("error = %q, want no identity on a file that is simply not there", err)
	}
}
