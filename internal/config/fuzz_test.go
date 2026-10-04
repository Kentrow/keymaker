// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

// The configuration file is the one input the operator writes by hand. Whatever it holds,
// reading it must end in a configuration or an error, never a crash; and a configuration
// accepted must name an account that exists, with every value trimmed the way the parser
// promises.
func FuzzParse(f *testing.F) {
	if sample, err := os.ReadFile("testdata/ovh.conf"); err == nil {
		f.Add(string(sample))
	}
	f.Add("[default]\nendpoint=ovh-eu\n\n[ovh-eu]\napplication_key=a\napplication_secret=b#c\nconsumer_key=d\n")
	f.Add("[ovh-ca]\napplication_key = spaced \n")
	f.Add("; comment\n[default]\nendpoint=missing\n[ovh-us]\n")
	f.Add("key=outside\n")
	f.Add("[unterminated\n")

	f.Fuzz(func(t *testing.T, content string) {
		cfg, err := parse(strings.NewReader(content))
		if err != nil {
			return
		}
		account, err := cfg.Account()
		if err != nil {
			t.Fatalf("an accepted configuration names no account: %v", err)
		}
		for _, value := range []string{account.Name, account.Management.ApplicationKey, account.Management.ApplicationSecret, account.Management.ConsumerKey} {
			if value != strings.TrimSpace(value) {
				t.Errorf("value %q kept surrounding space", value)
			}
			// A lone carriage return inside a line is kept, as every other character of a
			// value is; only a line break cannot be part of one.
			if strings.Contains(value, "\n") {
				t.Errorf("value %q spans lines", value)
			}
		}
	})
}
