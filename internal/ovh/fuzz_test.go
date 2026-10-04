// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// An address block as the API returns it. Whatever the string, it reads as a valid block
// or as an error.
func FuzzParsePrefix(f *testing.F) {
	for _, seed := range []string{"192.0.2.1", "192.0.2.0/24", "2001:db8::/32", "::1", "", "1.2.3.4/33", "x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		prefix, err := parsePrefix(value)
		if err == nil && !prefix.IsValid() {
			t.Errorf("parsePrefix(%q) = %v, an invalid block with no error", value, prefix)
		}
	})
}

// A credential as the API describes it, the largest document read from it. Whatever it
// holds, it decodes into a credential or an error.
func FuzzCredentialDecoding(f *testing.F) {
	for _, name := range []string{"credential_validated.json", "credential_unlimited.json", "credential_support.json"} {
		if sample, err := os.ReadFile("testdata/" + name); err == nil {
			f.Add(sample)
		}
	}
	f.Add([]byte(`{"allowedIPs":["not an address"]}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var wire apiCredential
		if json.Unmarshal(raw, &wire) != nil {
			return
		}
		got, err := wire.toDomain()
		if err != nil {
			return
		}
		for _, prefix := range got.AllowedIPs {
			if !prefix.IsValid() {
				t.Errorf("credential %d holds an invalid block %v", got.ID, prefix)
			}
		}
	})
}

// Retry-After comes from the API, or from anything in between. Whatever it says, the wait
// stays between zero and the ceiling.
func FuzzRetryAfter(f *testing.F) {
	for _, seed := range []string{"", "0", "3", "3600", "-5", "soon", "Sun, 04 Oct 2026 12:00:04 GMT", "9999999999", "99999999999999999999"} {
		f.Add(seed)
	}
	p := pacing{fallback: time.Second, ceiling: 10 * time.Second}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, header string) {
		if wait := p.delay(header, now); wait < 0 || wait > p.ceiling {
			t.Errorf("delay(%q) = %s, outside 0 to %s", header, wait, p.ceiling)
		}
	})
}
