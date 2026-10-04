// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"slices"
	"strings"
	"testing"
)

// A list of addresses is typed by the reader and ends up in a key's restriction. Whatever is
// typed, what comes out is a list the API stores as given: valid blocks, host bits cleared,
// none of length zero, none twice, no more than the bound; and reading that list again
// gives it back unchanged.
func FuzzReadAddresses(f *testing.F) {
	f.Add("192.0.2.7\n198.51.100.7/24, 198.51.100.0/24\n2001:db8::1")
	f.Add("0.0.0.0/0")
	f.Add("fe80::1%eth0")
	f.Add("::ffff:192.0.2.1")
	f.Add("not an address;;;,,")
	f.Add(strings.Repeat("192.0.2.1 ", maxAddresses+1))

	f.Fuzz(func(t *testing.T, typed string) {
		allowed, refusal := readAddresses(strings.Split(typed, "\n"))
		if refusal != nil {
			return
		}
		if len(allowed) > maxAddresses {
			t.Fatalf("%d blocks accepted, more than %d", len(allowed), maxAddresses)
		}
		written := make([]string, 0, len(allowed))
		for i, prefix := range allowed {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Bits() == 0 {
				t.Errorf("block %s is not one the API would store as given", prefix)
			}
			if slices.Contains(allowed[:i], prefix) {
				t.Errorf("block %s is listed twice", prefix)
			}
			written = append(written, prefix.String())
		}

		again, refusal := readAddresses(written)
		if refusal != nil || !slices.Equal(again, allowed) {
			t.Errorf("reading %v again gave %v, %v", written, again, refusal)
		}
	})
}
