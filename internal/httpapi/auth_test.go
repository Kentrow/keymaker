// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"strings"
	"testing"
)

func TestTheTokenIsNotGuessable(t *testing.T) {
	seen := map[string]bool{}

	for range 50 {
		token, err := NewToken()
		if err != nil {
			t.Fatalf("NewToken: %v", err)
		}
		if len(token) < 40 {
			t.Fatalf("token is %d characters, too short to resist guessing", len(token))
		}
		if strings.ContainsAny(token, "+/=") {
			t.Errorf("token %q needs escaping to travel in a URL", token)
		}
		if seen[token] {
			t.Fatal("the same token came out twice")
		}
		seen[token] = true
	}
}
