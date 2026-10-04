// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"os"
	"testing"
)

func seedWith(f *testing.F, files ...string) {
	f.Helper()
	for _, name := range files {
		if sample, err := os.ReadFile("testdata/" + name); err == nil {
			f.Add(sample)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"apis":[{"path":""}]}`))
	f.Add([]byte(`not json`))
}

// The index comes from the network. Whatever it holds, only branches shaped like an API path
// may come out of it, since each one becomes the URL of the next request.
func FuzzParseIndex(f *testing.F) {
	seedWith(f, "index.json")

	f.Fuzz(func(t *testing.T, raw []byte) {
		branches, err := parseIndex(raw)
		if err != nil {
			return
		}
		if len(branches) == 0 {
			t.Fatal("an index was accepted with no branch")
		}
		for _, branch := range branches {
			if !branchPath.MatchString(branch) {
				t.Errorf("branch %q is not an API path", branch)
			}
		}
	})
}

// A schema comes from the network too. Every route read out of one has a path and at least
// one operation with a method, and turning it into a rule path never fails.
func FuzzParseSchema(f *testing.F) {
	seedWith(f, "auth.json", "dedicated-cluster.json")

	f.Fuzz(func(t *testing.T, raw []byte) {
		routes, err := parseSchema(raw)
		if err != nil {
			return
		}
		for _, route := range routes {
			if route.Path == "" || len(route.Operations) == 0 {
				t.Fatalf("route %+v has no path or no operation", route)
			}
			for _, operation := range route.Operations {
				if operation.Method == "" {
					t.Errorf("route %s has an operation without a method", route.Path)
				}
			}
			if !Parameterised(route.Path) && RulePath(route.Path) != route.Path {
				t.Errorf("RulePath changed %q, which names no parameter", route.Path)
			}
		}
	})
}
