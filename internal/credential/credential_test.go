// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package credential

import "testing"

func TestPermits(t *testing.T) {
	held := Credential{Rules: []AccessRule{
		{Method: "GET", Path: "/me/api/credential"},
		{Method: "GET", Path: "/me/api/credential/*"},
		{Method: "DELETE", Path: "/me/api/credential/*"},
		{Method: "POST", Path: "/domain/zone/*/record"},
	}}

	permitted := []struct{ method, path string }{
		{"GET", "/me/api/credential"},
		{"GET", "/me/api/credential/4210987"},
		{"DELETE", "/me/api/credential/4210987"},
		{"delete", "/me/api/credential/4210987"},
		{"POST", "/domain/zone/example.com/record"},
	}
	for _, call := range permitted {
		if !held.Permits(call.method, call.path) {
			t.Errorf("%s %s was read as forbidden", call.method, call.path)
		}
	}

	forbidden := []struct{ method, path string }{
		{"DELETE", "/me/api/credential"},
		{"POST", "/me/api/credential/4210987"},
		{"GET", "/me/api/application"},
		{"GET", "/me/api/applications/1"},
		{"POST", "/domain/zone/example.com"},
		{"DELETE", ""},
	}
	for _, call := range forbidden {
		if held.Permits(call.method, call.path) {
			t.Errorf("%s %s was read as permitted", call.method, call.path)
		}
	}
}

func TestPermitsWithABroadRule(t *testing.T) {
	held := Credential{Rules: []AccessRule{{Method: "DELETE", Path: "/*"}}}

	if !held.Permits("DELETE", "/me/api/credential/1") {
		t.Error("a rule on /* was read as not covering a call")
	}
	if held.Permits("GET", "/me/api/credential/1") {
		t.Error("a rule on one method was read as covering another")
	}
}

// A rule naming a single credential covers that one and no other.
func TestPermitsWithAnExactRule(t *testing.T) {
	held := Credential{Rules: []AccessRule{{Method: "DELETE", Path: "/me/api/credential/42"}}}

	if !held.Permits("DELETE", "/me/api/credential/42") {
		t.Error("the named credential was read as not covered")
	}
	if held.Permits("DELETE", "/me/api/credential/43") {
		t.Error("another credential was read as covered")
	}
}

func TestPermitsWithNoRules(t *testing.T) {
	if (Credential{}).Permits("GET", "/me/api/credential") {
		t.Error("a credential with no rules permitted a call")
	}
}
