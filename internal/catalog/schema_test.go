// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return raw
}

func TestTheIndexYieldsEveryBranch(t *testing.T) {
	branches, err := parseIndex(fixture(t, "index.json"))
	if err != nil {
		t.Fatalf("parseIndex: %v", err)
	}

	for _, want := range []string{"/auth", "/me", "/dedicated/cluster"} {
		if !slices.Contains(branches, want) {
			t.Errorf("branch %q missing from %d branches", want, len(branches))
		}
	}
}

func TestABranchNamingSomethingOtherThanAPathIsDropped(t *testing.T) {
	raw := []byte(`{"apis":[
		{"path":"/me"},
		{"path":"https://elsewhere.example/x"},
		{"path":"//elsewhere.example/x"},
		{"path":"/me/../../etc/passwd"},
		{"path":""}
	]}`)

	branches, err := parseIndex(raw)
	if err != nil {
		t.Fatalf("parseIndex: %v", err)
	}
	if want := []string{"/me"}; !slices.Equal(branches, want) {
		t.Errorf("branches = %v, want %v", branches, want)
	}
}

func TestAnIndexWithNoUsableBranchIsAnError(t *testing.T) {
	if _, err := parseIndex([]byte(`{"apis":[]}`)); err == nil {
		t.Fatal("expected an error, got none")
	}
	if _, err := parseIndex([]byte(`not json`)); err == nil {
		t.Fatal("expected an error, got none")
	}
}

func TestASchemaYieldsItsRoutesAndMethods(t *testing.T) {
	routes, err := parseSchema(fixture(t, "auth.json"))
	if err != nil {
		t.Fatalf("parseSchema: %v", err)
	}
	if len(routes) != 6 {
		t.Fatalf("routes = %d, want 6", len(routes))
	}

	byPath := make(map[string]Route, len(routes))
	for _, route := range routes {
		byPath[route.Path] = route
	}

	credential, ok := byPath["/auth/credential"]
	if !ok {
		t.Fatal("/auth/credential missing from the parsed schema")
	}
	if len(credential.Operations) != 1 || credential.Operations[0].Method != "POST" {
		t.Fatalf("operations = %+v, want a single POST", credential.Operations)
	}
	if credential.Operations[0].Description == "" {
		t.Error("the operation carries no description, which is what the explorer shows")
	}
}

func TestADeprecatedOperationIsKeptAndMarked(t *testing.T) {
	routes, err := parseSchema(fixture(t, "dedicated-cluster.json"))
	if err != nil {
		t.Fatalf("parseSchema: %v", err)
	}

	var found bool
	for _, route := range routes {
		for _, op := range route.Operations {
			if route.Path == "/dedicated/cluster/availabilities" && op.Method == "GET" {
				found = true
				if !op.Deprecated {
					t.Error("the operation is marked DEPRECATED by the API but not by the parser")
				}
			}
			if route.Path == "/dedicated/cluster" && op.Deprecated {
				t.Error("a production operation was marked deprecated")
			}
		}
	}
	if !found {
		t.Fatal("the deprecated operation is missing from the parsed schema")
	}
}

func TestAnOperationWithoutAMethodIsDropped(t *testing.T) {
	raw := []byte(`{"apis":[
		{"path":"/thing","operations":[{"httpMethod":""}]},
		{"path":"","operations":[{"httpMethod":"GET"}]},
		{"path":"/other","operations":[{"httpMethod":"GET","description":"  padded  "}]}
	]}`)

	routes, err := parseSchema(raw)
	if err != nil {
		t.Fatalf("parseSchema: %v", err)
	}
	if len(routes) != 1 || routes[0].Path != "/other" {
		t.Fatalf("routes = %+v, want only /other", routes)
	}
	if got := routes[0].Operations[0].Description; got != "padded" {
		t.Errorf("description = %q, want it trimmed", got)
	}
}

func TestMergeOrdersRoutesAndKeepsOneEntryPerMethod(t *testing.T) {
	first := []Route{
		{Path: "/b", Operations: []Operation{{Method: "GET"}}},
		{Path: "/a", Operations: []Operation{{Method: "POST"}}},
	}
	second := []Route{
		{Path: "/a", Operations: []Operation{{Method: "POST"}, {Method: "DELETE"}}},
	}

	routes := merge(first, second)
	if len(routes) != 2 || routes[0].Path != "/a" || routes[1].Path != "/b" {
		t.Fatalf("routes = %+v, want /a then /b", routes)
	}

	methods := make([]string, 0, len(routes[0].Operations))
	for _, op := range routes[0].Operations {
		methods = append(methods, op.Method)
	}
	if want := []string{"DELETE", "POST"}; !slices.Equal(methods, want) {
		t.Errorf("methods = %v, want %v", methods, want)
	}
}

func TestARuleCarriesAWildcardWhereTheRouteNamesAParameter(t *testing.T) {
	cases := []struct {
		documented string
		rule       string
		parametric bool
	}{
		{"/me/api/credential", "/me/api/credential", false},
		{"/me/api/credential/{credentialId}", "/me/api/credential/*", true},
		{"/dedicated/server/{serviceName}/task/{taskId}", "/dedicated/server/*/task/*", true},
		{"/me/api/credential/{credentialId}/application", "/me/api/credential/*/application", true},
	}

	for _, c := range cases {
		if got := RulePath(c.documented); got != c.rule {
			t.Errorf("RulePath(%q) = %q, want %q", c.documented, got, c.rule)
		}
		if got := Parameterised(c.documented); got != c.parametric {
			t.Errorf("Parameterised(%q) = %v, want %v", c.documented, got, c.parametric)
		}
	}
}

func TestEveryPublishedRouteSurvivesTheConversionToARule(t *testing.T) {
	routes, err := parseSchema(fixture(t, "dedicated-cluster.json"))
	if err != nil {
		t.Fatalf("parseSchema: %v", err)
	}
	for _, route := range routes {
		rule := RulePath(route.Path)
		if rule == "" {
			t.Errorf("route %q produced an empty rule", route.Path)
		}
		if Parameterised(rule) {
			t.Errorf("rule %q still names a parameter", rule)
		}
	}
}

func TestTheSchemaOfABranchIsItsJSONDocument(t *testing.T) {
	if got := schemaPath("/dedicated/cluster"); got != "/dedicated/cluster.json" {
		t.Errorf("schemaPath = %q", got)
	}
}
