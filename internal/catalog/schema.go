// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// branchPath is what a top-level entry of the index is allowed to look like before the
// code turns it into a schema URL. The paths come from the API rather than from a
// request, so this is not the anti-SSRF boundary of S5; it is there so that a
// surprising index cannot quietly widen the set of URLs fetched, which would be hard to
// notice and hard to explain afterwards.
var branchPath = regexp.MustCompile(`^(/[A-Za-z0-9][A-Za-z0-9._-]*)+$`)

// placeholder matches the "{serviceName}" segments the API documents its routes with.
var placeholder = regexp.MustCompile(`\{[^/{}]*\}`)

type indexDocument struct {
	APIs []struct {
		Path string `json:"path"`
	} `json:"apis"`
}

type schemaDocument struct {
	APIs []struct {
		Path       string `json:"path"`
		Operations []struct {
			Method      string `json:"httpMethod"`
			Description string `json:"description"`
			APIStatus   struct {
				Value string `json:"value"`
			} `json:"apiStatus"`
		} `json:"operations"`
	} `json:"apis"`
}

// parseIndex reads GET /1.0/ and returns the branches whose schema is worth fetching.
func parseIndex(raw []byte) ([]string, error) {
	var doc indexDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unreadable API index: %w", err)
	}

	branches := make([]string, 0, len(doc.APIs))
	for _, api := range doc.APIs {
		if branchPath.MatchString(api.Path) {
			branches = append(branches, api.Path)
		}
	}
	if len(branches) == 0 {
		return nil, fmt.Errorf("the API index advertises no usable branch")
	}
	return branches, nil
}

// schemaPath is the document describing one branch. The index advertises it as the
// template "{path}.{format}", which is expanded here rather than carried around: the
// only format this code reads is JSON.
func schemaPath(branch string) string {
	return branch + ".json"
}

// parseSchema reads one branch schema into routes.
func parseSchema(raw []byte) ([]Route, error) {
	var doc schemaDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("unreadable schema: %w", err)
	}

	routes := make([]Route, 0, len(doc.APIs))
	for _, api := range doc.APIs {
		if api.Path == "" {
			continue
		}
		operations := make([]Operation, 0, len(api.Operations))
		for _, op := range api.Operations {
			if op.Method == "" {
				continue
			}
			operations = append(operations, Operation{
				Method:      op.Method,
				Description: strings.TrimSpace(op.Description),
				Deprecated:  op.APIStatus.Value == "DEPRECATED",
			})
		}
		if len(operations) == 0 {
			continue
		}
		routes = append(routes, Route{Path: api.Path, Operations: operations})
	}
	return routes, nil
}

// merge collects the routes of several branches into one ordered catalogue. A path is
// expected to be described by a single branch, but the schemas overlap here and there,
// and a route silently listed twice would be shown twice.
func merge(batches ...[]Route) []Route {
	byPath := make(map[string][]Operation)
	for _, batch := range batches {
		for _, route := range batch {
			for _, op := range route.Operations {
				existing := byPath[route.Path]
				if slicesContainsMethod(existing, op.Method) {
					continue
				}
				byPath[route.Path] = append(existing, op)
			}
		}
	}

	routes := make([]Route, 0, len(byPath))
	for path, operations := range byPath {
		sort.Slice(operations, func(i, j int) bool { return operations[i].Method < operations[j].Method })
		routes = append(routes, Route{Path: path, Operations: operations})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })
	return routes
}

func slicesContainsMethod(operations []Operation, method string) bool {
	for _, op := range operations {
		if op.Method == method {
			return true
		}
	}
	return false
}

// RulePath turns a documented route into the path an access rule can carry.
//
// A rule has no notion of a named parameter: "/me/api/credential/{credentialId}" is not
// something the API accepts, and the equivalent covering every identifier is
// "/me/api/credential/*". The substitution widens the rule, which is why the explorer
// shows the result rather than applying it out of sight.
func RulePath(documented string) string {
	return placeholder.ReplaceAllString(documented, "*")
}

// Parameterised reports whether a documented route names a parameter, and therefore
// whether RulePath widens it into a pattern.
func Parameterised(documented string) bool {
	return placeholder.MatchString(documented)
}
