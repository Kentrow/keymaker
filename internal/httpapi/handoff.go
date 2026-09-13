// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/kentrow/keymaker/internal/credential"
	"github.com/kentrow/keymaker/internal/ovh"
)

// methodsAllowed is the set an access rule may name, as the published auth.HTTPMethodEnum
// lists it.
var methodsAllowed = []string{"DELETE", "GET", "PATCH", "POST", "PUT"}

// Codes the interface words in the reader's language for a rule it would refuse.
const (
	codeMalformedRule = "malformed-rule"
	codeNoRules       = "no-rules"
)

// refusal is a reason a request was turned down, carried back to the handler that answers.
type refusal struct {
	status  int
	payload errorResponse
}

type handoffRequest struct {
	Rules []ruleResponse `json:"rules"`
}

type handoffResponse struct {
	URL string `json:"url"`
}

// handoff forges the OVHcloud page that issues a key carrying these rules.
//
// It is the only way to obtain a key without already holding an application: no endpoint
// creates one, and the page does both at once. What it cannot carry is
// the name, the description, the validity and the allowed addresses, which the reader
// fills in there; the rules are what this tool is for and they travel.
//
// The address is built here rather than in the browser for the same reason the wildcard
// substitution is: the rules a reader is shown and the rules they are
// sent to agree on are then produced by one piece of code. The page never receives a URL
// from the frontend either, which is what keeps S5 true of every outbound address this
// process names.
func (s *server) handoff(w http.ResponseWriter, r *http.Request) {
	var body handoffRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{
			Code:  codeMalformedRule,
			Error: "the request could not be read",
		})
		return
	}

	rules, failure := readRules(body.Rules)
	if failure != nil {
		writeJSON(w, failure.status, failure.payload)
		return
	}

	page, err := ovh.CreateTokenURL(s.endpoint, rules)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, handoffResponse{URL: page})
}

// readRules turns what the page sent into access rules, refusing anything the API would
// refuse, so that a link to the OVHcloud page never carries a rule that page would reject.
func readRules(sent []ruleResponse) ([]credential.AccessRule, *refusal) {
	if len(sent) == 0 {
		return nil, &refusal{http.StatusBadRequest, errorResponse{
			Code:  codeNoRules,
			Error: "a key with no access rule can do nothing",
		}}
	}

	rules := make([]credential.AccessRule, 0, len(sent))
	for _, rule := range sent {
		method := strings.ToUpper(strings.TrimSpace(rule.Method))
		path := strings.TrimSpace(rule.Path)
		if !slices.Contains(methodsAllowed, method) || !strings.HasPrefix(path, "/") {
			return nil, &refusal{http.StatusBadRequest, errorResponse{
				Code:  codeMalformedRule,
				Error: "an access rule names a method or a path the API would refuse",
			}}
		}
		rules = append(rules, credential.AccessRule{Method: method, Path: path})
	}
	return rules, nil
}
