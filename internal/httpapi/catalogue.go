// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"time"

	"github.com/kentrow/keymaker/internal/catalog"
)

type catalogueResponse struct {
	// Live says whether these routes were read from the API during this run. When it is
	// false the interface names the date, because a route added since is missing and a
	// route removed since is still listed.
	Live  bool      `json:"live"`
	Taken time.Time `json:"taken"`

	// Branches are the top-level entries of the API, which the explorer offers as a way
	// to narrow the list without typing.
	Branches []string `json:"branches"`

	Routes []catalogueRoute `json:"routes"`
}

type catalogueRoute struct {
	// Path is the route as the API documents it, parameters named.
	Path string `json:"path"`

	// Rule is the same route as an access rule can carry it, every parameter replaced by
	// a wildcard. The substitution happens here rather than in the browser so that the
	// rule the user is shown and the rule the API is sent are produced by the same code.
	Rule string `json:"rule"`

	// Wildcard says whether Rule is wider than Path, which is what the interface warns
	// about: a rule on one identifier is not something the API can express.
	Wildcard bool `json:"wildcard"`

	Operations []catalogueOperation `json:"operations"`
}

type catalogueOperation struct {
	Method      string `json:"method"`
	Description string `json:"description"`
	Deprecated  bool   `json:"deprecated"`
}

func (s *server) catalogue(w http.ResponseWriter, r *http.Request) {
	snapshot := s.catalog.Current(r.Context())

	branches := snapshot.Branches
	if branches == nil {
		branches = []string{}
	}

	response := catalogueResponse{
		Live:     snapshot.Live,
		Taken:    snapshot.Taken,
		Branches: branches,
		Routes:   make([]catalogueRoute, 0, len(snapshot.Routes)),
	}

	for _, route := range snapshot.Routes {
		operations := make([]catalogueOperation, 0, len(route.Operations))
		for _, op := range route.Operations {
			operations = append(operations, catalogueOperation{
				Method:      op.Method,
				Description: op.Description,
				Deprecated:  op.Deprecated,
			})
		}

		response.Routes = append(response.Routes, catalogueRoute{
			Path:       route.Path,
			Rule:       catalog.RulePath(route.Path),
			Wildcard:   catalog.Parameterised(route.Path),
			Operations: operations,
		})
	}

	writeJSON(w, http.StatusOK, response)
}
