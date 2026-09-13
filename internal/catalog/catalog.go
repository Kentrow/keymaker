// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package catalog turns the OVHcloud API schemas into the route list the creation
// screen browses.
package catalog

import (
	"context"
	"time"
)

// Operation is one method a route accepts, with what the API says it does.
type Operation struct {
	Method      string `json:"method"`
	Description string `json:"description"`

	// Deprecated marks an operation the API still serves but no longer recommends.
	// The explorer keeps those out of the way rather than dropping them: a key may
	// legitimately need one, but nobody should be steered towards it by accident.
	Deprecated bool `json:"deprecated"`
}

// Route is one entry of the catalogue, at the granularity the explorer offers: a path
// and the operations it accepts.
//
// Path is the route as the API documents it, placeholders included
// ("/me/api/credential/{credentialId}"). An access rule cannot carry a placeholder, so
// turning it into a pattern is a separate, deliberate step: see RulePath.
type Route struct {
	Path       string      `json:"path"`
	Operations []Operation `json:"operations"`
}

// Snapshot is a catalogue and the moment it was produced. The interface reports the
// date when it is showing the embedded fallback rather than a live answer.
type Snapshot struct {
	Routes []Route `json:"routes"`

	// Branches are the top-level entries of the API index, in the order the API lists
	// them. They are carried rather than derived from the routes, because the split
	// between one branch and the next is not visible in a path: "/dedicated/server" and
	// "/dedicated/cluster" are two branches while "/me/api" is part of one.
	Branches []string `json:"branches"`

	Taken time.Time `json:"taken"`

	// Live distinguishes a catalogue fetched from the API during this run from the
	// copy embedded at build time.
	Live bool `json:"live"`
}

// Catalog serves the route list. The implementation fetches it once at startup and
// keeps it in memory; a snapshot embedded at build time takes over when the fetch
// fails, in which case Taken reports when that fallback was produced and the interface
// says so.
type Catalog interface {
	Current(ctx context.Context) Snapshot
}
