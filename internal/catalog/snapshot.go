// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
)

// captured holds one catalogue per region, as it stood when a maintainer last ran the
// generator. The regions do not publish the same API: on 2026-10-04, ovh-eu listed 4656
// routes, ovh-ca 3556 and ovh-us 1990, so the fallback of one region is wrong for another.
// They are stored compressed because each uncompressed document is up to a megabyte, most of
// it repeated path prefixes (see tools/snapshotgen).
//
//go:embed snapshots/*.json.gz
var captured embed.FS

// Embedded is the catalogue of a region captured at build time, which the explorer browses
// until a refresh replaces it and for as long as refreshing keeps failing.
func Embedded(endpoint string) (Snapshot, error) {
	compressed, err := captured.ReadFile("snapshots/" + endpoint + ".json.gz")
	if err != nil {
		return Snapshot{}, fmt.Errorf("no embedded catalogue for endpoint %q", endpoint)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return Snapshot{}, fmt.Errorf("embedded catalogue of %s: %w", endpoint, err)
	}
	defer func() { _ = reader.Close() }()

	var snapshot Snapshot
	if err := json.NewDecoder(reader).Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("embedded catalogue of %s: %w", endpoint, err)
	}
	snapshot.Live = false
	return snapshot, nil
}
