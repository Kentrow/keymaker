// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
)

// captured is the catalogue as it stood when a maintainer last ran the generator. It is
// stored compressed because the uncompressed document is close to a megabyte, most of
// it repeated path prefixes (see tools/snapshotgen).
//
//go:embed snapshot.json.gz
var captured []byte

// Embedded is the catalogue captured at build time, which the explorer browses until a
// refresh replaces it and for as long as refreshing keeps failing.
func Embedded() (Snapshot, error) {
	reader, err := gzip.NewReader(bytes.NewReader(captured))
	if err != nil {
		return Snapshot{}, fmt.Errorf("embedded catalogue: %w", err)
	}
	defer func() { _ = reader.Close() }()

	var snapshot Snapshot
	if err := json.NewDecoder(reader).Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("embedded catalogue: %w", err)
	}
	snapshot.Live = false
	return snapshot, nil
}
