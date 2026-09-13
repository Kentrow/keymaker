// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

// Package config models the read-only configuration file, in the ovh.conf format the
// official OVHcloud SDKs already read.
//
// The file is mounted read-only and never written back: nothing in this package gains a
// write path, and the values it carries are never logged. Adding a String
// or MarshalJSON method to a type holding a secret would defeat the redaction helper,
// since a log call would then print the secret without going through it.
package config

// Config is the whole configuration. Accounts is a list even though the tool drives a
// single one, because retrofitting multi-account support later costs far more
// than carrying the shape now.
type Config struct {
	// Default names the account used when the interface does not select one.
	Default  string
	Accounts []Account
}

// Account is one OVHcloud customer account, on one endpoint.
type Account struct {
	Name string

	// Endpoint is an identifier understood by go-ovh, such as ovh-eu. The mapping from
	// identifier to base URL belongs to the SDK and is not restated here.
	Endpoint string

	// Management is the credential the tool authenticates with. It is provider-specific
	// by nature: an OAuth2 provider would add its own field rather than reuse this one.
	Management LegacyCredentials
}

// LegacyCredentials is an AK/AS/CK triplet, the only authentication scheme supported.
// The permissions this credential needs are ovh.ManagementRules; the tool works with the
// delete rule left out, and disables revocation accordingly.
type LegacyCredentials struct {
	ApplicationKey    string
	ApplicationSecret string
	ConsumerKey       string
}
