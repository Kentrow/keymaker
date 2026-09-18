// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/kentrow/keymaker/internal/credential"
)

// The types below mirror the models published in the API schemas: auth.ApiCredential,
// auth.ApiApplication and auth.AccessRule. Field names come from those schemas rather than
// from inference, and the fixtures in testdata are shaped after them.

type apiRule struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type apiCredential struct {
	CredentialID  int64      `json:"credentialId"`
	ApplicationID int64      `json:"applicationId"`
	Status        string     `json:"status"`
	Rules         []apiRule  `json:"rules"`
	AllowedIPs    []string   `json:"allowedIPs"`
	Creation      time.Time  `json:"creation"`
	Expiration    *time.Time `json:"expiration"`
	LastUse       *time.Time `json:"lastUse"`
	OvhSupport    bool       `json:"ovhSupport"`
}

type apiApplication struct {
	ApplicationID  int64  `json:"applicationId"`
	ApplicationKey string `json:"applicationKey"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Status         string `json:"status"`
}

// toDomain fills the credential with what this endpoint returns. Only the identifier of
// the application is known here; the provider resolves the rest.
func (c apiCredential) toDomain() (credential.Credential, error) {
	rules := make([]credential.AccessRule, 0, len(c.Rules))
	for _, r := range c.Rules {
		rules = append(rules, credential.AccessRule{Method: r.Method, Path: r.Path})
	}

	allowed := make([]netip.Prefix, 0, len(c.AllowedIPs))
	for _, value := range c.AllowedIPs {
		prefix, err := parsePrefix(value)
		if err != nil {
			return credential.Credential{}, fmt.Errorf("credential %d: %w", c.CredentialID, err)
		}
		allowed = append(allowed, prefix)
	}

	return credential.Credential{
		ID:          c.CredentialID,
		Application: credential.Application{ID: c.ApplicationID},
		Status:      credential.Status(c.Status),
		Rules:       rules,
		AllowedIPs:  allowed,
		CreatedAt:   c.Creation,
		ExpiresAt:   optionalTime(c.Expiration),
		LastUsedAt:  optionalTime(c.LastUse),

		// The published schema words this field as whether the credential "has been created
		// by yourself or by the OVH support team", so it says who issued the key and not who
		// may use it.
		IssuedBySupport: c.OvhSupport,
	}, nil
}

func (a apiApplication) toDomain() credential.Application {
	return credential.Application{
		ID:          a.ApplicationID,
		Key:         a.ApplicationKey,
		Name:        a.Name,
		Description: a.Description,
	}
}

func optionalTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
