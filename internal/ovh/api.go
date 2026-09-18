// Copyright 2026 Kentrow
// SPDX-License-Identifier: Apache-2.0

package ovh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	sdk "github.com/ovh/go-ovh/ovh"

	"github.com/kentrow/keymaker/internal/config"
	"github.com/kentrow/keymaker/internal/credential"
)

const (
	userAgent = "keymaker"

	requestTimeout = 30 * time.Second
)

// supportedEndpoints is deliberately narrower than the SDK table. The Kimsufi and
// SoYouStart entries point at hosts outside api.ovh.com, which the outbound rule does
// not cover, and supporting them has not been decided.
var supportedEndpoints = []string{"ovh-eu", "ovh-ca", "ovh-us"}

// APIClient is the Client implementation backed by the official SDK.
type APIClient struct {
	sdk         *sdk.Client
	endpointURL string
}

var _ Client = (*APIClient)(nil)

// NewAPIClient builds the client the tool authenticates with.
//
// The SDK client is assembled field by field rather than through sdk.NewClient, because
// that constructor merges in ambient configuration: /etc/ovh.conf, the file in the home
// directory, the working directory, and the OVH_* environment variables. Keymaker reads
// exactly one configuration file, the one it was given, and a credential picked up from
// the surroundings would be both surprising and unauditable.
func NewAPIClient(account config.Account, httpClient *http.Client) (*APIClient, error) {
	endpoint, err := endpointURL(account.Endpoint)
	if err != nil {
		return nil, err
	}
	if !account.Management.Complete() {
		return nil, errors.New("management credential is missing an application key, an application secret or a consumer key")
	}

	client := &sdk.Client{
		AppKey:      account.Management.ApplicationKey,
		AppSecret:   account.Management.ApplicationSecret,
		ConsumerKey: account.Management.ConsumerKey,
		Client:      httpClient,
		Timeout:     requestTimeout,
		UserAgent:   userAgent,
	}
	if err := client.SetEndpoint(endpoint); err != nil {
		return nil, err
	}

	return &APIClient{sdk: client, endpointURL: endpoint}, nil
}

func endpointURL(name string) (string, error) {
	if !slices.Contains(supportedEndpoints, name) {
		return "", fmt.Errorf("unsupported endpoint %q, expected one of %v", name, supportedEndpoints)
	}
	endpoint, ok := sdk.Endpoints[name]
	if !ok {
		return "", fmt.Errorf("endpoint %q is unknown to the SDK", name)
	}
	return endpoint, nil
}

// StatusCode returns the HTTP status an API error carries, or zero when the failure
// happened before a response was read. Callers use it to tell a missing permission from
// a broken call.
func StatusCode(err error) int {
	var apiErr *sdk.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code
	}
	return 0
}

func (c *APIClient) CurrentCredential(ctx context.Context) (credential.Credential, error) {
	var response apiCredential
	if err := c.sdk.GetWithContext(ctx, "/auth/currentCredential", &response); err != nil {
		return credential.Credential{}, err
	}
	return response.toDomain()
}

func (c *APIClient) ListCredentialIDs(ctx context.Context, status credential.Status) ([]int64, error) {
	path := "/me/api/credential"
	if status != "" {
		path += "?" + url.Values{"status": {string(status)}}.Encode()
	}

	var ids []int64
	if err := c.sdk.GetWithContext(ctx, path, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (c *APIClient) Credential(ctx context.Context, id int64) (credential.Credential, error) {
	var response apiCredential
	if err := c.sdk.GetWithContext(ctx, CredentialPath(id), &response); err != nil {
		return credential.Credential{}, err
	}
	return response.toDomain()
}

func (c *APIClient) CredentialApplication(ctx context.Context, id int64) (credential.Application, error) {
	var response apiApplication
	if err := c.sdk.GetWithContext(ctx, CredentialPath(id)+"/application", &response); err != nil {
		return credential.Application{}, err
	}
	return response.toDomain(), nil
}

func (c *APIClient) DeleteCredential(ctx context.Context, id int64) error {
	return c.sdk.DeleteWithContext(ctx, CredentialPath(id), nil)
}

func (c *APIClient) ListApplicationIDs(ctx context.Context) ([]int64, error) {
	var ids []int64
	if err := c.sdk.GetWithContext(ctx, "/me/api/application", &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

func (c *APIClient) Application(ctx context.Context, id int64) (credential.Application, error) {
	var response apiApplication
	if err := c.sdk.GetWithContext(ctx, ApplicationPath(id), &response); err != nil {
		return credential.Application{}, err
	}
	return response.toDomain(), nil
}

func (c *APIClient) DeleteApplication(ctx context.Context, id int64) error {
	return c.sdk.DeleteWithContext(ctx, ApplicationPath(id), nil)
}

func (c *APIClient) Index(ctx context.Context) ([]byte, error) {
	var raw json.RawMessage
	if err := c.sdk.GetUnAuthWithContext(ctx, "/", &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *APIClient) Schema(ctx context.Context, path string) ([]byte, error) {
	var raw json.RawMessage
	if err := c.sdk.GetUnAuthWithContext(ctx, path, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// ApplicationPath is the route a call about one application takes, exported for the same
// reason as CredentialPath: the code deciding whether a rule covers the call and the code
// making it must not drift apart.
func ApplicationPath(id int64) string {
	return "/me/api/application/" + strconv.FormatInt(id, 10)
}

// CredentialPath is the route a call about one credential takes. It is exported so that
// the code deciding whether a rule covers that call and the code making it cannot drift
// apart.
func CredentialPath(id int64) string {
	return "/me/api/credential/" + strconv.FormatInt(id, 10)
}

// parsePrefix accepts both forms the API returns for an ipBlock: a CIDR block and a bare
// address, which is turned into a single-host block.
func parsePrefix(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("unreadable address %q", value)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ManagementRules are the access rules the management credential needs, and the complete
// list of them. They are declared here, beside the calls that use them,
// so the permissions asked for and the permissions exercised cannot drift apart.
//
// Three entries are optional, and a key issued without them keeps working: the credential
// delete rule, without which revocation is not offered, the application listing, without which
// the applications holding no key cannot be shown, and the application delete rule, without
// which they cannot be deleted from here. Each says so on screen rather than failing.
var ManagementRules = []credential.AccessRule{
	{Method: http.MethodGet, Path: "/me/api/credential"},
	{Method: http.MethodGet, Path: "/me/api/credential/*"},
	{Method: http.MethodGet, Path: "/me/api/application"},
	{Method: http.MethodGet, Path: "/me/api/application/*"},
	{Method: http.MethodDelete, Path: "/me/api/credential/*"},
	{Method: http.MethodDelete, Path: "/me/api/application/*"},
}

// CreateTokenURL is the OVHcloud page that issues a credential, with rules prefilled.
//
// It is a page a person opens, not a call this process makes, and it lives on the same
// host as the API of their region. Building it here rather than printing one address in
// the documentation is what makes it right for an account that is not on ovh-eu.
func CreateTokenURL(endpoint string, rules []credential.AccessRule) (string, error) {
	base, err := endpointURL(endpoint)
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	var query strings.Builder
	for i, rule := range rules {
		if i > 0 {
			query.WriteByte('&')
		}
		query.WriteString(url.QueryEscape(rule.Method))
		query.WriteByte('=')
		query.WriteString(escapeRulePath(rule.Path))
	}

	page := url.URL{Scheme: parsed.Scheme, Host: parsed.Host, Path: "/createToken/", RawQuery: query.String()}
	return page.String(), nil
}

// escapeRulePath percent-encodes a rule path while leaving the two characters that make it
// readable. Both are legal unescaped in a query string, and keeping them means the address
// the user sees is the rule they are agreeing to rather than a line of escapes.
func escapeRulePath(path string) string {
	var out strings.Builder
	for _, b := range []byte(path) {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
			out.WriteByte(b)
		case b == '/', b == '*', b == '-', b == '_', b == '.', b == '~':
			out.WriteByte(b)
		default:
			fmt.Fprintf(&out, "%%%02X", b)
		}
	}
	return out.String()
}
