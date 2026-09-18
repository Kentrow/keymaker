# Architecture

This document describes how Keymaker is built, for people who want to review it or change
it. It describes the code as it is; if the two ever disagree, the code is right and this
file needs fixing.

## Goals

- Show every classic OVHcloud API key (application key, application secret, consumer key)
  of an account on one screen: access rules, allowed addresses, dates, status, and the
  application each key belongs to.
- Say what is risky about those keys, without fixing anything on its own.
- Revoke keys, one at a time behind a typed confirmation, or every expired and refused key
  in one pass.
- Help build a new key: browse the published API routes, choose access rules, and hand them
  to the OVHcloud page that issues the key.
- Explain the model the rest of the screens rest on: an application, the keys issued under
  it, and the access rules each key carries.
- Stay small enough to be audited by someone who does not trust it.

## Non-goals

- Keymaker never receives the values of a key it helps create. No API endpoint creates an
  application, and the application secret never travels through the API: keys are issued on
  the OVHcloud `createToken` page, in the reader's own browser.
- It does not change the access rules of an existing key. The API has no endpoint for it, so
  "editing" a key is a replacement: a new key, then the revocation of the old one.
- It does not manage OAuth2 service accounts or IAM policies.
- It does not administer any other OVHcloud service.
- It drives a single account per instance.

## Zero persistence

Keymaker writes nothing to disk. There is no database, no cache directory and no state file.

- The configuration file is opened read-only, once, at startup. The documented container
  mounts it read-only on a read-only root filesystem.
- The management credential lives in memory for the length of the run.
- The access token and the page token are generated at every start and never stored. Stopping
  the process ends every session.
- The route catalogue is held in memory; the copy embedded in the binary is the fallback.
- Interface preferences (language, theme, layout) are kept in the browser's local storage.
  They say nothing about the account.

## Package layout

| Path | Responsibility |
|---|---|
| `cmd/keymaker` | Entry point: flags, environment, configuration, logger, HTTP server and shutdown. |
| `internal/config` | Reads the `ovh.conf` file. Never writes it, never reads ambient configuration. |
| `internal/credential` | Provider-neutral model of a key, its access rules and its status, and the `Provider` interface the HTTP layer works with. |
| `internal/legacy` | The `Provider` for application key, application secret and consumer key credentials: listing, identity, revocation guards, application resolution. |
| `internal/ovh` | The transport boundary. `Client` is the complete set of API calls; `APIClient` implements it on top of `github.com/ovh/go-ovh`. Also builds the `createToken` link and declares the rules the management key needs. |
| `internal/audit` | Pure analysis of a credential: findings with a code and a severity. Makes no call. |
| `internal/catalog` | Turns the API index and schemas into a list of routes, refreshes it in the background and falls back to an embedded snapshot. |
| `internal/httpapi` | HTTP handlers, authentication, page token, security headers and request logging. |
| `internal/logging` | A `slog` handler that removes registered secrets from every log record. |
| `internal/publicip` | Optional lookup of the public address the process is seen from. |
| `internal/web` | The embedded interface: `index.html`, `app.js`, `app.css`, Alpine.js (CSP build) and icons. |
| `tools/snapshotgen` | Maintainer tool that regenerates `internal/catalog/snapshot.json.gz`. |

The only third-party Go dependency is `github.com/ovh/go-ovh`, which signs requests and
resynchronises the clock with the API. `.golangci.yml` enforces this with `depguard`.

## Startup

1. `--version` prints the build information and exits before anything else is read.
2. The configuration file is parsed. The application secret and the consumer key are
   registered with the log redactor before the logger is created, so no code path can log
   them.
3. `KEYMAKER_LOG_LEVEL` sets the log level. An unknown value stops the process.
4. The API client is built from that configuration only. `go-ovh`'s own loader, which also
   reads `~/.ovh.conf` and `OVH_*` variables, is deliberately not used.
5. The access token and the page token are generated (32 random bytes each).
6. The address to open, token included, is logged once.
7. The catalogue refresh starts in the background, and the server starts listening.

## Request lifecycle

Every request goes through the same chain of handlers, outermost first:

1. **Request log.** At debug level, one line per request with the method, the path, the
   status and the duration. The query string is never logged, because the address that opens
   a session carries the access token.
2. **Security headers.** `Content-Security-Policy`, `X-Content-Type-Options: nosniff`,
   `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY` on every response.
3. **Authentication.** `GET /healthz` is the only route served without the access token.
   Everything else needs the session cookie. A request carrying the token in its query string
   gets the cookie and is redirected to the same path without the token.
4. **Page token.** A request to a route that exists, with a method other than `GET`, `HEAD`
   or `OPTIONS`, must carry the page token in the `X-Keymaker-Csrf` header. A request no
   route accepts is left to the router, which answers 404 or 405 without running a handler.
5. **Router and handler.**

| Route | Purpose |
|---|---|
| `GET /healthz` | Fixed `ok` body for probes. Discloses no version, configuration or state. |
| `GET /api/session` | Page token, endpoint, version, whether the address lookup is enabled, and the link that issues a management key. |
| `GET /api/inventory` | Every credential with its application, findings and revocation offer, plus summary counts. |
| `GET /api/applications` | Every application of the account with how many credentials point at it, so the interface can show those holding none. |
| `DELETE /api/applications/{id}` | Deletes an application that holds no credential. |
| `POST /api/applications/keyless/deletions` | Deletes every application holding no credential. The request carries no list. |
| `GET /api/catalogue` | The route catalogue and whether it is live or the embedded snapshot. |
| `DELETE /api/credentials/{id}` | Revokes one credential. |
| `POST /api/credentials/inactive/revocations` | Revokes every expired or refused credential. The request carries no list. |
| `GET /api/address` | The public address of the process, when the lookup is enabled. |
| `POST /api/handoff` | Validates a set of access rules and returns the `createToken` link that carries them. |
| `GET /` | The embedded interface. |

JSON errors carry a stable `code` and an English sentence. The interface words the code in the
reader's language; the sentence is only a fallback.

## OVHcloud API usage

The backend calls a closed set of endpoints. The route of each call is built by the method
that makes it; no request parameter ever becomes a URL.

| Method | Route | Used for |
|---|---|---|
| `GET` | `/auth/currentCredential` | Identifying the credential Keymaker authenticates with |
| `GET` | `/auth/time` | Clock synchronisation, handled by `go-ovh` |
| `GET` | `/me/api/credential` | Listing credential identifiers |
| `GET` | `/me/api/credential/{id}` | Reading one credential |
| `GET` | `/me/api/application` | Listing the applications of the account, including those no credential points at |
| `GET` | `/me/api/application/{id}` | Reading an application the account owns |
| `GET` | `/me/api/credential/{id}/application` | Reading an application the account does not own, such as the OVHcloud API console |
| `DELETE` | `/me/api/credential/{id}` | Revoking a credential |
| `DELETE` | `/me/api/application/{id}` | Deleting an application that holds no credential |
| `GET` | `/1.0/` and the `*.json` schemas it lists | Building the route catalogue, without authentication |

Accepted endpoints are `ovh-eu`, `ovh-ca` and `ovh-us`. The Kimsufi and SoYouStart entries of
the `go-ovh` table resolve to hosts outside `api.ovh.com` and are refused.

The management key needs these rules, declared in `ovh.ManagementRules`. A test ties every rule
to a call the client makes, and every call under `/me` to a rule.

```text
GET    /me/api/credential
GET    /me/api/credential/*
GET    /me/api/application
GET    /me/api/application/*
DELETE /me/api/credential/*
DELETE /me/api/application/*     optional: without it, revocation is disabled
```

`DELETE /me/api/credential/*`, `GET /me/api/application` and `DELETE /me/api/application/*` are
optional: without them the affected screen says which rule is missing instead of showing a
refused call.

Some constraints of the API shape the interface:

- The access rules of a credential cannot be changed after it is issued, hence replacement
  instead of editing.
- The `createToken` page accepts access rules in its query string, but not the name, the
  description, the validity or the allowed addresses. The reader fills those in on that page,
  and a replacement lists the addresses of the replaced key so they can be typed again.
- An access rule cannot carry a named parameter. `/domain/zone/{zoneName}` becomes
  `/domain/zone/*`, which covers every zone. The substitution is done by the backend and shown
  in the interface.

### Inventory

The provider lists identifiers, then reads each credential with at most eight calls in flight.
A credential that disappears in between was revoked meanwhile and is dropped. A credential that
cannot be read for another reason is left out, and the inventory reports how many are missing;
a refused call fails the whole listing, because it means the management key lacks a rule.

Applications are read once each, also in parallel. When the application route answers 404,
the credential route is tried and the application is marked external.

### Applications without a key

Revoking a credential leaves its application behind, and an application is a key and a secret
under which a new credential can be requested; that request is only usable once the account
holder validates it on the OVHcloud page. The credential routes never name an application no
credential points at, so the listing is the only way to see one. The interface reads it after
the inventory, counts the credentials of each application from the same listing the inventory
shows, and names the ones holding none.

Deleting one is offered for those only. `DELETE /me/api/application/{id}` revokes every
credential of the application along with it, which would cut a working access, so the provider
counts them against the API at the moment of the call rather than trusting what the screen
showed, and refuses an application still holding one.

Deleting all of them at once takes the same path, once per application. The request carries no
list: the set is selected on the server from the listing and the inventory, as the credential
sweep selects its keys, so nothing reaching the endpoint can name an application of its own.
The credentials are listed once for the whole set and the identity read once, while the guard
and the rule check stay per application. One refusal does not end the pass, and the response
names what was deleted and what was refused, with a code for each refusal.

### Revocation

Every revocation checks the identity of the credential in use against the API and refuses to
revoke it. A single revocation reads that identity for the call itself. A sweep reads it once
at the start of the request and applies the same guard to each key. The sweep selects expired
and refused keys from what the API answers; the browser never names the keys. Whether the
management key holds a delete rule for a credential is computed from its rules, so the
interface can disable the action instead of offering one that would be refused.

### Route catalogue

At startup, the index and every schema it lists are fetched with at most eight calls in flight.
A refresh is all or nothing: a branch that fails to load discards the whole attempt, because a
missing route would read as a route the API does not offer. A failed refresh is retried after
10 seconds, 30 seconds, 1 minute, then every 5 minutes. Until one succeeds, the embedded
snapshot is served, and the interface shows its date. A request that arrives before the first
refresh finishes waits for it at most 15 seconds.

### Audit

`internal/audit` inspects validated credentials only; an expired, refused or pending key grants
nothing and belongs to no band.

| Finding | Raised when | Severity |
|---|---|---|
| `broad-access` | A rule has a wildcard whose fixed part is `/` or `/me` | risk |
| `no-ip-restriction` | No allowed address | caution |
| `no-expiry` | No expiration date | caution |
| `never-used` | Never used and created more than 30 days ago | caution |
| `dormant` | Last used more than 180 days ago | caution |
| `no-description` | The application has no description | note |

## Security model

### Access

- The access token is 32 random bytes, generated at every start and compared in constant time.
  It is logged once, in the startup address.
- The session cookie `keymaker_session` holds that token, with `HttpOnly` and
  `SameSite=Strict`. It has no `Secure` attribute, because the interface is served over plain
  HTTP on loopback.
- The page token is a second random value, served by `GET /api/session` and required in the
  `X-Keymaker-Csrf` header on every mutation. Another origin cannot read it, which also covers
  another local service on `127.0.0.1`: a browser treats it as the same site and would send the
  cookie.
- The binary listens on `127.0.0.1:8080` by default. The container image sets
  `KEYMAKER_ADDR=0.0.0.0:8080`, because loopback inside a network namespace is unreachable
  through a published port; the host-side mapping on `127.0.0.1` is then the boundary. Any
  address other than loopback logs a warning at startup.
- Server timeouts: 5 seconds to read headers, 15 seconds to read a request, 60 seconds to write
  a response, 60 seconds idle.

### Browser

- The content security policy is
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`.
- Alpine.js is the CSP build, which evaluates no expression strings. `internal/web` tests
  refuse a directive holding an expression, and any asset loaded from outside the binary.
- Links to OVHcloud open with `rel="noopener noreferrer"`.

### Logs

- Logs are `slog` text lines on standard error. Nothing is written elsewhere.
- The application secret and the consumer key are replaced by `[redacted]` in every message,
  attribute and group, by the handler itself. Types holding a secret have no `String` or
  `MarshalJSON` method, and `forbidigo` rejects `fmt.Print`, so nothing bypasses the handler.
  The HTTP server's own error log goes through the same handler.
- Revocations are logged at info level with the credential identifier, failures at warn or
  error level. There is no separate or persistent audit log: collecting the process output is
  left to whoever runs it.

### Outbound connections

- The OVHcloud API host of the configured endpoint.
- `https://api.ipify.org`, only when the reader asks for the public address, with a 5-second
  timeout, a 64-byte answer limit and a strict address parse. `KEYMAKER_IP_LOOKUP=off` removes
  the ability. The destination is a constant, not a setting.

### What Keymaker never does

- Store anything on disk, including the configuration it was given.
- Receive, display or log the values of a key it helps create.
- Revoke the credential it authenticates with.
- Revoke a set of keys named by the browser.
- Call a URL taken from a request.
- Load a script, a style, a font or an image from outside the binary.
- Send telemetry.
