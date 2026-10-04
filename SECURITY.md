# Security policy

Keymaker handles OVHcloud API credentials and can revoke keys. Security reports are welcome
and taken seriously.

## Supported versions

From 1.0, the latest minor release of the latest major version receives security fixes, as
the latest minor release did during `0.x`. A release in 1.x changes nothing that the
[compatibility promise](README.md#compatibility) covers, so moving to the latest one is always
safe. Upgrade to it before reporting, and mention the version you run (`keymaker --version`).

## Reporting a vulnerability

Report vulnerabilities **privately**, through GitHub's private vulnerability reporting:

<https://github.com/kentrow/keymaker/security/advisories/new>

Never open a public issue, discussion or pull request for a vulnerability.

**Never send a real credential**, not in a report, a log excerpt or a screenshot: no
application key, application secret, consumer key or `ovh.conf` content. If a report needs
one to be reproduced, describe the access rules it had instead. If a credential was exposed,
revoke it on OVHcloud first.

A useful report includes the version, how Keymaker runs (image, Compose, source), the steps to
reproduce, the impact you expect, and any proof of concept that uses placeholder values.

## What to expect

Keymaker is maintained by one person, in their own time.

- Acknowledgement within 7 days.
- An assessment, and a fix or mitigation plan, as soon as the issue is understood, typically
  within 30 days.
- A GitHub security advisory published with the fix. Reporters are credited unless they ask
  not to be.

## Scope

In scope: Keymaker itself, meaning the code in this repository, the container image published
at `ghcr.io/kentrow/keymaker` and its documented configuration.

Out of scope:

- The OVHcloud API, its authentication, the `createToken` page and any other OVHcloud service.
  Report those to OVHcloud.
- An attacker who already controls the machine running Keymaker or can read its configuration
  file.
- A key after it has been created and deployed elsewhere.
- Deployments that ignore the documented setup, for example publishing the port on a routable
  address.

## Security model in brief

The details, and how each point is implemented, are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

- **Local and single-user.** Anyone who can reach the interface can act with the management
  credential. The binary listens on `127.0.0.1` by default. The image listens on `0.0.0.0`
  inside its network namespace, so the host-side port mapping must be bound to `127.0.0.1`.
- **Access token.** A random token is generated at every start, printed once in the startup
  address, and required on every route except `GET /healthz`, whose body is a fixed `ok`.
- **Page token.** Every mutation requires a second token in a custom header, so a page from
  another origin, including another local service, cannot drive a revocation.
- **Browser hardening.** A strict content security policy without `unsafe-inline` or
  `unsafe-eval`, framing forbidden, no referrer, no resource loaded from outside the binary.
- **No persistence.** Nothing is written to disk. The configuration file is read-only. Keys
  created through Keymaker are issued on the OVHcloud page, and their values never reach the
  process.
- **Redacted logs.** The application secret and the consumer key are removed from every log
  record by the logging pipeline itself.
- **Revocation guards.** The ordinary revocation and the bulk revocation refuse the credential
  Keymaker authenticates with, checked against the API at the moment of the call. It can only
  be ended on purpose, through its own way out, "Revoke and leave", which names no key. A single
  revocation requires the identifier to be typed. The bulk revocation only touches expired and
  refused keys, selected by the server.
- **Address guard.** The credential Keymaker authenticates with is only restricted to a list
  covering the address the process is seen from, looked up at the moment of the change. With the
  lookup switched off, it is not restricted from here at all.
- **Closed outbound set.** The OVHcloud API of the configured endpoint, and `api.ipify.org` only
  when the reader asks for the public address or restricts the key Keymaker uses.
  `KEYMAKER_IP_LOOKUP=off` removes that call.
- **Least privilege.** The management key needs read rules on credentials and applications, and
  optional delete rules. The rule that changes the addresses of a key is left out of the key
  Keymaker suggests, since it can widen the reach of any key. Never grant it `/me/*` or `/*`.
- **Hardened image.** Distroless, non-root, meant to run with a read-only filesystem, no
  capabilities and `no-new-privileges`.

## Operational advice

- Run the container as documented: port published on `127.0.0.1`, configuration mounted
  read-only, `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges`.
- Keep `ovh.conf` out of version control and readable by its owner only (`chmod 600`), and run
  the container as that owner with `--user` rather than widening the file permissions.
- Give the management key an expiration, restrict it to your address, and leave out the delete
  rule if you only need the inventory.
- The startup log contains the access token. Treat that output as sensitive for as long as the
  process runs.
