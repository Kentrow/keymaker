# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- The banner listing applications left without a key and the notice shown while replacing a
  key link to the paragraph of the Understand screen that answers the question they raise.
- The key Keymaker authenticates with is compared with the rules Keymaker actually needs. A
  rule beyond them is flagged on that key and named on its card, with the link that issues a
  key holding exactly the needed rules.
- The audit flags a key expiring within a week. Whatever uses it stops working that day
  without a warning of its own, the management key of this tool included. A week leaves time
  to issue and deploy a replacement, and a key issued for 30 days, one of the validities the
  OVHcloud page offers, is only flagged in its last week rather than for its whole life.
- The audit and the explorer flag narrow rules that still cost something: those that can
  change access to the account (IAM users and tokens, OAuth2 clients, the addresses other keys
  accept, two-factor authentication, password and email changes, SSH keys) and those that
  reach billing, orders or payment means. Reading and revoking API keys is deliberately not
  among them. Both screens read one list, checked by a test against the published route
  catalogue.
- The audit names two keys of one application that nothing tells apart: same access rules, same
  allowed addresses. One of them is usually a first attempt nobody revoked, and the interface
  says so rather than choosing which to keep.
- The audit reads keys awaiting validation instead of skipping them, and flags the fact. Such a
  key opens nothing until the account holder validates it on the OVHcloud page, which is one
  click away, so what it would be allowed to do is reported before that happens. The checks
  that read how a key was used are skipped for it, since it could not have been used.
- The audit flags a key the OVHcloud support team created rather than the account holder. The
  API has always returned that fact and the interface dropped it, so such a key looked like any
  other. It is counted, explained and usable as a filter like the other findings.

### Fixed

- The New key screen no longer greets the reader with a red message before anything is wrong.
  An empty selection is explained once, in the first step, and red is kept for real errors.
- Changing screens moves the focus to the title of the new screen every time. It was sometimes
  lost to the page, leaving a keyboard or screen reader user nowhere in particular.
- Deleting the last application left without a key no longer leaves its unfolded panel on
  screen, empty but for its explanation.
- Fix the mascot logo in the interface and in the READMEs.

## [0.2.0] - 2026-09-18

### Added

- Applications left without a key are listed under the inventory, with what they still allow:
  revoking a key leaves its application behind, and an application is a key and a secret a new
  credential can be requested under.
- Deletion of an application that holds no key, behind a confirmation. An application still
  holding one is never offered, because OVHcloud revokes every key of an application along with
  it; the count is checked against the API at the moment of the deletion.
- Deletion of every application holding no key in one pass, behind a confirmation listing them.
  The request carries no list: the set is selected on the server from what the API answers, and
  the report says which applications were deleted and which were refused.
- The management key can hold `GET /me/api/application` and `DELETE /me/api/application/*`,
  which the listing and the deletion need. Both are optional, like the credential delete rule:
  without them the section says which rule is missing, and a key issued before this version
  keeps working.
- An Understand screen, in English and French, explaining what an application, a key and an
  access rule each are, on an invented example, and what follows from the way they fit
  together. It reads nothing from the account.

### Changed

- The quick start gives the ready-made management key link for each of the three endpoints
  instead of `ovh-eu` alone, so an account on `ovh-ca` or `ovh-us` no longer has to rebuild the
  address by hand. A test ties those links to the rules the code asks for.

## [0.1.0] - 2026-09-13

First public release.

### Added

- Inventory of every classic API key (application key, application secret, consumer key) of
  the configured account, with its access rules, allowed addresses, creation, expiry and last
  use, filterable by status, application, finding and free text, and sortable by alerts or by
  last use, in a list or card layout.
- Resolution of the application each key belongs to, including applications the account does
  not own, such as the OVHcloud API console, which are marked as external.
- Marking of the key Keymaker authenticates with.
- Key audit: broad access, no address restriction, no expiry, never used after 30 days, dormant
  after 180 days and no description, each explained in the interface, counted across the
  account and usable as a filter. Keys fall into "at risk", "to watch" and "nothing flagged";
  expired, refused and pending keys are not audited.
- Revocation of a key behind typing its identifier, refused for the key Keymaker authenticates
  with, and disabled with the reason when the management key has no delete rule for it.
- Revocation of every expired or refused key in one pass, selected by the server, with a report
  of what became of each key.
- Route explorer over the whole published OVHcloud API, searchable by route or by purpose and
  narrowable by branch and method, to build a set of access rules, with a warning on rules that
  reach the whole account.
- Route catalogue read from the API at startup and retried in the background after a failure,
  with an embedded snapshot shown with its date until a refresh succeeds.
- Key creation through the OVHcloud `createToken` page, opened with the chosen access rules
  filled in. The values of the new key never pass through Keymaker.
- Replacement of an existing key: its access rules are the starting point, its allowed addresses
  are listed to be entered again on the OVHcloud page, and revoking it is the last step, unlocked
  once that page has been opened.
- Optional display of the public address the instance is seen from, to restrict a new key to
  it, and `KEYMAKER_IP_LOOKUP=off` to remove that lookup.
- A link that issues a new management key with the right rules for the configured endpoint,
  offered when the API refuses the configured key, which is told apart from a missing rule.
- Access token generated at every start and required on every route except `GET /healthz`, and
  a second token required on every change.
- Content security policy that allows nothing the binary does not serve, and hardened response
  headers.
- Redaction of the application secret and the consumer key from every log record.
- Configuration read from an `ovh.conf` file and never written back, with `ovh.conf.example`
  describing every value. A file the process cannot read is reported with the identity it was
  refused under.
- `KEYMAKER_ADDR`, `KEYMAKER_CONFIG`, `KEYMAKER_PUBLIC_URL`, `KEYMAKER_IP_LOOKUP` and
  `KEYMAKER_LOG_LEVEL` environment variables, and a `--version` flag.
- Interface in English and French, with light and dark themes, accessible dialogs and
  explanations, a layout that fits a phone screen, and a footer with the version and a
  statement that the project is not affiliated with OVHcloud.
- Distroless, non-root container image for `linux/amd64` and `linux/arm64`, published to
  `ghcr.io/kentrow/keymaker` with provenance and SBOM attestations.

[Unreleased]: https://github.com/kentrow/keymaker/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kentrow/keymaker/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kentrow/keymaker/releases/tag/v0.1.0
