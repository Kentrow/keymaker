<!-- markdownlint-disable MD013 -- one line per entry, however long -->
# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- State in both READMEs what every 1.x release keeps stable, and how to check that an image was built by this repository.
- Add a `keymaker healthcheck` command, and declare it as the `HEALTHCHECK` of the image, so that Docker and Compose report the container as healthy without a shell or a client in it.

### Changed

- Draw the inventory forty keys at a time as it is scrolled: with five hundred keys, a change of filter or view took most of a second and now takes a tenth of one.

### Fixed

- Count the routes of each branch in the explorer with the method and deprecation filters applied, as the list it opens does.
- Hand the focus to the outcome after a revocation or a deletion removes the button that opened it, and keep it inside the address dialog between its two steps.
- Fall back on the route catalogue of the configured region, rather than on the ovh-eu one for every region: ovh-ca publishes 3556 routes and ovh-us 1990, against 4656 for ovh-eu.
- Wait out a `429 Too Many Requests` from the API, as long as `Retry-After` asks within ten seconds, and send the call again, rather than failing the listing of a large account.

## [0.5.1] - 2026-10-03

### Added

- Show the inventory in both READMEs, on invented data, in the reader's theme.

### Changed

- Refresh the route catalogue embedded in the binary: 4656 routes, read on 2026-10-03.

### Fixed

- Say in SECURITY.md that the key in use can be ended on purpose through "Revoke and leave", and only there.
- Try a read of the API once more when its connection drops before any answer, and say on the inventory when the key in use could not be identified.
- Filter a key whose application was deleted as inoperative rather than as active.
- Stop reporting a rule that ends in a slash without a wildcard, such as `PUT /me/api/credential/`, as able to change account access: it names no route.

## [0.5.0] - 2026-10-03

### Added

- Add two shortcuts to the inventory: `/` to search, and Escape to clear the filters.
- Add a control that unfolds the access rules of every key at once, for an audit pass.

### Changed

- Open the explorer on the branches of the API, each with its number of routes, rather than on four thousand routes in alphabetical order.
- Take the palette from the mascot, its navy for the ink and its cyan for the accent, on a slightly warm background.
- Set the screen titles and the small labels in the monospace face, and widen the type scale so that titles, text and labels stand apart.
- Replace the four metric tiles with one line: a bar split by band, then the counts as filters. The first keys now show without scrolling.
- Lay the filters and the list view on the page itself, with hairlines, instead of a panel around each part.
- Drop the icons from the screen navigation.

## [0.4.0] - 2026-10-03

### Added

- Add a way out on the card of the key Keymaker uses: revoke it and leave. It is deleted when it holds the delete rule and expired otherwise.
- Add a report of the whole inventory, downloadable as JSON or CSV, built in the browser and holding no key value.
- Add an editor for the allowed addresses of a key, behind the optional rule `PUT /me/api/credential/*`. The key Keymaker uses is only restricted to a list covering the address it is seen from.

### Changed

- Offer to revoke inactive keys only when the management key may, and say why otherwise.
- Show "Revoke" as a greyed button that explains why when the management key cannot revoke a key, instead of "revocation unavailable".

### Fixed

- Flag a key allowed from `0.0.0.0/0` or `::/0` as accepting any address: those blocks restrict nothing.
- Show a key whose application was deleted as inoperative, out of the audit, instead of as a live key: OVHcloud keeps listing it with its old status.

## [0.3.1] - 2026-09-30

### Fixed

- Encode the path of the redirect that removes the access token from the URL only once.

### Security

- Refuse a path starting with `/\` as the target of the access token redirect.
- Mark the session cookie `Secure` when `KEYMAKER_PUBLIC_URL` is an `https` address.

## [0.3.0] - 2026-09-28

### Added

- Flag narrow rules changing account access in the audit: IAM, OAuth2 clients, allowed addresses, 2FA, password, email, SSH keys. API key rules are not flagged.
- Flag narrow rules reaching billing, orders or payment means in the audit.
- Flag the same sensitive rules in the route explorer.
- Flag management key rules beyond what Keymaker needs on its card, with a link issuing a key holding only the needed rules.
- Flag keys created by OVHcloud support rather than the account holder.
- Flag keys of one application with identical access rules and allowed addresses.
- Flag keys expiring within 7 days, the management key included.
- Link the keyless applications banner and the key replacement notice to the relevant paragraph of the Understand screen.

### Changed

- Audit keys awaiting validation instead of skipping them, and flag them as pending. Usage-based checks are skipped for these keys.

### Fixed

- Stop showing a red message on the New key screen before anything is wrong. An empty selection is explained once, in the first step.
- Keep a readable line length in New key and Understand panel paragraphs on wide screens.
- Move focus to the new screen's title on every screen change.
- Close the keyless applications panel when its last application is deleted.
- Fix the mascot's overlapping right ears. Both ears are now symmetric, in the interface and the READMEs.

## [0.2.0] - 2026-09-18

### Added

- List applications left without a key under the inventory, with what they still allow.
- Add deletion of an application holding no key, behind a confirmation. Applications still holding keys are never offered, since deleting them revokes their keys.
- Add deletion of every keyless application in one pass, with a confirmation listing them and a report of deleted and refused ones.
- Allow optional `GET /me/api/application` and `DELETE /me/api/application/*` rules on the management key. The section names any missing rule; older keys keep working.
- Add an Understand screen, in English and French, explaining applications, keys and access rules on an invented example. It reads nothing from the account.

### Changed

- Give the ready-made management key link for each of `ovh-eu`, `ovh-ca` and `ovh-us` in the quick start, instead of `ovh-eu` alone.

## [0.1.0] - 2026-09-13

First public release.

### Added

- Add an inventory of every classic API key of the configured account, with access rules, allowed addresses, creation, expiry and last use.
- Filter the inventory by status, application, finding and free text.
- Sort the inventory by alerts or by last use.
- Show the inventory as a list or as cards.
- Resolve the application of each key, marking applications the account does not own, such as the OVHcloud API console, as external.
- Mark the key Keymaker authenticates with.
- Audit keys for broad access, no address restriction, no expiry, never used after 30 days, dormant after 180 days and no description.
- Explain each audit finding in the interface, count it across the account and make it usable as a filter.
- Group keys into "at risk", "to watch" and "nothing flagged". Expired, refused and pending keys are not audited.
- Add key revocation behind typing its identifier, refused for Keymaker's own key and disabled with the reason when no delete rule allows it.
- Revoke every expired or refused key in one pass, with a report of what became of each key.
- Add a route explorer over the whole published OVHcloud API, searchable by route or purpose and narrowable by branch and method.
- Build a set of access rules in the route explorer, with a warning on rules reaching the whole account.
- Read the route catalogue from the API at startup, retrying in the background after a failure.
- Embed a dated route catalogue snapshot, shown until a refresh succeeds.
- Create keys through the OVHcloud `createToken` page, opened with the chosen access rules filled in. The new key's values never pass through Keymaker.
- Replace a key from its access rules, listing its allowed addresses to re-enter; revocation comes last, once the OVHcloud page is opened.
- Show the public address the instance is seen from, optionally, to restrict a new key to it.
- Add `KEYMAKER_IP_LOOKUP=off` to disable the public address lookup.
- Offer a link issuing a new management key with the right rules for the configured endpoint when the API refuses the configured key.
- Tell a refused management key apart from one missing a rule.
- Read configuration from an `ovh.conf` file, never written back, with `ovh.conf.example` describing every value.
- Report an unreadable configuration file with the identity it was refused under.
- Add `KEYMAKER_ADDR`, `KEYMAKER_CONFIG`, `KEYMAKER_PUBLIC_URL`, `KEYMAKER_IP_LOOKUP` and `KEYMAKER_LOG_LEVEL` environment variables.
- Add a `--version` flag.
- Provide the interface in English and French, with light and dark themes.
- Make dialogs and explanations accessible.
- Fit the layout to a phone screen.
- Show a footer with the version and a statement that the project is not affiliated with OVHcloud.
- Publish a distroless, non-root container image for `linux/amd64` and `linux/arm64` to `ghcr.io/kentrow/keymaker`, with provenance and SBOM attestations.

### Security

- Require an access token, generated at every start, on every route except `GET /healthz`.
- Require a second token on every change.
- Set a content security policy that allows nothing the binary does not serve.
- Harden response headers.
- Redact the application secret and the consumer key from every log record.

[Unreleased]: https://github.com/kentrow/keymaker/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/kentrow/keymaker/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/kentrow/keymaker/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/kentrow/keymaker/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/kentrow/keymaker/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/kentrow/keymaker/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kentrow/keymaker/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kentrow/keymaker/releases/tag/v0.1.0
