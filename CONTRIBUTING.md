# Contributing to Keymaker

Thank you for considering a contribution. Keymaker handles API credentials, so changes are
reviewed with security in mind; this guide explains what that means in practice.

To report a security vulnerability, do not open an issue: follow [SECURITY.md](SECURITY.md).

By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

- Go, at the version declared in [`go.mod`](go.mod). The `toolchain` line lets a recent Go
  download the exact version on its own.
- Docker, to build and run the image.
- [golangci-lint](https://golangci-lint.run/) v2, for `make lint`.
- Optionally, [pre-commit](https://pre-commit.com/): `pre-commit install` runs gitleaks,
  gofmt and go vet before each commit.

No OVHcloud account is needed to build, lint or test Keymaker. The test suite runs on fixtures,
without network access; a test that needs a credential is a bug in the test.

## Make targets

| Target | What it does |
| --- | --- |
| `make help` | List the targets |
| `make build` | Build `./bin/keymaker` with version information |
| `make test` | Run the tests with the race detector and coverage |
| `make lint` | Check `gofmt`, `go mod tidy` and run golangci-lint |
| `make vuln` | Run govulncheck |
| `make markdown` | Check the Markdown files against `.markdownlint-cli2.jsonc` (needs `npx`) |
| `make check` | Run every check CI runs, in its order: lint, Markdown, tests, govulncheck |
| `make fuzz` | Explore every fuzz target, 30 seconds each, or `FUZZTIME` |
| `make snapshot` | Regenerate the embedded API catalogue |
| `make demo` | Run the interface on invented data, without an OVHcloud account |
| `make docker` | Build the image for the local platform |

To try a change against a real account, point the binary at a configuration file kept outside
the repository:

```bash
make build
KEYMAKER_CONFIG=~/ovh.conf KEYMAKER_LOG_LEVEL=debug ./bin/keymaker
```

Without an account, or to see a finding your account does not have, `make demo` runs the real
server and interface on invented keys, one of each finding among them, and never calls the API.
Revocations and deletions apply to its memory and are forgotten on restart. To see the
interface at the size of a large account, `go run ./tools/demo -keys 500` adds that many
invented keys.

## Workflow

1. Open an issue first for anything beyond a small fix, so the approach can be agreed before
   you spend time on it.
2. Create a short-lived branch from `main`, named after the kind of change:
   `feat/…`, `fix/…`, `docs/…` or `chore/…`.
3. Write commits following [Conventional Commits](https://www.conventionalcommits.org/):
   `feat: …`, `fix: …`, `docs: …`, `chore: …`, `ci: …`, `test: …`, `refactor: …`.
4. Open a pull request against `main` and fill in the checklist. The pull request title follows
   Conventional Commits too, because pull requests are squash-merged and the title becomes the
   commit message.
5. CI must pass: formatting, `go mod tidy`, golangci-lint, Markdown, tests, govulncheck, CodeQL
   and the multi-architecture image build. `make check` runs the same checks locally, but for
   CodeQL and the image, before you open the pull request.

## What every change needs

- **Tests.** New behaviour comes with tests, and fixed bugs with a test that fails without the
  fix. Any new interaction with the OVHcloud API comes with a JSON fixture shaped after a real
  response, with every identifier and credential replaced by a placeholder.
- **Documentation.** Keep `README.md` and `README.fr.md` in step: a change to one is made in
  the other in the same pull request. Update `docs/ARCHITECTURE.md` when the design changes.
  Markdown is checked in CI against `.markdownlint-cli2.jsonc`; to run the same check locally,
  `npx markdownlint-cli2 $(git ls-files '*.md')`.
- **Changelog.** A change a user would notice gets an entry under `## [Unreleased]` in
  [CHANGELOG.md](CHANGELOG.md), in the `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or
  `Security` group, written for users rather than for reviewers.
- **License header.** Every new source file starts with:

  ```go
  // Copyright 2026 Kentrow
  // SPDX-License-Identifier: Apache-2.0
  ```

  with the comment syntax of the language for JavaScript, CSS and HTML.
- **English.** Code, comments, commit messages and documentation are in English, except
  `README.fr.md` and the French strings of the interface.

## Rules that protect credentials

These rules come from the security model described in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model). A change that needs one of them
relaxed needs an issue first.

1. **Nothing is persisted.** No file, database or cache. The configuration file is only read.
2. **No secret is logged.** Everything goes through `log/slog` and its redaction handler; do not
   use `fmt.Print`, and do not give a type that holds a secret a `String` or `MarshalJSON`
   method. golangci-lint enforces the first part.
3. **The backend calls a closed list of endpoints.** Each call's route is built in
   `internal/ovh` by the method that makes it; no request parameter ever becomes a URL. Adding an
   endpoint means adding a method, a fixture and a line in `docs/ARCHITECTURE.md`, and adjusting
   `ovh.ManagementRules` if it needs a rule.
4. **The credential in use cannot be revoked.** Keep the guard in the provider, not only in the
   interface.
5. **No new outbound host.** The OVHcloud API and the optional `api.ipify.org` lookup are the
   only ones.
6. **No new dependency without discussion.** The dependency list is enforced by `depguard` in
   `.golangci.yml`; explain in the pull request why the standard library is not enough.

## The interface

The interface is plain HTML, CSS and JavaScript in `internal/web/static`, embedded in the
binary, with no build step. Alpine.js is vendored in its CSP build, which evaluates no
expression strings: a directive may only name a property or a method, and anything computed
belongs in `app.js`. This is what keeps the content security policy free of `unsafe-eval`.

Since nothing compiles these files, `go test ./internal/web` checks them, and refuses things no
other Go project refuses. Each of these mistakes has shipped once and failed silently in a
browser, which is why they fail loudly here. When one of them stops you:

| A failure about | What it means, and the usual fix |
| --- | --- |
| a directive holding an expression | Alpine's CSP build cannot evaluate it. Move the logic into a getter or a method of `app.js`, and name that in the markup. |
| a label defined and asked for nowhere, or asked for and defined nowhere | Every label exists in both `en` and `fr`, and is shown somewhere. Add the missing translation, or remove a label no screen uses any more. |
| a CSS class unused, unstyled, defined twice, or used as a modifier and as a component | Remove the leftover rule or class, or rename one of the two so they do not collide. |
| a custom property read but not declared, or declared but not read | Declare it in the `:root` blocks of `app.css`, or remove it. |
| a method called but not defined, or a member or top-level declaration nothing reads | Define the method, or remove what a removed screen left behind. |
| an error code or a finding code | The codes the backend sends and the audit raises must be exactly those the dictionaries word, in both languages. Add the wording, or remove a code that is no longer sent. |
| a resource loaded from outside the binary | No CDN, font, script or image from elsewhere: vendor it under `static/`, or use a data URI. |

A new audit finding needs a key in `tools/demo` that raises it: `go test ./tools/demo` fails
until there is one, so that every finding can be seen before it ships.

## The route catalogue

The explorer reads the API catalogue at startup and falls back to the copy of its region in
`internal/catalog/snapshots/` when that fails: the regions do not publish the same API, so each
has its own. The copies are committed and regenerated by hand, so that what ships is a reviewed
file:

```bash
make snapshot
```

The catalogue package embeds that file and does not compile without it.

## License of contributions

Keymaker is licensed under the [Apache License 2.0](LICENSE). As stated in section 5 of that
license, any contribution you intentionally submit for inclusion is provided under the same
license, without additional terms. There is no Contributor License Agreement and no Developer
Certificate of Origin to sign.
