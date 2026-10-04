# Releasing

A release is a tag `vX.Y.Z` pushed on `main`. The release workflow does the rest: it runs the
tests, builds the image for `linux/amd64` and `linux/arm64`, pushes it to
`ghcr.io/kentrow/keymaker` with provenance and an SBOM, and creates the GitHub release with the
notes taken from `CHANGELOG.md`. Everything before the tag is about making sure those notes, and
the image they describe, are right.

Releases are cut by the maintainer. The steps below assume the `gh` CLI is logged in.

## Which number

- **Patch** (`0.3.1`): fixes only, security fixes included.
- **Minor** (`0.4.0`): anything a user can see that is not a fix.
- **Major** (`2.0.0`): anything that breaks what the Compatibility section of the README lists.
- The image gets `X.Y.Z`, `X.Y`, `X` and `latest`. Releases before 1.0 published no major tag,
  so `0` never moved under anyone.

## 1. Prepare the release branch

Start from an up-to-date `main` on which the CI is green:

```bash
git switch main && git pull --ff-only origin main
git switch -c chore/release-X.Y.Z
```

Then, in `CHANGELOG.md`:

- rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, and add an empty `## [Unreleased]`
  above it;
- at the bottom, point `[Unreleased]` at `compare/vX.Y.Z...HEAD` and add
  `[X.Y.Z]: https://github.com/kentrow/keymaker/compare/vPREVIOUS...vX.Y.Z`.

The READMEs point at the major tag, `ghcr.io/kentrow/keymaker:1`, and do not change with a
release; only a new major version updates them:

```bash
grep -n "keymaker:[0-9]" README.md README.fr.md   # every line on the major of this release
```

Then refresh the route catalogues embedded in the binary, one per region. They are what an
instance shows when it cannot read the API index, and the demo runs on the ovh-eu one, so each
release ships recent ones:

```bash
make snapshot     # prints the number of routes and branches captured for each region
git diff --stat internal/catalog/snapshots/
```

The tests check every sensitive branch of the audit against the ovh-eu catalogue, so a branch
the API removed shows up in step 3.

## 2. Read the notes the workflow will publish

The workflow copies the section of `CHANGELOG.md` under the version heading, and fails when it
finds nothing. Run the same extraction locally and read what comes out, since it becomes the
public release page:

```bash
version=X.Y.Z
awk -v heading="## [${version}]" '
  index($0, heading) == 1 { found = 1; next }
  found && (/^## \[/ || /^\[[^]]+\]: /) { exit }
  found { print }
' CHANGELOG.md
```

## 3. Run every check

```bash
make lint test vuln
gitleaks dir .
```

## 4. Try it on a real account

The tests cannot reach the API. Before tagging, build the branch and walk through it against a
real account:

```bash
make build
KEYMAKER_CONFIG=./ovh.conf ./bin/keymaker
```

Open the four screens, check that the inventory and the applications load, and that the browser
console stays empty. Give the management key a validity of 30 days rather than one: a key that
expires in a day stops the tool the next morning.

## 5. Merge

```bash
git add -A
git commit -m "chore: release X.Y.Z"
git push -u origin chore/release-X.Y.Z
gh pr create --base main --title "chore: release X.Y.Z" \
  --body "Release notes for X.Y.Z."
gh pr checks --watch
gh pr merge --squash --delete-branch
```

## 6. Tag

Nothing else may be merged between the release pull request and the tag, or the notes no longer
describe the image.

```bash
git switch main && git pull --ff-only origin main
git log --oneline -1          # must be "chore: release X.Y.Z"
git tag -a vX.Y.Z -m "Keymaker X.Y.Z"
git push origin vX.Y.Z
gh run watch
```

## 7. Check what was published

```bash
gh release view vX.Y.Z
docker run --rm ghcr.io/kentrow/keymaker:X.Y.Z --version
docker buildx imagetools inspect ghcr.io/kentrow/keymaker:X.Y.Z
gh attestation verify oci://ghcr.io/kentrow/keymaker:X.Y.Z --repo kentrow/keymaker
```

`--version` names the release and the commit of the tag. The image index lists both platforms,
each with an attestation manifest, and `X.Y.Z`, `X.Y`, `X` and `latest` share one digest. The
READMEs point at `X`, so that tag is the one a reader actually pulls.

## 8. After the release

Close the milestone of the release, if it had one, so that no new issue is filed under a
version that has shipped:

```bash
gh api "repos/kentrow/keymaker/milestones?state=open" --jq '.[] | "\(.number) \(.title)"'
gh api -X PATCH repos/kentrow/keymaker/milestones/NUMBER -f state=closed
```

The release badge at the top of the README can keep showing the previous version for a while:
GitHub serves images through its own cache. To refresh it, take the `camo.githubusercontent.com`
address of the badge from the repository page and purge it:

```bash
curl -s https://github.com/kentrow/keymaker | grep -o 'https://camo.githubusercontent.com/[a-f0-9/]*'
curl -X PURGE "<the address of the release badge>"
```

## If a tag went out wrong

Before the release is announced anywhere, a tag and its release can be taken back and cut
again:

```bash
gh release delete vX.Y.Z --yes
git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z
```

The images already pushed stay in the registry under that version; the next push of the same
tag replaces them. Once a release has been announced, publish a new patch version instead of
rewriting one people may already run.
