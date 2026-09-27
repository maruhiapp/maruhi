# Release procedure (CLI)

The distribution design is [ADR-0015](./adr/0015-cli-distribution.md); the implementation is
[`.github/workflows/release.yml`](../.github/workflows/release.yml). This file records **operational procedure only**.

## First time only (owner's human tasks)

1. **Confirm publish rights on the npm org** — the account/org must be able to publish
   the unscoped `maruhi` (open item from session-22 §4)
2. **Configure the trusted publisher** (npmjs.com → package `maruhi` → Settings → Trusted Publisher):
   - Provider: GitHub Actions
   - Organization/User: `maruhiapp` / Repository: `maruhi`
   - Workflow filename: `release.yml` (leave Environment blank)
   - New configurations since 2026-05-20 require an explicit allowed action — pick "publish"
3. Registering an npm token in GitHub Secrets is **not needed** (OIDC only. No long-lived tokens)
4. (Recommended) Restrict creation of `v*` tags to admins via a GitHub tag ruleset
   (the workflow also checks "tag = a commit on main's lineage", but defense in depth)

## Normal release

1. **Version-bump PR**: bump `version` in `apps/cli/package.json` (that alone propagates to
   `--version`, the binaries, and npm — a single source). Merge it
2. **Tag main** (tag = `v` + the package.json version. The workflow stops if they do not match):

   ```sh
   git switch main && git pull
   git tag v0.1.0-rc.1
   git push origin v0.1.0-rc.1
   ```

3. The release workflow automatically: runs the quality gate (all ci.yml steps) → checks version
   match → builds binaries for 5 targets + checksums.txt → smokes them on 5 real OS runners →
   creates the GitHub Release (notes auto-generated. `-rc.N` marked prerelease) → npm publish
   (with provenance. `-rc.N` goes to dist-tag `next`, stable to `latest`)
4. **Verify**: the Release carries tar.gz × 5 + checksums.txt,
   `npm view maruhi dist-tags` looks as expected, and the npm page shows the
   provenance badge

## Updating the Homebrew tap (stable releases only, after the release completes)

The tap is a separate repository, `maruhiapp/homebrew-maruhi`. The formula is a **generated file**,
built by [`apps/cli/scripts/generate-formula.ts`](../apps/cli/scripts/generate-formula.ts) from the
Release's `checksums.txt` (do not copy sha256 values by hand).

**Prereleases (`-rc.N`) are not published to the tap** — the generator refuses by default
(`--allow-prerelease` overrides it, but is not normally used).

### First time only (owner's human tasks)

1. On GitHub, create **`maruhiapp/homebrew-maruhi`** (public. The `homebrew-` prefix is required —
   it is what makes `brew install maruhiapp/maruhi/maruhi` resolve)
2. Create a `Formula/` directory at the repository root (a README is a nice touch)
3. Once the first formula is in place, **tap it and grant trust, then** run audit.
   `brew audit` loads and evaluates the formula's Ruby, so with an untrusted tap it fails
   without being able to read the formula (Homebrew 6.0.0 tap trust. Trust is once per machine):

   ```sh
   brew tap maruhiapp/maruhi
   brew trust --tap maruhiapp/maruhi
   brew audit --new maruhiapp/maruhi/maruhi   # --new implies --strict and --online
   ```

   **The repository-side CI only checks `ruby -c` (syntax) and golden equality; the Homebrew
   DSL semantics (`on_macos` > `on_arm` nesting, `bin.install_symlink`, `test do`) cannot run
   until the tap exists**. If audit flags something, do not fix the formula by hand —
   fix `apps/cli/scripts/formula.ts` (the formula is generated; hand edits vanish on the next release)

### Every release

```sh
# 1. Generate the formula from the Release's checksums.txt (default output: packaging/homebrew/maruhi.rb)
bun apps/cli/scripts/generate-formula.ts --version v0.1.0

# 2. Copy it into the tap repository and push (the content diff is only the 4 targets' version / url / sha256)
cp packaging/homebrew/maruhi.rb ../homebrew-maruhi/Formula/maruhi.rb
cd ../homebrew-maruhi && git add Formula/maruhi.rb && git commit -m "maruhi 0.1.0" && git push

# 3. Verify on a real machine (if already tapped: `brew update && brew upgrade maruhi`).
#    Since Homebrew 6.0.0, third-party taps need an explicit trust grant before evaluation (once per machine)
brew trust --tap maruhiapp/maruhi
brew install maruhiapp/maruhi/maruhi
maruhi --version && mh --version
brew test maruhi
```

`--checksums <path>` (use a local `apps/cli/dist/checksums.txt`) and `--out <path>`
(write directly to the tap's path) are also available. Omitting `--version` uses the version in `apps/cli/package.json`.

There is no automated PR (the release workflow pushing to the tap) because that would mean adding a
cross-repo write credential to the release path, which already holds `contents: write` +
`id-token: write` (it does not balance with ADR-0015's permission minimization). Revisit if release
cadence rises.

## Dry run (pipeline verification before tagging)

The release workflow can run everything except publish (build + 5-OS smoke +
checksums + npm staging) via `workflow_dispatch`. On PRs that touch the workflow,
run it once against the branch before merging.

Exception (bootstrap): `workflow_dispatch` only works once the workflow exists on the
**default branch**, so the very PR that creates or renames release.yml cannot be
dry-run before merging. In that case, run one dry run on main right after merging and
**before** tagging.

## Retrying

**Do not re-tag** (re-pushing an existing tag fails at Release creation and stops.
That is by design). For a failed release, fix the cause and retry with the **rc number
bumped** (`v0.1.0-rc.1` → `v0.1.0-rc.2`). A version already published to npm is not
revoked (no unpublish. npm also rejects re-publishing over it).

**Exception — when only publish-npm failed** (the Release exists but npm did not get it):
no need to bump the rc. npm has not consumed that version, so fix the cause (the first
time it is usually the trusted publisher config — workflow name, org, allowed action)
and **re-run the failed job** on the same run to recover on the same version (re-run
works within the artifact retention window = **30 days**. Past that, bumping the rc is
the only way).
However, **re-run only fixes config/environment causes**. A failure that needs a code
fix cannot be re-run away (the run uses the workflow and artifacts from tag time), so
fix it and bump the rc (the v0.1.0-rc.1 bin-normalization bug is a real example). The
order Release-first → npm-later exists to make this recovery possible (in reverse, a
published npm version cannot be retried).
Note also that **the OIDC (trusted publishing) path cannot be exercised by a dry run**
(authentication only happens when publish actually runs). Before the first tag,
re-confirm the first-time setup (items 1–3 above).

## Notes

- **The public body of a GitHub Release is English** (ADR-0017 decision 1). The workflow builds the body from PR titles via `gh release create --generate-notes` (no `--draft` = public the moment the tag is pushed). The owner rewrites the Release body to English right after publication (`--draft` / `--notes-file` usage and English PR titles are separate decisions)
- **windows-x64 is experimental** (the Credential Manager path is unverified. The
  fail-closed design means it cannot break on the dangerous side — ADR-0015)
- **macOS is not notarized**. A browser download gets quarantined by Gatekeeper
  (a curl download does not). Notarization is handled at the public-release stage (ROADMAP)
- Release artifacts come from source only (binaries, bundled JS, checksums).
  There is no path for secrets like `.dev.vars` to enter the workflow
- **The install script is distributed at a tag-pinned raw URL**
  (`raw.githubusercontent.com/maruhiapp/maruhi/<tag>/packaging/install.sh`).
  Tagging already publishes that version's script, so there is no extra release step.
  The script itself is verified per-PR by [`installer.yml`](../.github/workflows/installer.yml)
  on 4 real OSes (independent of actual releases)
- However, **the branch that resolves "the latest stable" when `--version` is omitted cannot be
  exercised in CI** (during the prerelease period `releases/latest` does not exist, and the
  harness always sets `MARUHI_BASE_URL` = a path that skips resolution). **Right after
  shipping the first stable `v0.1.0`, run it once without `--version` to verify**. If it
  is broken it fails with an explicit "specify a tag" error — a silent install of an old
  version cannot happen
