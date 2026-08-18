# setup-maruhi

Installs the [maruhi](https://github.com/maruhiapp/maruhi) CLI in a GitHub
Actions job, so the job can lease secrets through `maruhi ci run` — with **no
secrets stored on GitHub** and **nothing written to disk**.

The binary is downloaded from the maruhi GitHub release assets and verified
against `checksums.txt` (SHA-256) before anything is installed. Linux and
macOS runners are supported (`linux-x64` / `linux-arm64` / `darwin-x64` /
`darwin-arm64`); Windows runners are not.

> This action lives inside the maruhi repository for now. Reference it as
> `maruhiapp/maruhi/actions/setup-maruhi@<ref>`. A Marketplace listing will
> follow when the repository goes public.

## Requirements

- **`permissions: id-token: write` on the job.** `maruhi ci run`
  authenticates with a GitHub Actions OIDC token — without this permission
  the runner does not expose the token endpoint and the command fails with an
  explanatory error. No other credential is needed: no maruhi API token, no
  repository secret, no keychain.
- **A workload lease grant on the project.** A project owner must have run
  `maruhi server grant` with a lease policy that matches this workflow (see
  [Server-side setup](#server-side-setup)).

## Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # required: maruhi ci run authenticates via OIDC
      contents: read
    steps:
      - uses: actions/checkout@v4

      # Pin the action to a tag or commit SHA — it installs the binary that
      # will hold your decrypted secrets in memory. Do not use a mutable ref.
      # Replace <tag> with the first release tag that contains this action
      # directory (tags up to v0.1.0-rc.2 predate it and will not resolve)
      - uses: maruhiapp/maruhi/actions/setup-maruhi@<tag>
        with:
          # Required while no stable release exists (releases/latest cannot
          # be resolved during the pre-release period)
          version: v0.1.0-rc.1

      - name: Deploy with leased secrets
        run: >-
          maruhi ci run
          --server https://maruhi.example.com
          --project 4f0c…64-hex-project-id…9a1b
          --env prod
          --anchor .maruhi/anchor.json
          -- ./scripts/deploy.sh
```

`maruhi ci run` performs, in one round-trip:

1. generates an ephemeral X25519 key pair in memory (it dies with the job),
2. mints a fresh GitHub Actions OIDC token (audience defaults to the server
   origin; override with `--audience`),
3. requests the lease and receives the chain, ciphertexts, signed statements
   and the epoch DEKs re-sealed to the ephemeral key,
4. verifies everything client-side — the chain against the **pinned genesis**
   (`--project` *is* the genesis hash), every value signature and metadata
   statement, and every DEK against its chain-published commitment — before
   anything is decrypted,
5. injects the decrypted values into the child process environment only
   (memory injection; no file is ever written).

### Inputs

| Input     | Required | Description                                                                     |
| --------- | -------- | ------------------------------------------------------------------------------- |
| `version` | for now  | Release tag to install (e.g. `v0.1.0-rc.1`). May be omitted once a stable release exists. |

### Flags of `maruhi ci run`

All configuration is passed as explicit flags — CI mode reads no config file
and no keychain, so the values live in your reviewed workflow file:

| Flag         | Required | Description                                                                  |
| ------------ | -------- | ---------------------------------------------------------------------------- |
| `--server`   | yes      | maruhi server URL                                                            |
| `--project`  | yes      | Project ID — the genesis hash your job pins and verifies the chain against   |
| `--env`      | yes      | Environment ID to lease                                                      |
| `--audience` | no       | OIDC audience (defaults to the server origin)                                |
| `--anchor`   | no       | Path to the committed repository anchor file (rollback detection — see below) |

To lease several environments in one job, run `maruhi ci run` once per
environment. Each invocation mints its own token and its own ephemeral key.

## Server-side setup

A project **owner** enables the lease path by disclosing the environment DEKs
to the server with a lease policy bound to the membership chain:

```sh
maruhi server grant --environments prod --lease-policy lease-policy.json
```

```json
[
  {
    "issuerUrl": "https://token.actions.githubusercontent.com",
    "audience": "https://maruhi.example.com",
    "claimConstraints": {
      "repository": "acme/app",
      "ref": "refs/heads/main"
    }
  }
]
```

Claim constraints are exact-match. To allow several branches, list one policy
element per branch. The policy lives on the signed chain (owner-signed,
append-only), never in mutable server configuration.

## Repository anchor (recommended)

A CI job is a floorless, unattended client: it cannot remember the chain head
it verified last time, so a compromised server could serve it an old (but
validly signed) view — for example a pre-rotation view that keeps a leaked
credential deployed. The **repository anchor** closes this: a project member
commits a small non-secret file (chain head + per-environment epochs), and
`maruhi ci run --anchor` refuses any response whose chain does not contain the
anchored head or regresses below the anchored epochs.

```sh
maruhi project anchor > .maruhi/anchor.json
git add .maruhi/anchor.json && git commit -m "chore: update maruhi anchor"
```

Re-run this after every rotation (`maruhi env rotate`) so the anchor keeps up
with the current epochs. The file contains only hashes, sequence numbers and
epoch numbers — no key material and no secret values.

## Failure modes worth knowing

- 404: the lease endpoint answers a **uniform 404** for an unknown project,
  a missing grant, a lease-policy mismatch (issuer / audience / claim
  constraints), and an out-of-scope or unknown environment (existence
  hiding). If your coordinates look right, the most common cause is a policy
  mismatch — e.g. the workflow runs on a branch or repository the policy does
  not list. Fix the policy with `maruhi server grant --lease-policy`.
- `token-replayed` (401): the OIDC token was already bound to a different
  ephemeral key (first-use binding). `maruhi ci run` automatically mints a
  fresh token and retries **once**; if it happens again, treat it as a signal
  that this job's tokens are being exfiltrated.
- 429: the project's lease window (fixed, per hour) is exhausted. The CLI
  does not retry — re-run the job later.
- 503 `oidc-jwks-unavailable`: transient issuer / network condition on the
  server side — retry the job.
- 503 `server-wraps-missing`: the grant exists but the DEKs are not yet
  re-wrapped to the server key — an administrator should finish the pending
  rotation or grant backfill.
- 503 `server-key-unconfigured`: the deployment has no server key — see
  `docs/SELF_HOSTING.md`.
