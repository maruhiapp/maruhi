# Contributing to maruhi

Thanks for your interest in contributing to maruhi. Issues and pull requests are welcome.

## Development setup

- The runtime is Bun, pinned exactly by `.bun-version` (currently 1.3.14). The 1.4 series from ADR-0004 has not been reached yet
- Install dependencies with `bun install`
- Run the full quality gate before committing: `bun run check` (oxfmt → oxlint → tsc → ImportLint → fallow → React Doctor → tests)

For development rules, see [CLAUDE.md](CLAUDE.md) (Japanese) and [docs/adr/](docs/adr/) (Japanese). In particular:

- The crypto specification [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) (Japanese) is the sole source of truth. Changes to `packages/crypto` must go through human review and verification against the test vectors (`test-vectors/`)
- Changes that let plaintext secrets pass through the server API, disk, or logs (the diskless invariant) will not be accepted

## License layout and how contributions are treated

This repository uses different licenses per area ([ADR-0003](docs/adr/0003-license-fsl-mit.md); Japanese):

- Repository default (including `apps/server` and `apps/web`): [FSL-1.1-MIT](LICENSE.md)
- `apps/cli`, `packages/crypto`, `packages/core`, `packages/api-schema`: MIT (`LICENSE` in each directory)

By submitting a pull request, you agree that your contribution is offered under the license that applies to the directory you change.

## DCO (Developer Certificate of Origin)

Every commit needs a `Signed-off-by` trailer showing agreement with [DCO 1.1](https://developercertificate.org/). The `-s` flag adds it automatically:

```sh
git commit -s
```

The trailer must look like the following, using your real name or a consistent identity that identifies you, and a valid email address:

```
Signed-off-by: Your Name <your@example.com>
```

<details>
<summary>Developer Certificate of Origin 1.1 (full text)</summary>

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

</details>

## Security

If you find a vulnerability, do not put details in a public issue. Report it through GitHub Private Vulnerability Reporting (Security tab → Report a vulnerability).
