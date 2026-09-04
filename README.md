# maruhi ㊙

A general-purpose, diskless secrets manager that runs on Cloudflare.

- **Self-hostable** — a serverless stack (Workers + Durable Objects + D1) that comes up on your own Cloudflare account with a single `wrangler deploy`
- **E2EE (zero-knowledge) by default** — encryption and decryption happen entirely on the client; plaintext secrets never reach the server
- **Diskless CLI** — `maruhi run -- <cmd>` injects values into a child process's environment in memory only, and never writes plaintext to disk

> **Status**: in development (pre-release). APIs and specs may change without notice.

## Install (CLI)

The distribution design is recorded in [ADR-0015](docs/adr/0015-cli-distribution.md) (Japanese).

### install script (Linux / macOS. Recommended. Bun not required)

```sh
# Replace V with the latest tag on the Releases page
# (https://github.com/maruhiapp/maruhi/releases).
# During the pre-release period (until v0.1.0), releases/latest does not exist,
# so you must specify the tag explicitly
V=<latest-tag>
curl -fsSL "https://raw.githubusercontent.com/maruhiapp/maruhi/${V}/packaging/install.sh" -o maruhi-install.sh
less maruhi-install.sh          # read the script before running it (see the trust model below)
sh maruhi-install.sh --version "${V}"
```

This places `maruhi` and `mh` (a symlink to `maruhi`) in `~/.local/bin`. It does not use sudo.
From stable `v0.1.0` onward you can omit `--version` and the latest stable release is installed.

> The install script is bundled with a Release starting with **the release after `v0.1.0-rc.1`**.
> To install `v0.1.0-rc.1`, use "Install a prebuilt binary by hand" below
> (pointing `${V}` at an earlier tag makes the raw URL 404).

- Main options: `--dir <path>` (default `~/.local/bin`) / `--version <tag>`.
  The environment variables `MARUHI_INSTALL_DIR` / `MARUHI_VERSION` do the same. Full list: `sh maruhi-install.sh --help`
- A one-liner (`curl | sh`) also works —
  `curl -fsSL ".../${V}/packaging/install.sh" | sh -s -- --version "${V}"`.
  Read the trust model below before choosing that form
- Supported targets are linux-x64 / linux-arm64 / darwin-x64 / darwin-arm64. **Windows is not supported**
  (use the manual steps below)

<details>
<summary><b>Trust model for the install script</b> (stated explicitly because this is a secrets manager)</summary>

- The only host this script talks to is **github.com**. There is no telemetry and no outbound traffic of any kind ("say nothing").
  The only exception is when you yourself set `MARUHI_BASE_URL` (an internal-mirror / verification hook; unused by default)
- Each tar.gz is **verified** against the SHA-256 in `checksums.txt` **before** extraction. If verification fails, the
  script leaves no partial files in the install directory and exits non-zero
- `checksums.txt` itself is **not signed yet**. Integrity rests only on TLS to github.com
  (signing is future work). We do not claim "signature verification" for something that does not exist.
  That is why `curl | sh` is not the default, and why the first instructions are **download, read, then run**
- The script does not edit shell config files (`~/.zshrc` and similar). It only prints a line to add to PATH
- macOS binaries are not notarized, but **a curl download does not receive Gatekeeper's quarantine attribute**
  (a browser download does). Notarization lands as part of the public-release preparation

</details>

### Homebrew (macOS / Linuxbrew)

> **Not ready yet** — the tap (`maruhiapp/homebrew-maruhi`) is not published. The formula ships from
> stable `v0.1.0` (prereleases are not added to the tap). Until then, use the install script above.

```sh
# Homebrew 6.0.0 and later require an explicit trust grant before third-party tap
# code is evaluated (older brew has no `brew trust`, so skip this line)
brew trust --tap maruhiapp/maruhi
brew install maruhiapp/maruhi/maruhi
```

`brew trust` is Homebrew's mechanism for asking the user to consent before running the tap's Ruby
code; it is not a maruhi-specific requirement (untrusted taps are not auto-tapped).

<details>
<summary><b>Install a prebuilt binary by hand</b> (this is the Windows path)</summary>

Download the platform-specific `maruhi-<os>-<arch>.tar.gz` from
[GitHub Releases](https://github.com/maruhiapp/maruhi/releases), verify the checksum, and extract:

```sh
# Example: Apple Silicon Mac (linux-x64 / linux-arm64 / darwin-x64 / windows-x64 are the same).
# Replace V with the latest tag on the Releases page (during the pre-release
# period, releases/latest does not exist, so use a tag URL)
V=v0.1.0-rc.1
curl -fsSLO "https://github.com/maruhiapp/maruhi/releases/download/${V}/maruhi-darwin-arm64.tar.gz"
curl -fsSLO "https://github.com/maruhiapp/maruhi/releases/download/${V}/checksums.txt"
shasum -a 256 --ignore-missing -c checksums.txt   # on Linux: sha256sum --ignore-missing -c
tar -xzf maruhi-darwin-arm64.tar.gz
./maruhi --version
```

If you want the `mh` alias, link it next to the binary: `ln -s maruhi mh`

- **windows-x64 is experimental** (the Credential Manager path is unverified. If the keychain
  has a problem, maruhi does not fall back to plaintext; it stops with a typed error). scoop / winget are future work
- macOS binaries are not notarized, so a **browser** download is quarantined by Gatekeeper
  (a curl download, as above, does not get the quarantine attribute)

</details>

### npm (Bun runtime required)

The CLI depends on Bun-specific APIs such as the OS keychain (`Bun.secrets`), so the npm package
needs [Bun](https://bun.sh). The minimum version matches the repository [`.bun-version`](.bun-version);
the published package's `engines.bun` is derived from the same file. Without Bun:
starting under Node.js prints a hint and exits; invoking `maruhi` directly on Unix fails at shebang
resolution as `env: bun: No such file or directory` (wording varies with the OS `env` implementation.
Either way, installing Bun fixes it):

```sh
# During the pre-release period (until v0.1.0), pass the dist-tag `next`.
# Bare `maruhi` currently points at the placeholder (0.0.1) — be careful
bun install -g maruhi@next
maruhi --version             # mh --version is the same
```

From the stable release (`v0.1.0`) onward, `bun install -g maruhi` is enough.

## Docs

- [maruhi.app/docs](https://maruhi.app/docs) — the documentation site (source in `apps/site`; goes live with the hosted beta)
- [docs/CRYPTO_SPEC.md](docs/CRYPTO_SPEC.md) — crypto specification (sole source of truth; Japanese)
- [docs/AUTH_SPEC.md](docs/AUTH_SPEC.md) — authentication and identity specification (Japanese)
- [docs/SELF_HOSTING.md](docs/SELF_HOSTING.md) — self-hosting guide
- [docs/adr/](docs/adr/) — architecture decision records (Japanese)

## License

This repository uses different licenses per area ([ADR-0003](docs/adr/0003-license-fsl-mit.md); Japanese).

| Area | License |
|---|---|
| Repository default, including `apps/server` and `apps/web` | [FSL-1.1-MIT](LICENSE.md) |
| `apps/cli`, `packages/crypto`, `packages/core`, `packages/api-schema` | MIT (`LICENSE` in each directory) |
| Brand assets in `apps/web/public/` (the ㊙ mark: `logo*.svg`, `favicon*`, `og.png`) | The 秘 outline derives from Noto Sans CJK JP (SIL OFL 1.1) — notice and license text in [`apps/web/public/fonts/OFL-NotoSansCJK.txt`](apps/web/public/fonts/OFL-NotoSansCJK.txt) |
| Web fonts in `apps/site/public/fonts/` (Archivo, Martian Mono — served by the `maruhi.app` site) | SIL OFL 1.1 — notice and license text in [`OFL-Archivo.txt`](apps/site/public/fonts/OFL-Archivo.txt) and [`OFL-MartianMono.txt`](apps/site/public/fonts/OFL-MartianMono.txt) (Latin subsets from [Fontsource](https://fontsource.org), same sources as Google Fonts; neither family declares a Reserved Font Name) |

FSL-1.1-MIT (Functional Source License) only restricts offering the software as a competing hosted
service. Self-hosting, internal use, modification, and redistribution are unrestricted, and the
license converts to MIT automatically two years after publication. It is not OSI "open source";
it is source-available / Fair Source.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every commit needs a DCO `Signed-off-by`.
