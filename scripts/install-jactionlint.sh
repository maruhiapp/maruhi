#!/usr/bin/env bash
set -euo pipefail

die() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error::install-jactionlint: $*" >&2
  else
    echo "install-jactionlint: $*" >&2
  fi
  exit 1
}

if [ "$#" -ne 2 ]; then
  die "usage: install-jactionlint.sh <linux-x64|darwin-arm64> <destination>"
fi

readonly platform="$1"
readonly destination="$2"
[ -n "$destination" ] || die "the destination must not be empty"
readonly release_base="https://github.com/jdx/jactionlint/releases/download/v2.2.0"

case "$platform" in
  linux-x64)
    readonly archive_name="jactionlint_2.2.0_linux_amd64.tar.gz"
    readonly archive_size="7399119"
    readonly archive_sha256="8137d5bfe266dd5e48d2af2306827785ce07c6988e04b1c3d6ad4776e97d27d2"
    readonly binary_sha256="61001c6104348bf3651a7c1c76587cb98531968c03f7162cb9fedbe2e2159327"
    ;;
  darwin-arm64)
    readonly archive_name="jactionlint_2.2.0_darwin_arm64.tar.gz"
    readonly archive_size="6870439"
    readonly archive_sha256="622b29b15a59618bc032163073209ffc434252e9a19eafd451e69207a50f266a"
    readonly binary_sha256="d4ca2db16dff90dd631a3439465cbd11f96f9b6237d68493697a88ec70abfbb7"
    ;;
  *)
    die "unsupported jactionlint platform: $platform"
    ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
archive="$temporary/$archive_name"

curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --retry-all-errors \
  "$release_base/$archive_name" \
  --output "$archive" || die "jactionlint archive download failed"

actual_size="$(wc -c < "$archive" | tr -d '[:space:]')"
if [ "$actual_size" != "$archive_size" ]; then
  die "jactionlint archive size mismatch: expected $archive_size, received $actual_size"
fi

actual_archive_sha256="$(shasum -a 256 "$archive" | awk '{print $1}')"
if [ "$actual_archive_sha256" != "$archive_sha256" ]; then
  die "jactionlint archive SHA-256 mismatch"
fi

rm -rf "$destination"
mkdir -p "$destination"
tar -xzf "$archive" -C "$destination" jactionlint

actual_binary_sha256="$(shasum -a 256 "$destination/jactionlint" | awk '{print $1}')"
if [ "$actual_binary_sha256" != "$binary_sha256" ]; then
  die "jactionlint binary SHA-256 mismatch"
fi

chmod 755 "$destination/jactionlint"
if [ "$("$destination/jactionlint" --version | head -n 1)" != "2.2.0" ]; then
  die "jactionlint binary version mismatch"
fi
echo "install-jactionlint: verified jactionlint 2.2.0 for $platform"
