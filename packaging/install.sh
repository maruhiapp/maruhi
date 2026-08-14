#!/bin/sh
# maruhi install script(Unix: linux-x64 / linux-arm64 / darwin-x64 / darwin-arm64)
#
#   curl -fsSL https://raw.githubusercontent.com/maruhiapp/maruhi/<tag>/packaging/install.sh -o install.sh
#   less install.sh          # 中身を読んでから実行するのが正道
#   sh install.sh --version <tag>
#
# 設計(docs/adr/0015-cli-distribution.md / README.md):
# - 外部アクセスは github.com からの取得のみ。テレメトリ・外部送信は無い(CLAUDE.md「言わざる」)
# - checksums.txt による SHA-256 検証を必須とし、検証を通るまでインストール先へ一切書かない。
#   途中で失敗したら部分ファイルを残さず非 0 で終わる
# - 「署名検証」は書かない: checksums.txt は現時点で未署名で、完全性の根拠は github.com への
#   TLS のみ。無いものを検証したように見せない(署名導入は ROADMAP)
# - `mh` は maruhi への相対 symlink として張る(ADR-0015 裁定 6/7)
# - シェルの設定ファイル(~/.zshrc 等)は書き換えない。PATH へ足す行は表示するだけ
# - sudo を呼ばない。既定のインストール先は ~/.local/bin
#
# 全体を main() に包み、最終行で呼ぶ。転送が途中で切れた `curl | sh` が
# 中途半端に実行される形を塞ぐ。

# `local` は POSIX 未定義だが dash/ash/bash/zsh/busybox いずれも実装しており、
# 代替(全部グローバル変数)は関数間の取り違えの温床になる。ここだけ意図的に外す
# shellcheck disable=SC3043

set -eu

REPO="maruhiapp/maruhi"
RELEASES_URL="https://github.com/${REPO}/releases"

# 対応対象。apps/cli/scripts/shared.ts の TARGETS から windows-x64 を除いた 4 種と
# 一致することを apps/cli/test/installer.test.ts が検査する(対象表の複製を放置しない)。
SUPPORTED_TARGETS="linux-x64 linux-arm64 darwin-x64 darwin-arm64"

# set -u の下で参照する変数はすべてここで初期化する
VERSION=""
INSTALL_DIR=""
BASE_URL=""
EXPECTED_VERSION=""
INSTALLED_VERSION=""
TARGET=""
ARCHIVE=""
BINARY=""
SHA_TOOL=""
MH_LINKED="0"
TMP_DIR=""
PARTIAL_FILE=""

log() { printf '%s\n' "$*"; }
warn() { printf 'maruhi: 警告: %s\n' "$*" >&2; }
die() {
  printf 'maruhi: エラー: %s\n' "$*" >&2
  exit 1
}

# 失敗経路でも「途中状態」を残さない。TMP_DIR は作業一式、PARTIAL_FILE は
# インストール先へ rename する直前の一時ファイル
cleanup() {
  if [ -n "${TMP_DIR}" ]; then rm -rf "${TMP_DIR}"; fi
  if [ -n "${PARTIAL_FILE}" ]; then rm -f "${PARTIAL_FILE}"; fi
}

usage() {
  cat <<EOF
maruhi install script (Unix)

使い方:
  sh install.sh [--version <tag>] [--dir <path>]
  curl -fsSL <この script の URL> | sh -s -- --version <tag>

オプション:
  --version <tag>   入れる版(例: v0.1.0-rc.1)。省略時は最新の安定版を
                    ${RELEASES_URL}/latest から解決する。
                    プレリリース期間中は latest が存在しないため指定が必要
  --dir <path>      インストール先(既定: ~/.local/bin)。sudo は呼ばない
  -h, --help        このヘルプ

環境変数:
  MARUHI_VERSION      --version と同じ(--version が優先)
  MARUHI_INSTALL_DIR  --dir と同じ(--dir が優先)
  MARUHI_BASE_URL     アセットの取得元ディレクトリを差し替える(内部ミラー・
                      ローカル検証用。例: file:///path/to/dist)。指定時は
                      GitHub のタグ解決をせず、版指定は起動確認の期待値としてのみ使う

対応対象: ${SUPPORTED_TARGETS}
Windows は対象外(README の手動手順を参照)。
github.com からの取得以外の通信はしない。
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version)
        shift
        [ $# -gt 0 ] || die "--version にタグが必要です(例: --version v0.1.0-rc.1)"
        VERSION="$1"
        ;;
      --version=*) VERSION="${1#--version=}" ;;
      --dir)
        shift
        [ $# -gt 0 ] || die "--dir にパスが必要です"
        INSTALL_DIR="$1"
        ;;
      --dir=*) INSTALL_DIR="${1#--dir=}" ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "不明な引数: $1(--help でヘルプ)" ;;
    esac
    shift
  done
}

require_tools() {
  local cmd
  for cmd in curl tar grep mktemp uname; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      die "${cmd} が必要です"
    fi
  done
  # Linux は coreutils の sha256sum、macOS は shasum。どちらも無ければ入れない
  # (検証なしのインストールは行わない)
  if command -v sha256sum >/dev/null 2>&1; then
    SHA_TOOL="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    SHA_TOOL="shasum"
  else
    die "sha256sum も shasum も見つかりません。チェックサム検証なしでは入れません"
  fi
}

sha_check() {
  case "${SHA_TOOL}" in
    sha256sum) sha256sum -c "$1" ;;
    shasum) shasum -a 256 -c "$1" ;;
    *) die "内部エラー: 未知のチェックサムツール ${SHA_TOOL}" ;;
  esac
}

detect_target() {
  local os arch musl
  os="$(uname -s)"
  arch="$(uname -m)"
  case "${os}" in
    Linux)
      # 配布バイナリは glibc リンク(musl 対象は未提供)。ここで止めないと、
      # 実行時に "not found" という無関係に見える形で失敗する
      for musl in /lib/ld-musl-*.so.1; do
        if [ -e "${musl}" ]; then
          die "musl libc 環境(Alpine 等)向けのバイナリは未提供です。glibc 環境か、Bun 経由(bun install -g maruhi)をご検討ください"
        fi
      done
      case "${arch}" in
        x86_64 | amd64) TARGET="linux-x64" ;;
        aarch64 | arm64) TARGET="linux-arm64" ;;
        *) die "未対応の CPU アーキテクチャ: ${arch}(対応: ${SUPPORTED_TARGETS})" ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        arm64) TARGET="darwin-arm64" ;;
        x86_64)
          # Rosetta 下の sh から見た uname -m は x86_64。ネイティブ版を入れる
          if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf '0')" = "1" ]; then
            TARGET="darwin-arm64"
          else
            TARGET="darwin-x64"
          fi
          ;;
        *) die "未対応の CPU アーキテクチャ: ${arch}(対応: ${SUPPORTED_TARGETS})" ;;
      esac
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      die "Windows はこの script の対象外です。README の手動 tar 手順を参照してください: https://github.com/${REPO}"
      ;;
    *) die "未対応の OS: ${os}(対応: ${SUPPORTED_TARGETS})" ;;
  esac
}

normalize_version() {
  case "${VERSION}" in
    v*) ;;
    *) VERSION="v${VERSION}" ;;
  esac
  case "${VERSION}" in
    v[0-9]*) ;;
    *) die "版は v0.1.0 / 0.1.0 の形で指定してください: ${VERSION}" ;;
  esac
  # URL に載る値。想定外の文字をここで弾く
  case "${VERSION}" in
    *[!A-Za-z0-9.+-]*) die "版に使えない文字が含まれています: ${VERSION}" ;;
  esac
}

resolve_version() {
  local resolved
  if [ -n "${VERSION}" ]; then
    normalize_version
  elif [ -n "${BASE_URL}" ]; then
    # ミラー指定 + 版未指定: タグ解決も版の照合もしない
    return 0
  else
    # GitHub API(未認証 60 req/h・JSON 解析)には依存せず、releases/latest の
    # リダイレクト先タグを見る。プレリリースは latest にならないので、rc 期間中は
    # ここで解決できない = 推測せず明示エラーにする
    resolved="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${RELEASES_URL}/latest" 2>/dev/null)" || resolved=""
    case "${resolved}" in
      */releases/tag/?*) VERSION="${resolved##*/releases/tag/}" ;;
      *)
        die "最新の安定版を解決できませんでした。プレリリース期間中は releases/latest が存在しません — --version v0.1.0-rc.1 のようにタグを指定してください(一覧: ${RELEASES_URL})"
        ;;
    esac
    normalize_version
  fi
  EXPECTED_VERSION="${VERSION#v}"
}

resolve_base_url() {
  if [ -n "${BASE_URL}" ]; then
    BASE_URL="${BASE_URL%/}"
  else
    BASE_URL="${RELEASES_URL}/download/${VERSION}"
  fi
}

fetch() {
  # -f: HTTP エラーを非 0 に / -L: リダイレクト追従(Release アセットは
  # objects.githubusercontent.com へ 302)/ --retry: 一時障害のみ再試行
  if ! curl -fsSL --retry 3 --retry-delay 1 -o "$2" "$1"; then
    die "取得に失敗しました: $1"
  fi
}

download_and_verify() {
  local pattern matches
  ARCHIVE="maruhi-${TARGET}.tar.gz"
  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/maruhi-install.XXXXXX")" || die "作業ディレクトリを作れません"
  trap cleanup EXIT INT TERM

  fetch "${BASE_URL}/checksums.txt" "${TMP_DIR}/checksums.txt"
  fetch "${BASE_URL}/${ARCHIVE}" "${TMP_DIR}/${ARCHIVE}"

  # checksums.txt は sha256sum -c 互換(hex 64 桁 + スペース 2 個 + ファイル名)。
  # 自対象の行だけを取り出して検証する(他対象のアーカイブは手元に無いため、
  # 実装差のある --ignore-missing に頼らない)。行が 1 行でない・形式が違うのは
  # 改竄でも生成事故でも危険側なので拒否する
  pattern="^[0-9a-f]{64}  maruhi-${TARGET}\.tar\.gz\$"
  matches="$(grep -E -c "${pattern}" "${TMP_DIR}/checksums.txt" || true)"
  if [ "${matches}" != "1" ]; then
    die "checksums.txt に ${ARCHIVE} の行が 1 行だけ見つかりません(${matches:-0} 行)。取得元を確認してください: ${BASE_URL}/checksums.txt"
  fi
  grep -E "${pattern}" "${TMP_DIR}/checksums.txt" >"${TMP_DIR}/checksums.filtered"

  if ! (cd "${TMP_DIR}" && sha_check checksums.filtered); then
    die "SHA-256 が一致しません(${ARCHIVE})。取得元・通信経路を確認してください。何もインストールしていません"
  fi
}

extract_and_check() {
  local got
  mkdir -p "${TMP_DIR}/extract"
  tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}/extract" || die "アーカイブを展開できません(${ARCHIVE})"
  BINARY="${TMP_DIR}/extract/maruhi"
  [ -f "${BINARY}" ] || die "アーカイブの中身が想定と違います(maruhi が入っていません)"
  chmod 755 "${BINARY}"

  # インストール先へ触る前に起動を確認する。対象の取り違え・libc 不整合を
  # 「何も残さない失敗」として扱えるのはこの順序のときだけ
  got="$("${BINARY}" --version)" || die "取得したバイナリを起動できませんでした(対象: ${TARGET})"
  if [ -n "${EXPECTED_VERSION}" ] && [ "${got}" != "${EXPECTED_VERSION}" ]; then
    die "版が一致しません(期待 ${EXPECTED_VERSION} / 実際 ${got})。アセットの取り違えの可能性があります"
  fi
  INSTALLED_VERSION="${got}"
}

install_binary() {
  mkdir -p "${INSTALL_DIR}" || die "インストール先を作れません: ${INSTALL_DIR}"
  INSTALL_DIR="$(cd "${INSTALL_DIR}" && pwd)"
  [ -w "${INSTALL_DIR}" ] || die "書き込めません: ${INSTALL_DIR}(--dir で変更してください。この script は sudo を呼びません)"

  # 同一ディレクトリ内へ置いてから rename する: 途中状態の実行ファイルを
  # 見せず、実行中バイナリの上書き(ETXTBSY)も避ける
  PARTIAL_FILE="${INSTALL_DIR}/.maruhi.install.$$"
  cp "${BINARY}" "${PARTIAL_FILE}" || die "インストール先へコピーできません: ${INSTALL_DIR}"
  chmod 755 "${PARTIAL_FILE}"
  mv -f "${PARTIAL_FILE}" "${INSTALL_DIR}/maruhi" || die "設置に失敗しました: ${INSTALL_DIR}/maruhi"
  PARTIAL_FILE=""
}

link_alias() {
  local link current
  link="${INSTALL_DIR}/mh"
  if [ -L "${link}" ]; then
    current="$(readlink "${link}" 2>/dev/null || printf '')"
    case "${current}" in
      maruhi | "${INSTALL_DIR}/maruhi") ln -sf maruhi "${link}" ;;
      *)
        warn "${link} は maruhi 以外を指す symlink のため触りません(現在: ${current})"
        return 0
        ;;
    esac
  elif [ -e "${link}" ]; then
    warn "${link} が既にあります(symlink ではない)。mh エイリアスは作りません"
    return 0
  else
    # 相対 symlink にする(ディレクトリごと移動しても壊れない)
    ln -s maruhi "${link}" || die "mh の symlink を作れません: ${link}"
  fi
  MH_LINKED="1"
}

report() {
  local rc_hint path_line
  log "maruhi ${INSTALLED_VERSION} を ${INSTALL_DIR}/maruhi に入れました(${TARGET})"
  if [ "${MH_LINKED}" = "1" ]; then
    log "エイリアス: ${INSTALL_DIR}/mh -> maruhi"
  fi
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      # rc_hint は画面に出す案内文であって、この script が開くパスではない
      # (だから展開されない `~` のままでよい)
      # shellcheck disable=SC2088
      case "$(basename "${SHELL:-sh}")" in
        fish)
          rc_hint="~/.config/fish/config.fish"
          path_line="fish_add_path ${INSTALL_DIR}"
          ;;
        zsh)
          rc_hint="~/.zshrc"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
        bash)
          rc_hint="~/.bashrc"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
        *)
          rc_hint="シェルの設定ファイル"
          path_line="export PATH=\"${INSTALL_DIR}:\$PATH\""
          ;;
      esac
      log ""
      log "${INSTALL_DIR} は PATH にありません。次の行を ${rc_hint} に足してください:"
      log "  ${path_line}"
      log "(この script は設定ファイルを書き換えません)"
      ;;
  esac
  log ""
  log "次: maruhi --help"
}

main() {
  parse_args "$@"
  VERSION="${VERSION:-${MARUHI_VERSION:-}}"
  INSTALL_DIR="${INSTALL_DIR:-${MARUHI_INSTALL_DIR:-}}"
  BASE_URL="${MARUHI_BASE_URL:-}"

  if [ -z "${INSTALL_DIR}" ]; then
    [ -n "${HOME:-}" ] || die "HOME が未設定です。--dir でインストール先を指定してください"
    INSTALL_DIR="${HOME}/.local/bin"
  fi

  require_tools
  detect_target
  resolve_version
  resolve_base_url
  download_and_verify
  extract_and_check
  install_binary
  link_alias
  report
}

main "$@"
