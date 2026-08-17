#!/usr/bin/env bash
# packaging/install.sh の実走テスト(正例 + 改竄の負例)。
#
#   bun run --filter @maruhi/cli build:binaries   # 先に成果物を作る
#   packaging/install-test.sh --dist apps/cli/dist --target linux-x64 --version 0.1.0-rc.1
#
# 実リリースには依存しない: install.sh の MARUHI_BASE_URL を使い、
# ローカルの成果物(build:binaries の出力)を http://127.0.0.1 と file:// の
# 両方から入れる。CI(.github/workflows/installer.yml)は release.yml の smoke と
# 同じ unix 4 対象の実 runner でこれを回す。
#
# 負例は「checksums.txt を 1 文字改竄」「アーカイブを 1 バイト改竄」「アセット
# 不在」「置き換え先が通常ファイルでない」「版の不一致」の 5 種。いずれも非 0 終了で、
# インストール先に部分ファイルを残さないことまで検査する(検証をすり抜けても
# 気づけない形を作らない)。
set -euo pipefail

DIST=""
TARGET=""
VERSION=""
PORT=""
SERVER_PID=""
WORK=""
FAILURES=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="${SCRIPT_DIR}/install.sh"

usage() {
  cat <<EOF
使い方: install-test.sh --dist <dir> --target <name> --version <x.y.z>

  --dist     maruhi-<target>.tar.gz と checksums.txt があるディレクトリ
  --target   検査する対象(例: linux-x64)。この runner で install.sh が
             検出する対象と一致している必要がある
  --version  期待する \`maruhi --version\` の出力(v なし)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)
      DIST="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "不明な引数: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n ${DIST} && -n ${TARGET} && -n ${VERSION} ]] || {
  usage >&2
  exit 2
}

DIST="$(cd "${DIST}" && pwd)"
ARCHIVE="maruhi-${TARGET}.tar.gz"
[[ -f "${DIST}/${ARCHIVE}" ]] || {
  echo "成果物がありません: ${DIST}/${ARCHIVE}" >&2
  exit 2
}
[[ -f "${DIST}/checksums.txt" ]] || {
  echo "成果物がありません: ${DIST}/checksums.txt" >&2
  exit 2
}
# ローカルの http fixture 用(install.sh 自体は curl / tar / sha256 系だけを要求する)
command -v python3 >/dev/null || {
  echo "python3 が必要です(ローカルの http fixture を立てるため)" >&2
  exit 2
}

cleanup() {
  if [[ -n ${SERVER_PID} ]]; then kill "${SERVER_PID}" 2>/dev/null || true; fi
  if [[ -n ${WORK} ]]; then rm -rf "${WORK}"; fi
}
trap cleanup EXIT

WORK="$(mktemp -d "${TMPDIR:-/tmp}/maruhi-install-test.XXXXXX")"
mkdir -p "${WORK}/serve"

# 素の成果物(正例)。以降のケースはこれを複製して改竄する
new_case() {
  local name="$1"
  local dir="${WORK}/serve/${name}"
  mkdir -p "${dir}"
  cp "${DIST}/${ARCHIVE}" "${DIST}/checksums.txt" "${dir}/"
  printf '%s' "${dir}"
}

start_server() {
  local log="${WORK}/server.log"
  # port 0 = OS 任せの空きポート(並列実行での衝突を作らない)。
  # `python3 -m http.server` の起動メッセージは解析しない — stdout がファイルへ
  # 向くとブロックバッファされ、文言も版で変わる(CI で実際に踏んだ)。
  # ポートは自分で取って flush して出す
  python3 -u -c '
import functools, http.server, socketserver, sys

handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
with socketserver.TCPServer(("127.0.0.1", 0), handler) as httpd:
    print(httpd.server_address[1], flush=True)
    httpd.serve_forever()
' "${WORK}/serve" >"${log}" 2>&1 &
  SERVER_PID=$!
  # 後始末の kill で bash が「Terminated」の非同期通知を出し、python プログラム
  # 全体がログ末尾に流れる(実 runner で確認)。ジョブ表から外して黙らせる
  disown "${SERVER_PID}" 2>/dev/null || true
  local i
  for ((i = 0; i < 100; i++)); do
    PORT="$(head -n 1 "${log}" 2>/dev/null || true)"
    if [[ ${PORT} =~ ^[0-9]+$ ]]; then return; fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then break; fi
    sleep 0.1
  done
  PORT=""
  cat "${log}" >&2
  echo "http サーバーを起動できません" >&2
  exit 2
}

pass() { echo "  ok: $1"; }
fail() {
  echo "  NG: $1" >&2
  FAILURES=$((FAILURES + 1))
}

# check <ラベル> <コマンド...>: コマンドの終了状態で ok / NG を数える。
# `A && pass || fail` 形は A が真でも pass が失敗すれば fail が走る形なので使わない
check() {
  local label="$1"
  shift
  if "$@"; then pass "${label}"; else fail "${label}"; fi
}

# インストール先に何も残っていないこと(部分ファイル・空でない中身を許さない)
assert_clean_dest() {
  local dest="$1" label="$2"
  if [[ ! -e ${dest} ]]; then
    pass "${label}: インストール先を作っていない"
    return
  fi
  local leftovers
  leftovers="$(ls -A "${dest}")"
  if [[ -z ${leftovers} ]]; then
    pass "${label}: インストール先が空のまま"
  else
    fail "${label}: 途中状態が残った: ${leftovers}"
  fi
}

run_install() {
  local base="$1" dest="$2"
  shift 2
  MARUHI_BASE_URL="${base}" sh "${INSTALL_SH}" --dir "${dest}" "$@" 2>&1
}

# ---- 正例 1: http 経由で入り、mh が同じバイナリを指す --------------------------
case_http_ok() {
  local dest out
  new_case http-ok >/dev/null
  dest="${WORK}/dest/http-ok"
  if ! out="$(run_install "http://127.0.0.1:${PORT}/http-ok" "${dest}" --version "${VERSION}")"; then
    fail "http 正例: 失敗した"
    echo "${out}" >&2
    return
  fi
  check "http 正例: maruhi を設置した" test -x "${dest}/maruhi"
  check "http 正例: --version が ${VERSION}" test "$("${dest}/maruhi" --version)" = "${VERSION}"
  check "http 正例: mh は maruhi への相対 symlink" test "$(readlink "${dest}/mh")" = "maruhi"
  check "http 正例: mh も起動する" test "$("${dest}/mh" --version)" = "${VERSION}"
}

# ---- 正例 2: file:// 経由(内部ミラー・ローカル成果物の経路)-------------------
case_file_ok() {
  local dir dest out
  dir="$(new_case file-ok)"
  dest="${WORK}/dest/file-ok"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "file 正例: 失敗した"
    echo "${out}" >&2
    return
  fi
  check "file 正例: maruhi を設置した" test -x "${dest}/maruhi"
  check "file 正例: mh も張られる" test "$(readlink "${dest}/mh")" = "maruhi"
}

# ---- 正例 3: 再インストール(冪等)+ 他人の mh を潰さない ----------------------
case_reinstall_and_foreign_mh() {
  local dir dest out
  dir="$(new_case reinstall)"
  dest="${WORK}/dest/reinstall"
  mkdir -p "${dest}"
  # 別ツールの mh を置いておく(symlink ではない実体)
  printf '#!/bin/sh\necho other\n' >"${dest}/mh"
  chmod 755 "${dest}/mh"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "再インストール: 失敗した"
    echo "${out}" >&2
    return
  fi
  check "再インストール: 他人の mh を残した" test "$("${dest}/mh")" = "other"
  check "再インストール: mh について警告した" grep -q "already exists (not a symlink)" <<<"${out}"
  # 2 回目(既存の maruhi を上書き)
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "再インストール: 2 回目が失敗した"
    echo "${out}" >&2
    return
  fi
  check "再インストール: 上書きできる" test "$("${dest}/maruhi" --version)" = "${VERSION}"
}

# ---- 正例 4: 既存の mh が「他人を指す symlink」なら張り替えない -----------------
# link_alias で `ln -sf` に到達しうる唯一の分岐。通常ファイルの分岐(正例 3)とは
# 別経路なので個別に踏む
case_foreign_mh_symlink() {
  local dir dest out
  dir="$(new_case foreign-mh-symlink)"
  dest="${WORK}/dest/foreign-mh-symlink"
  mkdir -p "${dest}"
  printf '#!/bin/sh\necho other\n' >"${dest}/other-tool"
  chmod 755 "${dest}/other-tool"
  ln -s other-tool "${dest}/mh"
  if ! out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "他人の mh symlink: 失敗した"
    echo "${out}" >&2
    return
  fi
  check "他人の mh symlink: 張り替えていない" test "$(readlink "${dest}/mh")" = "other-tool"
  check "他人の mh symlink: 警告した" grep -q "does not point to maruhi" <<<"${out}"
  check "他人の mh symlink: maruhi 自体は入る" test -x "${dest}/maruhi"
}

# ---- 負例 1: checksums.txt を 1 文字改竄(変異検証の本体)----------------------
case_tampered_checksums() {
  local dir dest out
  dir="$(new_case tampered-checksums)"
  # 自対象の行の hex 先頭 1 文字だけを別の hex 桁に差し替える。形式(64 桁 + 空白
  # 2 個)は保つ = 形式チェックではなく SHA-256 の比較そのものを踏ませる
  awk -v target="${ARCHIVE}" '
    $2 == target {
      first = substr($1, 1, 1)
      newfirst = (first == "0" ? "1" : "0")
      printf "%s%s  %s\n", newfirst, substr($1, 2), $2
      next
    }
    { print }
  ' "${DIST}/checksums.txt" >"${dir}/checksums.txt"
  if diff -q "${DIST}/checksums.txt" "${dir}/checksums.txt" >/dev/null; then
    fail "改竄 checksums: 改竄できていない(テスト自体の不備)"
    return
  fi
  if ! grep -qE "^[0-9a-f]{64}  ${ARCHIVE}\$" "${dir}/checksums.txt"; then
    fail "改竄 checksums: 形式が壊れた(SHA 比較を踏まないテストになる)"
    return
  fi
  dest="${WORK}/dest/tampered-checksums"
  if out="$(run_install "http://127.0.0.1:${PORT}/tampered-checksums" "${dest}" --version "${VERSION}")"; then
    fail "改竄 checksums: インストールが成功してしまった"
    echo "${out}" >&2
    return
  fi
  pass "改竄 checksums: 非 0 で終了した"
  check "改竄 checksums: 検証失敗として報告した" grep -q "SHA-256" <<<"${out}"
  assert_clean_dest "${dest}" "改竄 checksums"
}

# ---- 負例 2: アーカイブを 1 バイト改竄 ----------------------------------------
case_tampered_archive() {
  local dest out
  local dir
  dir="$(new_case tampered-archive)"
  printf 'X' | dd of="${dir}/${ARCHIVE}" bs=1 seek=1024 conv=notrunc 2>/dev/null
  if cmp -s "${DIST}/${ARCHIVE}" "${dir}/${ARCHIVE}"; then
    fail "改竄アーカイブ: 改竄できていない(テスト自体の不備)"
    return
  fi
  dest="${WORK}/dest/tampered-archive"
  if out="$(run_install "http://127.0.0.1:${PORT}/tampered-archive" "${dest}" --version "${VERSION}")"; then
    fail "改竄アーカイブ: インストールが成功してしまった"
    echo "${out}" >&2
    return
  fi
  pass "改竄アーカイブ: 非 0 で終了した"
  check "改竄アーカイブ: 検証失敗として報告した" grep -q "SHA-256" <<<"${out}"
  assert_clean_dest "${dest}" "改竄アーカイブ"
}

# ---- 負例 3: アセット不在(404)-----------------------------------------------
case_missing_asset() {
  local dir dest out
  dir="$(new_case missing-asset)"
  rm -f "${dir}/${ARCHIVE}"
  dest="${WORK}/dest/missing-asset"
  if out="$(run_install "http://127.0.0.1:${PORT}/missing-asset" "${dest}" --version "${VERSION}")"; then
    fail "アセット不在: インストールが成功してしまった"
    echo "${out}" >&2
    return
  fi
  pass "アセット不在: 非 0 で終了した"
  check "アセット不在: 取得失敗として報告した" grep -q "download failed" <<<"${out}"
  assert_clean_dest "${dest}" "アセット不在"
}

# ---- 負例 4: 置き換え先が通常ファイルでない(mv が中へ潜り込む形を塞ぐ)--------
case_dest_not_a_file() {
  local dir dest out
  dir="$(new_case dest-not-a-file)"
  dest="${WORK}/dest/dest-not-a-file"
  mkdir -p "${dest}/maruhi"
  if out="$(run_install "file://${dir}" "${dest}" --version "${VERSION}")"; then
    fail "置き換え先が非ファイル: インストールが成功してしまった"
    echo "${out}" >&2
    return
  fi
  pass "置き換え先が非ファイル: 非 0 で終了した"
  check "置き換え先が非ファイル: 理由を報告した" grep -q "is not a regular file" <<<"${out}"
  check "置き換え先が非ファイル: 中へ潜り込んでいない" test -z "$(ls -A "${dest}/maruhi")"
}

# ---- 負例 5: 版の不一致(アセット取り違えの検出)-------------------------------
case_version_mismatch() {
  local dir dest out
  dir="$(new_case version-mismatch)"
  dest="${WORK}/dest/version-mismatch"
  if out="$(run_install "file://${dir}" "${dest}" --version "99.99.99")"; then
    fail "版の不一致: インストールが成功してしまった"
    echo "${out}" >&2
    return
  fi
  pass "版の不一致: 非 0 で終了した"
  check "版の不一致: 版の不一致として報告した" grep -q "version mismatch" <<<"${out}"
  assert_clean_dest "${dest}" "版の不一致"
}

echo "install.sh 実走テスト(target=${TARGET} version=${VERSION})"
start_server
echo "http fixture: http://127.0.0.1:${PORT}/"

case_http_ok
case_file_ok
case_reinstall_and_foreign_mh
case_foreign_mh_symlink
case_tampered_checksums
case_tampered_archive
case_missing_asset
case_dest_not_a_file
case_version_mismatch

if [[ ${FAILURES} -gt 0 ]]; then
  echo "失敗: ${FAILURES} 件" >&2
  exit 1
fi
echo "すべて通過"
