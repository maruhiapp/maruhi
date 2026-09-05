// live.ts の対話入力プリミティブの単体テスト(レビュー修正の回帰防止)。
//
// - makeStdinLineReader: 複数プロンプトにまたがる未消費行の保持(readline を
//   都度閉じる形は次行を捨てていた)、CRLF、改行なし終端、EOF
// - readHiddenLine: raw mode 入力の終端処理(end/error でハングしない)、
//   Ctrl+D 中断、エスケープ列(矢印キー)と制御文字の無視、Backspace
//
// PassThrough に TTY のスタブ(setRawMode / isRaw)を足して駆動する。

import { spawnSync } from "node:child_process";
import { closeSync, openSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";

import { describe, expect, it } from "vitest";

import { makeStdinLineReader, readHiddenLine, writeLine } from "../src/live.ts";

/** raw mode スタブ付きの擬似 stdin。 */
function fakeTty(): PassThrough & { isRaw: boolean; setRawMode: (raw: boolean) => void } {
  const stream = new PassThrough();
  return Object.assign(stream, {
    isRaw: false,
    setRawMode(raw: boolean) {
      this.isRaw = raw;
      return this;
    },
  });
}

function asStdin(stream: PassThrough): NodeJS.ReadStream {
  return stream as unknown as NodeJS.ReadStream;
}

describe("makeStdinLineReader(非 TTY の共有行リーダー)", () => {
  it("1 チャンクに複数行が来ても、後続のプロンプトが残りの行を受け取れる", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.write("WRONG\nAAAA-BBBB\n");
    // 1 回目のプロンプトが 1 行目、2 回目(再試行)が 2 行目を得る
    expect(await readLine()).toBe("WRONG");
    expect(await readLine()).toBe("AAAA-BBBB");
  });

  it("CRLF の行末を落とし、改行なしで終端した最終行も返す", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.write("first\r\nlast-without-newline");
    stream.end();
    expect(await readLine()).toBe("first");
    expect(await readLine()).toBe("last-without-newline");
    await expect(readLine()).rejects.toThrow("eof");
  });

  it("入力が空のまま終端したら eof で失敗する(ハングしない)", async () => {
    const stream = new PassThrough();
    const readLine = makeStdinLineReader(asStdin(stream));
    stream.end();
    await expect(readLine()).rejects.toThrow("eof");
  });
});

describe("readHiddenLine(raw mode の非エコー入力)", () => {
  it("Backspace は末尾を消し、Enter で確定する", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    tty.write("ABCX\u007fD\r");
    expect(await pending).toBe("ABCD");
    // raw mode は復元される
    expect(tty.isRaw).toBe(false);
  });

  it("矢印キー等のエスケープ列とタブは入力に混ざらない(見えない破損の防止)", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    // 左矢印(ESC [ D)とタブを挟んでも、印字可能文字だけが残る
    tty.write("AB\u001b[D\tCD\n");
    expect(await pending).toBe("ABCD");
  });

  it("Ctrl+C / Ctrl+D は中断として扱う", async () => {
    const byCtrlC = fakeTty();
    const pendingC = readHiddenLine(asStdin(byCtrlC));
    byCtrlC.write("AB\u0003");
    await expect(pendingC).rejects.toThrow("interrupted");

    const byCtrlD = fakeTty();
    const pendingD = readHiddenLine(asStdin(byCtrlD));
    byCtrlD.write("AB\u0004");
    await expect(pendingD).rejects.toThrow("interrupted");
  });

  it("入力途中でストリームが終端してもハングせず eof で失敗する", async () => {
    const tty = fakeTty();
    const pending = readHiddenLine(asStdin(tty));
    tty.write("AB");
    tty.end();
    await expect(pending).rejects.toThrow("eof");
  });
});

describe("writeLine(同期書き込みと閉じたパイプ)", () => {
  it("1 行 + 改行を fd へ書き切る(ファイル)", () => {
    const path = join(tmpdir(), `maruhi-writeline-${process.pid}.txt`);
    const fd = openSync(path, "w");
    try {
      writeLine(fd, "first");
      writeLine(fd, "second");
    } finally {
      closeSync(fd);
    }
    expect(readFileSync(path, "utf8")).toBe("first\nsecond\n");
  });

  it("読み手が先に閉じたパイプへの書き込み(EPIPE)は defect にせず、プロセスは 0 で終わる", () => {
    // `maruhi … | head -1` の形。writeSync は 2 行目以降で EPIPE を投げるが、
    // console.log と同じく黙って捨てる(PR #151 Bugbot 指摘)。実プロセスで検査する:
    // 書き手を bun で走らせ、読み手 head が 1 行で閉じた後の終了コードを見る
    const script =
      'import { writeLine } from "./apps/cli/src/live.ts"; for (let i = 0; i < 200000; i += 1) writeLine(1, `line${i}`); process.exit(0);';
    const result = spawnSync(
      "bash",
      ["-c", `bun -e '${script}' | head -1; echo "writer-exit=\${PIPESTATUS[0]}"`],
      { cwd: new URL("../../..", import.meta.url).pathname, encoding: "utf8" },
    );
    // 失敗時に原因(bun の不在・スクリプトの構文)が読めるよう stderr を添える
    // (bash 側の終了コードは末尾の echo で常に 0 なので、断言は書き手の
    // 終了コード = writer-exit と 1 行目の到達で行う)
    expect(result.stdout, result.stderr).toContain("line0");
    expect(result.stdout, result.stderr).toContain("writer-exit=0");
    expect(result.stderr).not.toContain("EPIPE");
  });
});
