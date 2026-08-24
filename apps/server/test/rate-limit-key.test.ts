// レート制限キーの正規化(worker-env.ts — レビューループ 5)のユニットテスト。
// IPv6 の /64 集約が要点: 標準割当 /64 内の下位 bit ローテーションで毎リクエストが
// 新規キーになると、M3/B11/M5 の窓が一切効かなくなる。

import { describe, expect, it } from "vitest";

import { rateLimitKeyOf } from "../src/worker-env.ts";

describe("rateLimitKeyOf(発信元 IP → 制限キー)", () => {
  it("IPv4 はそのまま", () => {
    expect(rateLimitKeyOf("203.0.113.7")).toBe("203.0.113.7");
  });

  it("IPv6 は /64 プレフィックスへ丸める(下位 64 bit のローテーションが同一キーに畳まれる)", () => {
    expect(rateLimitKeyOf("2001:db8:1:2:3:4:5:6")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKeyOf("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    // 圧縮形も同じプレフィックスへ正規化される
    expect(rateLimitKeyOf("2001:db8:1:2::9")).toBe("2001:db8:1:2::/64");
    expect(rateLimitKeyOf("2001:DB8:0001:2::9")).toBe("2001:db8:1:2::/64");
    // 先頭圧縮・全圧縮
    expect(rateLimitKeyOf("::1")).toBe("0:0:0:0::/64");
    expect(rateLimitKeyOf("fe80::")).toBe("fe80:0:0:0::/64");
  });

  it("IPv4-mapped(::ffff:a.b.c.d)は埋め込み IPv4 をキーにする(共有バケットへ畳まない)", () => {
    expect(rateLimitKeyOf("::ffff:192.0.2.1")).toBe("192.0.2.1");
    expect(rateLimitKeyOf("::ffff:c000:201")).toBe("192.0.2.1");
    // v4-mapped 以外の IPv4 埋め込み(NAT64 等)は通常の /64 集約
    expect(rateLimitKeyOf("64:ff9b:1:2::192.0.2.1")).toBe("64:ff9b:1:2::/64");
  });

  it("パース不能な値は素の文字列キーへフォールバックする(アドレス単位の制限は残る)", () => {
    expect(rateLimitKeyOf("not:an:ip:::")).toBe("not:an:ip:::");
    expect(rateLimitKeyOf("2001:db8:1:2:3:4:5:6:7:8")).toBe("2001:db8:1:2:3:4:5:6:7:8");
  });

  it("埋め込み IPv4 の octet は厳密な 10 進のみ(deepsec R9)", () => {
    // Number() の強制変換で通っていた形。素の文字列キーへ落ちる(= 別バケット
    // に化けたり、不正表記が正当なアドレスとして畳まれたりしない)
    for (const malformed of [
      "::ffff:0x1.2.3.4",
      "::ffff:1.2.3.",
      "::ffff:1.2.3.4.5",
      "::ffff:1e2.2.3.4",
      "::ffff:1.2.3. 4",
      "::ffff:01.2.3.4",
      "::ffff:1.2.3.256",
      "::ffff:1.2.3.-1",
    ]) {
      expect(rateLimitKeyOf(malformed)).toBe(malformed);
    }
    // 正当な形は従来どおり畳まれる(0 と 255 の境界を含む)
    expect(rateLimitKeyOf("::ffff:0.0.0.0")).toBe("0.0.0.0");
    expect(rateLimitKeyOf("::ffff:255.255.255.255")).toBe("255.255.255.255");
  });

  it("IPv4 埋め込みはアドレス末尾のピースだけ(RFC 4291 §2.2 (3))", () => {
    expect(rateLimitKeyOf("::ffff:1.2.3.4:0")).toBe("::ffff:1.2.3.4:0");
    expect(rateLimitKeyOf("1.2.3.4::")).toBe("1.2.3.4::");
    // 非圧縮形の末尾に置くのは正当(6 グループ + IPv4 = 8 グループ)
    expect(rateLimitKeyOf("2001:db8:1:2:0:0:192.0.2.1")).toBe("2001:db8:1:2::/64");
  });
});
