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

  it("IPv4 埋め込み末尾(::ffff:1.2.3.4)も展開して数える", () => {
    expect(rateLimitKeyOf("::ffff:192.0.2.1")).toBe("0:0:0:0::/64");
    expect(rateLimitKeyOf("64:ff9b:1:2::192.0.2.1")).toBe("64:ff9b:1:2::/64");
  });

  it("パース不能な値は素の文字列キーへフォールバックする(アドレス単位の制限は残る)", () => {
    expect(rateLimitKeyOf("not:an:ip:::")).toBe("not:an:ip:::");
    expect(rateLimitKeyOf("2001:db8:1:2:3:4:5:6:7:8")).toBe("2001:db8:1:2:3:4:5:6:7:8");
  });
});
