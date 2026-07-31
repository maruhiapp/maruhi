import { describe, expect, it } from "vitest";

import { PACKAGE_NAME } from "../src/index.ts";

describe("@maruhi/cli placeholder", () => {
  it("exports the package name", () => {
    expect(PACKAGE_NAME).toBe("@maruhi/cli");
  });
});
