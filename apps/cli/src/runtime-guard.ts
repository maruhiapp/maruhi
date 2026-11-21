if (typeof globalThis.Bun === "undefined") {
  console.error(
    "The maruhi CLI runs only on the Bun runtime (https://bun.sh). " +
      "Install Bun, or use a precompiled binary from GitHub Releases.",
  );
  process.exit(1);
}
