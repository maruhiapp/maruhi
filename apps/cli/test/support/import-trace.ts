// A preload for test/startup-loads.test.ts: for every import of a file path
// that Bun resolves from a CLI source file (apps/cli/src), static or
// dynamic, it appends a line "<importer>\t<specifier>" to the file
// IMPORT_TRACE names. It only watches: the resolution is left to Bun. Bun
// does not ask a runtime plugin about package or node: specifiers, and it
// erases type-only imports before resolving, so neither shows up.

import { appendFileSync } from "node:fs";

const trace = process.env["IMPORT_TRACE"];
if (trace === undefined || trace === "") {
  throw new Error("IMPORT_TRACE must name the file the trace is appended to");
}

const CLI_SOURCE = /[\\/]apps[\\/]cli[\\/]src[\\/]/;

Bun.plugin({
  name: "import-trace",
  setup(build) {
    build.onResolve({ filter: /.*/ }, ({ importer, path }) => {
      if (CLI_SOURCE.test(importer)) {
        appendFileSync(trace, `${importer}\t${path}\n`);
      }
    });
  },
});
