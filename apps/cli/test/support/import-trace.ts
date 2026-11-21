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
