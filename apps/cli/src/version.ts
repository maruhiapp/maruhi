// Single source of the version = apps/cli/package.json. At release time the
// release workflow checks that it matches the tag (docs/RELEASING.md).
//
// **named import is required**: switching to a default import embeds the
// entire manifest (scripts, dependency pins) into the npm distribution and
// every binary (observed; npm-dist.test.ts pins this on the artifact side).
// Confining the import to this one module keeps the blast radius of a
// dangerous rewrite in a single place.

import { version } from "../package.json";

/** The CLI version reported by `maruhi --version`. */
export const CLI_VERSION: string = version;
