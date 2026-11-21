import { cfD1Binding } from "./cf-config.ts";

const mode = process.argv[2];
console.log(cfD1Binding(mode, "d1-id").id);
