# AGENTS

Project-specific guidance for AI coding agents.

**maruhi-specific overrides (root `CLAUDE.md` "Web UI (Astryx) styling discipline" is the source of truth)**:

- **`astryx swizzle` is forbidden in maruhi**, although the CLI still offers it (`astryx help`) and the generated block below no longer lists it. Not just the command — copying Astryx's internal implementation source into the repository by any means is forbidden (reading it is allowed for learning only). Upstream bugs are handled with exact pins and by "sending back the upgrade PR"
- Order of consideration for customization: ① defineTheme in `apps/web/theme/` (including adding variants) → ② xstyle → ③ a composed wrapper in `ui.package` → ④ a new bespoke component in `ui.package` (Astryx public APIs only) → ⑤ an issue / PR to upstream (facebook/astryx)

<!-- ASTRYX:START -->
Astryx v0.7.3 · 173 components
CLI: run every command as `bunx astryx <cmd>` (shown below as `astryx ...`).

SETUP (once, in app entry e.g. main.tsx) — without these, components render unstyled:
  import "@astryxdesign/core/reset.css";
  import "@astryxdesign/core/astryx.css";

WORKFLOW — start every page from a template, never from scratch:
1. `astryx build "<idea>"` — names the template to scaffold from and the parts it lacks.
2. `astryx template <name> <path>` — scaffold it; keep its frame, gap and padding; replace the content.
3. `astryx template <Block>` for parts it lacks; `astryx component <Name>` to read props before using one.
Changing an existing page? Keep it: skip step 2 and add blocks/components inside its sections.

RULES:
- No <div> — components handle all layout and spacing.
- Read `astryx docs layout` before changing a template's frame.
- Dense data = rows (Table, List/Item), not Card-wrapped lists. Badge = counts only.
- Style with component props first, then the xstyle prop / StyleX tokens. No raw hex/px.
- Palettes and custom colors go through the theme, never :root overrides. Run `astryx theme add <slug>` to import; `theme eject <slug>` only forks source. See `astryx docs theme`.
- SELF-CHECK: re-read the file; replace any className=, style={{…}}, raw <div>/<span>, imported .css/@apply, or hardcoded #hex/px with the component or the xstyle prop + a token.

`astryx help` lists every command. Key ones beyond the workflow:
  search "<query>"   find any component / hook / doc / template
  discover <words>   integrations you could add
  docs <topic>       getting-started, principles, tokens, theme … (`astryx docs` lists all)
  docs cli           commands and API reference
  docs authoring     build an integration package, and every field it holds
  upgrade --from <old version> --apply   run after a dependency bump
<!-- ASTRYX:END -->
