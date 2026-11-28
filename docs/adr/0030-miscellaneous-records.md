# ADR-0030: Miscellaneous decision records relocated from code comments

Status: 2026-11-21. Accepted on merge of the PR that adds this ADR.

**Context**: The 2026-11-21 comment audit (ADR-0020) classified every code comment in the repository. 321 comments on areas without a single dominant theme were Decision Records: they documented non-obvious decisions — rationale, rejected alternatives, invariants, external constraints, security judgments — that cannot be derived from the code itself. Under ADR-0020 those records move out of code comments into ADRs; this ADR is their new home. Each entry below is the audit's one-line distillation of the original comment. Line numbers refer to the tree at the audit base commit `0f036bef`, so the original comment text remains recoverable from git history at the cited location. Where a decision is also recorded in an earlier ADR or in a spec (CRYPTO_SPEC, AUTH_SPEC, AUDIT_SPEC), that record remains authoritative and the entry here is the code-site index into it.

**Decision**: The decision records for this area are the entries in the list below, grouped by the file whose comment carried them. They bind the same way the comments did: changing the behavior they describe means revising this ADR (or the spec or ADR they point to), not silently editing the code.

### `apps/cli/src/approval.package/command.ts`

- L334: An exhaustive Record narrows the argument type per kind via Extract, but the shared call site holds the wide type, hence the cast.

### `apps/cli/src/invite.package/index.ts`

- L1: invite.package's index exposes only what other files import; invite-link.ts stays at the src root because routing it through this index would close an import cycle via pins.ts/invite.ts.

### `apps/cli/src/key.package/index.ts`

- L1: key.package's index exposes only what other files import; key-record/reserve/recovery files stay at the src root because routing them through this index would load keygen.ts and key-publish.ts into guardian add and device add.

### `apps/cli/src/member.package/index.ts`

- L1: member.package's index exposes only what other files import; member-list.ts stays at the src root because project list uses it on the startup path, where this index would also load member-add.ts and with it chain-sync.ts.

### `apps/cli/src/passkey.package/index.ts`

- L1: passkey.package's index is the package's public surface; there is no command.ts here — the passkey subcommands live inside key.package/command.ts, which imports this index like any other outside file.

### `apps/cli/src/project.package/command.ts`

- L525: The environment-floor handle is resolved ahead of the command body to keep issueCheckpoint's environment requirement at CliIo.

### `apps/cli/src/project.package/index.ts`

- L1: project.package's index exposes only what other files import; the command pieces live in command.ts per the package-entry convention.

### `apps/cli/src/project.package/project-init.ts`

- L34: The org-selection pure function returns a tagged Result — no instanceof discrimination, for uniformity of idiom.

### `apps/cli/src/push.package/index.ts`

- L1: push.package's index exposes only what other files import; the command pieces live in command.ts per the package-entry convention.

### `apps/cli/src/server.package/index.ts`

- L1: server.package's index exposes only what other files import; server-disclosure.ts stays at the src root because project.package/command.ts imports it on the startup path, where this index would also load server-grant.ts and with it chain-sync.ts.

### `apps/cli/src/sigv4.ts`

- L1: AWS Signature Version 4 (SigV4) over WebCrypto — the request signer of the `aws-iam-access-key` rotation connector (PF6
- L53: The static credential a request is signed with (an STS session carries a token).
- L62: The absolute URL (the path is signed as given; the query is canonicalized).
- L66: Request headers to sign (`host` is derived from the URL; `x-amz-date` is added). Names are lower-cased.
- L74: The headers to send: the input headers plus `host`, `x-amz-date`, `authorization` (and `x-amz-security-token`).
- L76: Exposed for the test vector of the AWS documentation.
- L82: RFC 3986 unreserved set — what SigV4's URI encoding leaves alone.
- L101: Derives the signing key: HMAC chain over the date, region, service, and the terminator.

### `apps/cli/src/var.package/index.ts`

- L1: var.package's index exposes only what other files import; the command pieces live in command.ts per the package-entry convention.

### `apps/cli/src/version.ts`

- L1: Single source of the version = apps/cli/package.json. At release time the release workflow checks that it matches the tag

### `apps/server/src/crypto-catch.ts`

- L1: Exhaustive handling of a crypto call's typed error channel (`WrappedCryptoError`, the @maruhi/core bridge).
- L14: One entry per `WrappedCryptoError` kind.
- L27: Handles every `WrappedCryptoError` kind of `self` through `cases`.
- L40: `cases` pairs each tag with a handler for that tag's member, and `error["_tag"]` selected the entry, so the argument matches it (the…

### `apps/server/src/ids.ts`

- L1: Generation and comparison of identifiers and credential randomness (Web-standard crypto only; no Bun-specific APIs).
- L26: ULID is @maruhi/core's shared implementation (the same one used for the CLI's ledger id assignment)
- L29: A fresh internal user id (AUTH_SPEC §2 — a ULID).
- L36: A fresh organization id (AUTH_SPEC §9 — a ULID).
- L45: Base62 representation of a 256-bit nonce (43 chars fixed, the AUTH_SPEC §6 token body).
- L64: A random hex string (`byteLength` bytes).
- L72: The synchronous counterpart of `randomHex`, for the call sites that cannot run an Effect (see the file header).
- L80: SHA-256 in hex (lowercase). The storage hash for sessions / tokens (AUTH_SPEC §5 / §6).
- L88: Timing-safe comparison of two hex strings (AUTH_SPEC §6).

### `apps/site/astro.config.ts`

- L31: Docs index leads the sidebar; every other page joins it in sidebar.order frontmatter order.

### `apps/site/scripts/postbuild.ts`

- L87: A declaration list maps to a class name by hash; a hash collision fails the build, and an empty style attribute is undefined.

### `apps/site/scripts/theme.ts`

- L154: brand.css is imported after Nimbus globals.css so its --nb-* definitions win and Tailwind's @theme mapping picks them up; fonts stay self-hosted.
- L221: Dark logo derivation fails when no fill matches the light accent, because that means the DP1 ruling-A premise (SVG red = light accent) broke.

### `apps/site/src/components.ts`

- L1: MDX globals registry: components usable in MDX without import, wired via <Content components={components} /> in [...slug].astro.

### `apps/site/src/components/AgentDirective.astro`

- L3: Page-markdown URL prop is null when the page has no per-page Markdown; the directive then points at the index only.
- L7: llms.txt index URL prop is null when no route of the site serves one.

### `apps/site/src/components/Header.astro`

- L18: hasSidebar=false hides the mobile menu button: a page that opted out of the sidebar shouldn't show a button that opens an empty dialog.
- L27: entryId stays in Props as a forward-compat hook for the version-switcher recipe but is intentionally not destructured, to avoid an unused-var warning.
- L36: An API reference beside the docs is not in the docs sidebar, so the docs and each reference become the header tabs; a root-served reference is the site.
- L41: The current reference is determined by the longest mount that equals the path or is a folder of it.

### `apps/site/src/components/Logo.astro`

- L2: Header logo: light uses /logo.svg, dark uses the generated /logo-dark.svg whose fill build-theme.ts swapped to the dark accent.

### `apps/site/src/components/Render.astro`

- L2: Render includes MDX partials from src/content/partials; params are declared in partial frontmatter and passed as props.
- L77: Levenshtein distance is inlined to keep the Render component dependency-free.

### `apps/site/src/components/logo.ts`

- L1: Social-card glyph is taken from apps/web/public/logo.svg; the card draws the circle itself in the accent colour, unlike the header's full logo files.
- L9: The glyph drawing's box: callers size it by height and keep the ratio.

### `apps/site/src/components/ui/aside/Aside.astro`

- L2: Aside callout: each type's colour comes from CSS keyed on data-type; a rich title can be passed via the title slot.
- L16: The prop is named type, not variant, to match the conventional <Aside type=...> authoring API.
- L70: Aside CSS variables: --_c tints the border and inline code, --_f is for text; icon and title take the type's text colour while body text stays readable.
- L80: Aside inline-code styling excludes code inside Expressive Code pre blocks.

### `apps/site/src/components/ui/badge/Badge.astro`

- L6: Badge text prop: when omitted, slotted children render instead.

### `apps/site/src/components/ui/banner/Banner.astro`

- L2: Banner: passing dismissible {id, days?} shows a close button whose dismissal persists to localStorage.

### `apps/site/src/components/ui/banner/banner.client.ts`

- L1: Dismissal storage key is nb-banner-dismissed-{id}; value "0" means permanent, otherwise a future ms timestamp for time-limited dismissal.

### `apps/site/src/components/ui/breadcrumbs/Breadcrumbs.astro`

- L11: The final crumb renders as non-interactive text by default; when false, every crumb with an href is a link and a single-crumb trail still renders.

### `apps/site/src/components/ui/button/Button.astro`

- L2: Button is the primary action trigger, with primary/secondary/ghost/outline variants, icon and loading states (usage examples in the header).

### `apps/site/src/components/ui/button/variants.ts`

- L1: Button styling is a single source of truth shared by Button and LinkButton so the two stay visually identical.
- L22: rounded-lg is every button's default radius; circle overrides it to rounded-full, square keeps rounded-lg.

### `apps/site/src/components/ui/card/Card.astro`

- L2: Card is a titled panel with an optional icon; with href, the whole card becomes the link.
- L27: A linked card's title is not a heading: the card is named by its link, and a row of cards under the page title would otherwise skip a heading level.

### `apps/site/src/components/ui/dialog/Dialog.astro`

- L2: Dialog is a modal overlay on the native <dialog>: open with showModal(), close with close() or Escape; scroll-lock and backdrop-click are handled automatically.
- L20: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/dialog/DialogClose.astro`

- L11: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/dialog/DialogContent.astro`

- L11: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/dialog/dialog.client.ts`

- L11: Backdrop click closes only when the press also started on the backdrop, so a text selection dragged out of the dialog does not close it.
- L28: A view-transition swap while open never fires close, so the scroll lock must be balanced manually.

### `apps/site/src/components/ui/image-zoom/ImageZoom.astro`

- L2: ImageZoom is one native <dialog> per docs layout showing a content image full-size; an image opts out with data-nb-zoom="off".

### `apps/site/src/components/ui/image-zoom/image-zoom.client.ts`

- L1: Wraps each content image that would get meaningfully bigger in a button opening the zoom dialog; re-evaluates on load, DOM appearance and viewport change.
- L7: Below the minimum size gain, zooming is not worth a button: a phone screenshot already fills the column.
- L22: Zoom size uses the max of the width attribute and naturalWidth because the file's own size can exceed the attribute.
- L45: All measuring happens before all DOM changes so layout runs once.
- L67: The zoom dialog clones the <picture> element when present, sized for the viewport, so the browser picks the largest fitting source.
- L117: The scroll lock is released immediately on swap because the dialog's close event fires only after the page has gone.

### `apps/site/src/components/ui/layer-card/LayerCard.astro`

- L2: LayerCard is a two-layer card (recessed header + raised content); orientation="horizontal" puts the header beside the content.
- L21: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/layer-card/LayerCardContent.astro`

- L8: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/layer-card/LayerCardHeader.astro`

- L8: A composing component can pass its own data-slot in place of this component's default.

### `apps/site/src/components/ui/link-button/LinkButton.astro`

- L2: LinkButton is an anchor styled as a button, sharing Button's variant vocabulary.

### `apps/site/src/components/ui/package-managers/PackageManagers.astro`

- L2: PackageManagers shows a tab per package manager; selection syncs across instances via sessionStorage and is restored pre-paint by an inline custom element.
- L20: Block ids use a prop hash plus a per-page counter on Astro.locals: counter order is stable within a render, so warm builds match cold, unlike crypto.randomUUID().

### `apps/site/src/components/ui/package-managers/package-managers.client.ts`

- L1: Sync key ui-pm-tab (sessionStorage) is shared with the <nb-pm-restore> early-paint element to avoid flash across navigations.

### `apps/site/src/components/ui/page-actions/PageActions.astro`

- L20: Extra actions render after the built-in ones, in this component, so an action that renders nothing adds no separator.

### `apps/site/src/components/ui/page-actions/page-actions.client.ts`

- L41: The clipboard gets a pending ClipboardItem inside the click because Safari refuses a write that starts after the fetch resolves.

### `apps/site/src/components/ui/pagination/Pagination.astro`

- L2: Pagination renders prev/next links as one surface with a sliding highlight; the [ and ] keys move between pages.
- L26: A prevNext-built bar answers its keys page-wide while single-key shortcuts are on; a composed bar only while focus is in it; false turns a bar's keys off.

### `apps/site/src/components/ui/pagination/PaginationKey.astro`

- L2: PaginationKey is the key cap that moves to this page; it is hidden on touch screens and when the bar sets keys={false}.

### `apps/site/src/components/ui/pagination/pagination.client.ts`

- L3: The next page is warmed on keydown via a plain prefetch link, so sites that turn off Astro's prefetch still build.
- L65: Prev/next keys answer page-wide only while single-key shortcuts are on and the page offers the WCAG 2.1.4 opt-out switch; otherwise only while focus is in the bar.

### `apps/site/src/components/ui/search/SearchDialog.astro`

- L36: The results list is hidden while it has no options: an empty listbox is invalid.

### `apps/site/src/components/ui/search/SearchTrigger.astro`

- L7: The trigger renders the non-macOS shortcut; the client swaps in the Cmd glyph on macOS and names the key in aria-keyshortcuts.

### `apps/site/src/components/ui/search/providers/pagefind.ts`

- L34: Search excludes deprecated versions when the site has any; layouts mark deprecated-version pages with data-pagefind-filter="status:deprecated".
- L43: Search filters are read from the current page on every search because the module outlives client-side navigation; a deprecated version's page searches that version.
- L71: Index result URLs already carry their slice prefix; only the base is needed, which Pagefind itself adds to each result.
- L76: A multi-collection slice writes one bundle; the other collections' bundle URLs 404 and are skipped during merge.

### `apps/site/src/components/ui/search/search.client.ts`

- L62: A result's link is reached with the arrow keys through its option, never with Tab: Tab leaves the listbox.
- L203: Home/End are intercepted only while a search option is active; otherwise they keep their caret-movement meaning.
- L239: search.client is imported for side effects by SearchDialog.astro; it wires dialogs via mount() and binds the global open shortcut once.
- L253: Global shortcut/trigger binding uses a module-scoped guard, not an <html> attribute, because ClientRouter resets <html> on swap but keeps document listeners.
- L280: Per-element search wiring moved to mount(): idempotent discovery on page-load, teardown on before-swap; data-search-ready is now only the wired marker.

### `apps/site/src/components/ui/shortcuts/ShortcutsToggle.astro`

- L2: ShortcutsToggle lets readers turn single-key shortcuts off, as WCAG 2.1.4 requires of page-wide single keys; it renders nothing when no single-key shortcut exists.

### `apps/site/src/components/ui/sidebar/Sidebar.astro`

- L2: Sidebar renders a recursive navigation tree from SidebarItem[]; persist opts into sessionStorage for open/scroll state, desktop only.

### `apps/site/src/components/ui/sidebar/SidebarGroup.astro`

- L2: SidebarGroup is a native <details>: opening and closing needs no script, and links in closed groups stay in the HTML.

### `apps/site/src/components/ui/sidebar/SidebarLink.astro`

- L2: SidebarLink rows carry no class or data attributes because large sidebars repeat them thousands of times; the sidebar styles li > a by position instead.

### `apps/site/src/components/ui/sidebar/sidebar.client.ts`

- L1: Sidebar runtime uses native <details>: open state is the element's own property and toggle events are captured on the root (toggle does not bubble); no click simulation.
- L46: SidebarFilter is rendered next to Sidebar (a sibling), so the lookup also checks the parent, preserving the layout where the filter sits above.
- L163: A hidden tree reads scrollTop 0, so the last visible scroll position is kept instead of overwriting saved state.
- L204: toggle does not bubble, so group changes are captured on the root; filter-opened groups are transient and never saved.
- L246: One sidebar tree per page now; the filter input travels between rail and drawer, so the first visible input is the target.

### `apps/site/src/components/ui/steps/Step.astro`

- L2: Step is a single step inside <Steps>, an alternative to authoring an <ol><li> directly.

### `apps/site/src/components/ui/steps/Steps.astro`

- L2: Steps wraps a markdown ordered list or only <Step> children; intro text goes before <Steps>, and start offsets the counter.
- L16: <Step> children are given their list on the server; content before the first Step (an introduction) stays outside the list.
- L23: Without the start prop, a Markdown list's own start attribute (e.g. `3.`) sets the counter.

### `apps/site/src/components/ui/steps/steps.client.ts`

- L1: Safari strips list semantics when list-style: none is applied; restoring role="list" on the inner <ol> makes VoiceOver announce the item count again.

### `apps/site/src/components/ui/switch/Switch.astro`

- L2: Switch is a role="switch" button whose aria-checked holds the state; a click flips it and fires a bubbling change event, and state owners can set aria-checked themselves.

### `apps/site/src/components/ui/tabs/TabItem.astro`

- L2: TabItem's label prop is read by tabs.client.ts to synthesize the matching trigger button; each TabItem becomes one [data-nb-tabs-content] panel.

### `apps/site/src/components/ui/tabs/Tabs.astro`

- L2: Tabs: syncKey syncs selection across instances; manual control is available via TabsList, TabsTrigger and TabsContent.
- L21: Manual mode brings its own TabsList, so Tabs does not render a second, empty one.
- L23: Manual mode is detected by a TabsList appearing before any TabItem, so intro text can precede the list and Tabs nested in a panel do not count.

### `apps/site/src/components/ui/tabs/tabs.client.ts`

- L16: Trigger lookup is scoped to this container so a nested <Tabs> cannot flip the parent into manual mode, independent of mount order.
- L73: The active tab is scrolled into the strip's visible range by overhang amount, not scrollIntoView, which would also scroll the page vertically.
- L97: RTL scrollLeft runs from 0 down to -max, so overflow distance is measured via Math.abs.
- L111: Cross-instance tab sync keys on trigger label; duplicate labels resolve by first match and would activate the wrong panel, so dev builds surface it.

### `apps/site/src/components/ui/theme-toggle/theme-toggle.client.ts`

- L1: The theme toggle writes the preference to localStorage (ui-mode); BaseLayout's pre-paint script owns DOM application so view transitions, OS changes and cross-tab edits stay in sync.

### `apps/site/src/components/ui/toc/MobileTOC.astro`

- L2: MobileTOC fills the gap below xl, where the desktop TOC rail does not render: a native <select> under the page title that tracks the active section.

### `apps/site/src/components/ui/toc/TOC.astro`

- L16: Headings that slug to "" (e.g. an emoji-only heading) are left out of the TOC: they have no target to link to.

### `apps/site/src/components/ui/toc/mobile-toc.client.ts`

- L1: Mobile TOC keeps the jump-to-section <select> in sync both ways: selection scrolls the page with the observer suppressed, and scrolling updates the selection.
- L19: The active heading is whatever sits in the reading band [10%, 30%] of viewport height; the observer ignores the top 10% and bottom 70%.

### `apps/site/src/components/ui/toc/toc.client.ts`

- L1: Scroll-spy uses a single IntersectionObserver; the indicator dash slides by arc-length so it weaves through the rail's curves instead of cutting across.
- L21: Only resolvable headings are observed, each carrying its original index, so scroll-spy stays aligned with the links and segments when a heading's target is missing.
- L56: The rail path is measured per command in O(1) and accumulated, rather than re-measuring the growing path with getTotalLength() each iteration (O(n^2), blocking the main thread).
- L116: First paint forces a layout recalc so only opacity transitions, with no dash sweep of the TOC rail indicator.
- L172: At page bottom the active TOC entry is the last heading on the page, not the last link, since a link whose heading has no target can't be the one being read.
- L329: Late-loading content (the API home's parts) dispatches nb:toc-headings; the TOC tracks headings that have appeared since.

### `apps/site/src/content.config.ts`

- L17: Docs are agent-friendly by default; set audience: human in frontmatter to flag a page written primarily for human readers.
- L20: The related: frontmatter field (carried over from Blume) feeds the Related pages cards; every page but the index names 2-4, enforced by a unit test.

### `apps/site/src/layouts/BaseLayout.astro`

- L4: The brand layer (generated --nb-* token overrides and @font-face for the self-hosted fonts) is imported last so its tokens win.
- L43: The per-page agent-index pointer resolves to /<prefix>/llms.txt for non-primary or version collections, falling back to the root /llms.txt.

### `apps/site/src/layouts/DocsLayout.astro`

- L2: DocsLayout is a three-column docs layout whose named slots (header, sidebar, toc, page-title, content-footer, pagination) are all optional overrides.
- L41: searchable derives from noindex when omitted (a non-crawlable page is by default not in site search either); explicit searchable: true overrides for the internal-search-only edge case.
- L47: sidebar: false / tableOfContents: false arrive from the route as literal false and drive per-column suppression: chrome, mobile dialog and the header menu button.
- L54: Per-page version status drives Pagefind faceting, the deprecation banner, and the data-pagefind-ignore exclusion for hidden versions.
- L65: Page-body ignore resolution: searchable: false (or noindex with no explicit override) ignores the page; hidden-version pages are ignored unconditionally, hidden taking precedence.
- L74: The status filter rides its own element: an inline name:value filter captures to the end of the string, so a second inline filter would corrupt the version value.
- L88: The sidebar filter is rendered only once the sidebar is long enough to be worth searching.
- L95: Below xl the On-this-page bar's own borders separate header from content, so the header rule draws only where that bar is hidden.
- L360: mount() re-binds on every astro:page-load and tears down on astro:before-swap, so the hamburger survives client-side navigation.
- L386: One sidebar tree per page: the drawer borrows the rail's tree node while open and returns it on close, so markup renders once and open groups, filter and scroll state stay with the reader.
- L463: Past the desktop breakpoint the hamburger is hidden, so an open drawer is dismissed to avoid stranding focus once its trigger disappears.
- L476: A view-transition swap while open never fires close, so the scroll lock must be balanced manually.

### `apps/site/src/lib/shortcuts.ts`

- L3: Shortcuts config: change a key or set it to false to remove it; Mod is Cmd on macOS and Ctrl elsewhere; readers can turn single-key shortcuts off from the search dialog.

### `apps/site/src/lib/variants.ts`

- L16: variants() turns a component's variant tables into one class function, so every component picks its look the same way.

### `apps/site/src/pages/docs/[...slug].astro`

- L18: The docs collection is mounted at /docs by this route's folder; every URL Nimbus builds for the collection follows the route-folder mount.
- L45: tocOn's boolean narrowing is not carried by TypeScript to the getTOC argument, so tableOfContents is re-checked to guarantee getTOC only ever sees its options object or undefined.

### `apps/site/src/pages/index.astro`

- L2: LP structure is plan A revision 2 after the owner review (2026-09-04): the chain of Whys, per web-design-pass rulings D and G.
- L333: Waitlist channel is a static placeholder only; H6 swaps in a POST form to Workers.
- L394: LP headings use Archivo's width axis, made wide and extra-bold per web-design-pass §4.
- L401: On the LP the accent is used sparingly: only the heading punchline, CTA buttons, and the 'key' in figures.
- L471: On the LP the terminal appears in only two places, as evidence (hero and schema); its background is the code token with no decoration.
- L540: Chain steps keep the figure after the text in the visual order as in the DOM; alternating sides would make visual order disagree with screen-reader order (pinned by e2e).
- L596: LP figures are 3px round-ended pictograms with the accent at exactly one point per figure — what holds the key (owner ruling 2026-09-04, §4 G rev 2).
- L653: SVG figure labels use geometricPrecision because Chromium otherwise lays SVG text out at on-screen size with whole-pixel advances, drifting labels as figures scale; e2e pins no crossings.

### `apps/site/src/pages/og/_card.ts`

- L1: Social cards render at build time via nimbus-docs/og; the leading underscore in _card.ts keeps Astro from routing the file or _fonts/.
- L18: OG card colors are the maruhi dark palette from theme/tokens.ts, written as hex because Satori requires hex values.
- L45: OG fonts sit beside _card.ts, not in public/, so they never ship; they are read from the project root so astro build --root finds them.
- L75: The card draws its own circle because logo.ts carries only the glyph path; the source SVG draws the circle as a stroked <circle> around it.
- L112: The card footer hangs from the hairline rather than the bottom margin because X crops cards to 2:1 and covers the foot with the link's domain.

### `apps/site/src/styles/globals.css`

- L5: globals.css is the theme file of record: --nb-* tokens feed Tailwind via @theme, dark mode is [data-mode=dark], colors are oklch, and token names avoid reserved Tailwind keywords.
- L35: Muted foreground keeps 4.5:1 contrast or better on every light surface, inline code included.
- L46: The brand color is a blue-traced grey used only for wayfinding — current page/section/tab and actionable focus/link hover.
- L72: Warning foreground is darker than the line colour so text on the warning tint still reads at 4.5:1.
- L80: The API method palette here is the shared source of truth for the method chip across the sidebar, endpoint card and code rail.
- L90: The PUT method color is a step darker than the warning colour to hold 4.5:1 on its own tint.
- L105: The sticky header height token grows on phones when section tabs take their own row; sticky bars and scroll margins read the token.
- L117: The type scale is one ratio (√1.5) from the 16px body landing on whole pixels (16→24→36, h3 at the half step), line heights on the 4px grid, weight falling as size rises.
- L136: Surfaces share one radius and small inner marks a smaller one; changing these two tokens re-rounds the whole site.
- L289: Focus outline defaults to the ring's resting values so toggling the ring changes nothing a transition can animate — no color/width/offset flash.
- L356: Code line-height is a whole-pixel 24px line so a block of n lines is always 24n + 24px tall.
- L435: Code surfaces keep LTR chrome order on RTL pages because code and diagrams read left to right in every language.
- L446: Code chrome lives on the non-scrolling figure wrapper because iOS Safari slides absolutely-positioned children of overflow:auto containers.
- L464: In titled blocks the language chip stays hidden because the filename's extension already names the language; title bar height is 8+20+8+1px.
- L632: Sidebar rows are styled by position with no class/data attributes because large sidebars repeat rows thousands of times; components layer keeps row utilities winning.
- L678: The current-page marker is the one place the sidebar uses the brand color.
- L700: The group caret is drawn once as a CSS mask instead of an inline SVG per group.
- L738: Closed sidebar groups get display:none because Safari still lays out closed <details> content in large trees.
- L742: Sidebar rows are 14px against the 16px body so docs and API sidebars land on the same pixels; the on-demand API sidebar is named explicitly too.
- L773: View transitions are scoped to the main content only; chrome snap-swaps via the root rule so the visual field doesn't shift on navigation.

### `apps/site/src/styles/prose.css`

- L1: Prose sizes and line heights are whole pixels on a 4px grid (body 16/28, small 14/24, headings from the --nb-h* tokens).
- L9: Long unbroken tokens wrap via overflow-wrap so they can't leak past the column; pre blocks are unaffected (they scroll) and wide tables keep their own handling.
- L18: Prose rhythm uses :where() to keep specificity at (0,1,0) so component margin utilities can override it.
- L69: Component boundary: elements carrying a class are component-owned; markdown never adds classes to h1-h6 or p, so classless selectors style prose only.
- L168: Inline code keeps line-height 1 because a smaller font on its own line height would grow the line box by half a pixel; every text line stays exactly 28px.
- L220: Table scroll is owned by the .nb-table-scroll wrapper (injected by the tableScroll hast plugin) because overflow is ignored on a table element.
- L262: Code in a table cell stays on one line and the table scrolls, rather than breaking identifiers like RateLimit-Remaining across two lines.
- L318: <mark> is harmonized with ::selection instead of the browser's fluorescent yellow; box-decoration-break keeps the tint coherent across wrapped lines.
- L331: Native disclosure styling excludes the FileTree subtree because FileTree builds classless <details> internally; without the guard its rows would grow double carets and borders.

### `apps/web/public/pages.css`

- L122: The pre gets tabindex and the shared focus ring because horizontal scroll needs keyboard reach on narrow screens (axe scrollable-region-focusable).
- L143: The outcome line is the one fact each script-free landing page must make visible (AUTH_SPEC §3 / ROADMAP H6).
- L163: The confirmation code is the page's largest element: system monospace (no web font), wide tracking, slashed zero; the alphabet is Crockford Base32 with no I/L/O/U.

### `apps/web/src/App.tsx`

- L1: App is the server-component entry: route definitions live in a server module and page bodies are baked into the RSC payload; the dashboard binds via bindRoute (ruling BO).
- L28: routes.ts is the single catalog of route paths (ruling BZ — a unit test checks the SPA space and run_worker_first do not intersect); App.tsx only binds them.
- L33: Authenticated screens sit under a pathless parent (DashboardLayout) so navigations never remount the shell.

### `apps/web/src/Root.tsx`

- L1: Root is the static build-time shell and a server component; it must not import client components, which would never hydrate.
- L50: The framework's mount-point constraint requires a raw div for #app — do not componentize it; children must be its parent's only child.

### `apps/web/src/components/FocusOnNavigation.tsx`

- L5: Focus moves to the page h1 after an intercepted SPA navigation finishes (audit A-2); first load, static fallback and non-intercepted navigations are deliberately left alone.
- L49: A rejected navigation finished promise means the navigation was superseded or failed, so focus must not move; the rejection callback also keeps it from surfacing as unhandled.

### `apps/web/src/dashboard/AccountAuditScreen.tsx`

- L3: The account audit screen is the self axis only (AUDIT_SPEC §3.1/§6); on the D1 path seq is never on the response, so the column naturally never appears.

### `apps/web/src/dashboard/AuditEventList.tsx`

- L3: AuditEventList is shared by the three axes (ruling BQ): role-adaptive heading, seq shown only when the response carries it, before-cursor paging, no counts, identifiers only (no unverified name resolution).
- L82: The actor head shows only the principal; provider information is structurally absent from the event.
- L88: Actor identifiers (key FP, token id) are reference values, not verification material (§4-3).
- L103: A rotation.recommended row's epoch label is 'exposure epoch' because for that event the epoch is its exposure bound (AUDIT_SPEC §3.3).
- L129: Event summary order is actor, coordinates, seq/time on one line (ruling Q — no wide-screen gap); seq is response-adaptive (§7) and the trigger holds no interactive elements.
- L318: Load more never swaps the button out while loading (a LoadingRow would drop focus to body); isInterruptible avoids native disabled for the same reason, with double-load blocked in the handler.
- L357: The audit list opens at most one row (single) so other rows never move while the expanded part is being read; expansion state survives appended pages.
- L417: In-flight page state is a generation counter, not a boolean, so a stale request settling cannot clear the flag of the request that replaced it.
- L422: Each fetch axis has a generation; when the axis changes, a stale in-flight response is discarded so an old-axis page cannot bleed into the new axis's list.

### `apps/web/src/dashboard/DashboardScreen.tsx`

- L3: The project list carries only server-reported projectId + chain-derived role (§11-5) with nextAfter Load more; typing a project ID directly (genesis hash as capability) is formally in place.
- L116: Loaded rows are deduped by projectId so a hostile or broken server repeating an id cannot grow rows and React keys.
- L129: MAX_EMPTY_PAGE_HOPS caps auto-following empty pages as a resource bound against a server that mints a fresh cursor every time; past it, manual load more takes over.
- L132: An empty page is not the end of the list (§11-5 — ghost exclusion / confirmation omission); following stops at a seen cursor (hostile server) and is bounded by the fixed cap.

### `apps/web/src/dashboard/DashboardShell.tsx`

- L3: DashboardLayout holds session state in the pathless parent so screens never remount or re-fetch /auth/me; useLocation is avoided because Location.hash would trip the §15-3 'hash' tripwire.
- L91: The sidebar/sign-in logo is the inverted mark pinned to vermilion — its color deliberately does not follow the theme, matching the favicon.
- L102: Content width is one shared 1200 for every page: it exactly fills a 1440px notebook's region and sits centered at 1920px.
- L108: Separator discipline (ruling O): heading/section/body boundaries are whitespace, not lines; lines appear only inside collections and on the tab row.
- L131: A screen's shell-nav declaration is applied in a layout effect before paint so the first frame after a transition never retains the previous screen's selection.
- L155: Per-screen document.title is set client-side because SPA transitions never change the static shell's title; unmount restores the shell's value in commit order.
- L277: SignInScreen renders outside AppShell so the main landmark is given via role; after a sign-out/401 the vanished focus is moved to the heading, but never stolen on initial render.

### `apps/web/src/dashboard/DevicesScreen.tsx`

- L3: Devices screen is read-only and advisory: the registry is not the source of truth (each project's chain is); no registration/deletion/approval here — only the token-revocation funnel (§13-11, K5).
- L254: During the post-revocation re-fetch the previous table stays and each row's Revoke is disabled, preventing a double revocation on a pre-refetch row.

### `apps/web/src/dashboard/InvitesTab.tsx`

- L3: Invites tab: no issuing here (ADR-0018 amendment 2 — no out-of-band anchor); the tab is not hidden by role in advance — a 403 is displayed with role wording (ruling CP).
- L60: Invite status color lookup uses Object.hasOwn so an unexpected status string, including prototype-chain key names, falls back to the default color.
- L73: REVOCABLE_STATUSES copies the server's acceptance condition for display only — it is not a defense; literals are type-bound to the closed enum so a rename fails at compile time (ruling CC).
- L145: Revocation state lives outside the list resource so the latest failure display does not disappear on an unmount mid-refetch.

### `apps/web/src/dashboard/OverviewChain.tsx`

- L23: Only the chain report's shape is read — defense against a hostile server: an unreadable attestation row is dropped without being counted.
- L168: Four-eyes approvals are read-only here; approving and withdrawing are the CLI's (ADR-0018). The vote count shown is a recount of the fold, not the record.

### `apps/web/src/dashboard/OverviewMembers.tsx`

- L41: Device cap wording is identical on web and CLI (describeCap) — the same fact is written the same way on both surfaces (K5-3).
- L88: A device FP appears only once it could be bound from the reported bytes, because the add_device wire carries no FP (K5-1).
- L158: Unreadable dropped entries are never silently absorbed (K5-17): the display may be off in either direction and never asserts one (K5-18); verification is the CLI's job.

### `apps/web/src/dashboard/ProjectScreen.tsx`

- L3: Project screen is read-only with server-reported display only: chain fold is not verification, metadata pulls never carry values/DEKs, and rotation flags have no dismiss here (ADR-0018).
- L48: Tab panels take their name from the corresponding tab (APG); Astryx Tabs auto-assigns no ids, so explicit tab ids are referenced via aria-labelledby.
- L58: The hidden attribute alone doesn't hide a VStack panel: its display:flex in astryx-base beats the reset's [hidden] rule; the StyleX display:none wins by layer order (ADR-0013).
- L73: The invites tab is keyed by projectId so a revocation state cannot carry over to another project.

### `apps/web/src/dashboard/ProjectScreenAudit.tsx`

- L42: Axis switching uses ToggleButtonGroup because SegmentedControl's unselected-label contrast is 4.26:1 in dark, short of AA (a11y audit).

### `apps/web/src/dashboard/ProjectScreenOverview.tsx`

- L19: The chain fetch doubles as the project-existence check and leads; environments are read only after it arrives to avoid stacking the same 404/403 banner per section — the serialization is accepted.

### `apps/web/src/dashboard/ProjectScreenRotation.tsx`

- L33: Trigger labels are a Map so a hostile trigger string never hits a prototype-chain name.
- L46: Flag trigger display uses the §3.3 trigger wording; the tail carries triggerChainSeq so a revoke_device row (no FP) can be traced to the Audit tab's mirrored row (K5-5).
- L158: Dismissing rotation flags is not on the web: erasing a warning is a governance operation (ADR-0018 amendment 2).

### `apps/web/src/dashboard/ResumeToDashboard.tsx`

- L3: The return island acts only when the sign-in round-trip marker exists (ruling BU): without it a landing visitor costs zero API calls; with no session only the marker disappears.

### `apps/web/src/dashboard/TokensScreen.tsx`

- L3: Tokens screen: no issuing or raw-value display here (ADR-0018 amendment 2); the response structurally has no raw values or hashes; revocation is a modal confirm (ruling CO).

### `apps/web/src/dashboard/audit-read.ts`

- L1: audit-read duplicates core's interpretation because the web holds only type-only imports (TCB minimal); the acceptance condition is identical to core's so the two never diverge in count or display.
- L135: The version_pushed lineage label derives from sameValueAs: previous version = re-encryption, older = rollback, none declared = fresh value (§3.3).

### `apps/web/src/dashboard/chain-view-devices.ts`

- L42: Stale-holder resolution (K5-12): an accepted add_device means the key is not currently valid, so an unbound holder device with unresolved entries is confirmed revoked and removed; otherwise it is a duplicate.
- L65: Re-adding the same key restores the learned FP (revocation is not monotonic, §6.2); same-FP duplicates need no check here by the table's injectivity and key uniqueness (K5-16).
- L123: An unmatched FP that is already someone's key cannot be a revocation of this person's unbound device (§6.2 unknown-device), so the row is unreadable (K5-16).
- L158: Removing matched bound devices leaves their FPs on the table, henceforth never tied to another device (K5-16).
- L176: revoke_device fold arithmetic (K5-1): bound matches are removed; unmatched FPs are removed arithmetically against the unbound remainder, with any shortfall counted into unresolved.

### `apps/web/src/dashboard/chain-view-operations.ts`

- L43: change_role fully replaces (role, scope) (§6.2); a restatement of the current role and scope is valid and leaves sinceSeq at the last change.
- L87: OPERATION_FOLDERS holds only ops shared by direct appends and approve inner ops; device ops and delete_environment fold only as direct entries because they are never four-eyes targets (K5-4).
- L132: An unmodeled inner op is ignored (K5-4); a non-record payload is counted as an unreadable row (K5-17 discipline).

### `apps/web/src/dashboard/chain-view-proposals.ts`

- L39: Owner-vote counting is fail-closed (§6.2, K5-2): the voter must be a current owner whose FP matches a bound owner-capped device; an unbound FP counts only when every unbound device is owner-capped.
- L93: applyApprove only transcribes vote arithmetic: an approve on the chain already passed the consensus rule at the acceptance surface, so no consensus check is repeated here.

### `apps/web/src/dashboard/chain-view-reported.ts`

- L3: A reported device's FP is null while it could not be bound from the reported bytes, because the add_device wire carries public keys, not the fingerprint (K5-1).
- L79: unreadableEntries (K5-17 generalization) counts every entry the fold left out; dropped add/revoke rows can shrink or grow the displayed sets, so the count is shown, never silently absorbed.

### `apps/web/src/dashboard/chain-view-state.ts`

- L22: proposerSignedAsOwner records whether the proposal signature counted as an owner vote when made (§6.2); whether it still counts is judged at the tally like any vote (K5-2).
- L56: unboundSignerFps is used only for the vote judgment (K5-2) and is discarded every time a revocation shrinks the unbound devices (fail-closed).
- L65: The key-FP table is injective and set-once (K5-16): once learned, neither key nor FP is ever tied to another party, excluding stale-actor and cross-interval re-binding structurally.
- L120: ownProp reads only own properties so a hostile server's __proto__ never yields a prototype-chain value.
- L205: An FP already on the table belongs to a current, revoked, previous-interval or someone else's key in every case, so it is never a candidate for an unbound device (K5-16).
- L222: bindActor ties a signer's actor FP to a device only when exactly one device is unbound (K5-1); with two or more it goes to unbound signer FPs, with zero the report is unreadable.
- L249: scopeIdsWithout mirrors crypto's scopeWithout (§6.2 delete_environment): all is never pruned; a listed scope naming the environment stays listed, possibly empty.
- L261: An unreadable scope folds to listed + empty (hostile-server defense), rendering as 'no environments' — indistinguishable from a delete-emptied scope; the member record itself is not dropped.
- L274: The dispatch table's folder type is the generic signature for recording calls; each folder is invoked only after widening, assuming rows that passed the structural check.

### `apps/web/src/dashboard/chain-view.ts`

- L1: chain-view is a display fold, not verification (ADR-0018): no signature/hash/consensus checks in the web bundle; hashes come from the next entry's prevHashHex, votes are recounted, FPs bind only from reported bytes (K5/K6-J).
- L104: delete_environment prunes the id from member, device and server scopes (a member's sinceSeq moves to the deletion); the environment set itself is not folded — live environments come from the server listing (§12-7).
- L140: The device ops and delete_environment fold only as direct entries because they cannot be proposed (§6.2 approval-not-required, K5-4); other state-changing ops go to applyOperation.
- L170: The fold's op lookup uses Object.hasOwn so a hostile server's op like __proto__ cannot hit a prototype-chain value and drop the render with a throw.
- L188: ENTRY_KINDS is the closed set of ops the fold admits; create_environment / rotate_epoch / checkpoint are excluded because they do not affect the member/server sets.

### `apps/web/src/dashboard/display.tsx`

- L3: Display discipline (§4): only server-reported phrasing, no client-side assertions; the one client judgment is ExpiryCell's Expired, which ruling CQ allows.
- L28: ServerTime renders the server-reported value converted to the viewer's timezone; hasTooltip=false inside buttons because a tooltip would build a nested interactive element.
- L72: RoleToken uses Object.hasOwn so an unexpected role string, including prototype-chain key names, falls back to the default color; the display never claims to be verified (§4).
- L106: ExpiryCell (ruling CQ): the displayed value is always the server-reported expiresAtMs; only the is-past check compares against the client clock.

### `apps/web/src/dashboard/endpoints.ts`

- L63: Invite/token ids are server-issued opaque ids with no client format check, so they go through encodeURIComponent; a hostile id straying off the path stays a visible 404/405 (ruling CN).

### `apps/web/src/dashboard/icons.tsx`

- L1: Heroicons are copied inline rather than depended on (no-new-dependencies policy); the MIT license text sits beside the copied asset as MIT requires.

### `apps/web/src/dashboard/ids.ts`

- L9: The project-ID pattern is kept as a literal rather than imported from core, because the policy is to bring no executable code into the bundle (ruling BR); the check lives in one place here.

### `apps/web/src/dashboard/resource-states.tsx`

- L3: Resource states follow ruling B: every screen draws loading/empty/failure only via LoadingRow, EmptyNotice and FailureNotice (replacement or appended form); screens never compose Text/Banner directly.
- L42: The session-not-allowed literal is type-bound to api-schema's closed enumeration (ruling CC) so renaming a reason fails at compile time, not as a silent fallback to generic wording.
- L47: The 404 wording's uniform meaning (someone else's vs nonexistent is not distinguished) never changes; only the noun adapts to the screen's subject, unified in this module (ruling BP).
- L95: The 410 notice takes its noun from the subject at ruling BP's single implementation point, so a future 410 consumer surface does not leave one noun fixed on only one side.
- L157: A 401 reports session expiry to the shell, which swaps to sign-in on the spot; the Signed out banner covers the single render until the report lands, or use outside the shell.
- L191: EmptyNotice's default wording includes 'as reported by the server' and must not hint at counts or an invisible class (§4-4); headingLevel follows the box hierarchy to avoid an h1 to h3 jump.

### `apps/web/src/dashboard/resume.ts`

- L1: The resume marker is a one-shot sessionStorage flag (ruling BU): only its presence triggers one /auth/me check on the landing; unavailable storage degrades to the static-link funnel.

### `apps/web/src/dashboard/revocable-list.tsx`

- L3: revocable-list is the shared skeleton for S8/S9: the screen supplies rows, columns, revocability and wording; revocation state stays outside the list resource so failures survive re-fetches.
- L118: During the post-revocation re-fetch the previous list stays and every row's Revoke is disabled, preventing a double revocation on a pre-refetch row.

### `apps/web/src/dashboard/revocation.tsx`

- L3: revocation.tsx is the shared S8/S9/S11 revocation surface (button, dialog, outcome); display discipline: only server-reported phrasing, no client-side assertions (§4).
- L19: DP3 amendment 4 replaced ruling CO's in-row two-step confirm with the modal AlertDialogAsyncAction shape because in-row buttons stacked in a narrow column and changed other rows' heights.
- L93: On revocation success focus moves to the announcement banner itself, because the revoked row disappears on re-fetch and the focus the dialog returned is lost with it.
- L117: RevocationOutcome was promoted to a shared surface when DK K5 produced a third screen; the success message is built at confirm time because the object may not remain in the list after re-fetch.
- Added 2026-11-28 (after the audit; no base line): after a failed revocation the dialog returns focus to the row's Revoke button, and focus stays there while the row is still revocable, so a retry is one key press away. When the re-fetch draws the row without its button (a 410 race), focus fell to the document body (reproduced in the web e2e). `RevocationFailure` wraps FailureNotice in a focusable container and takes focus once the re-fetch has settled with focus on the body. Focus moves only in that case: moving it on every failure would take it off the retry control on S8, S9 and S11.

### `apps/web/src/dashboard/routes.ts`

- L1: Route definitions live in one shared module (ruling BO): the path space is pinned to /dashboard, plainly separated from the API's /auth and /projects spaces.
- L41: dashboardShellRoute is pathless: the shell mounts once across navigations with no /auth/me re-fetch; having no path, it is deliberately not listed in SPA_ROUTES.
- L52: spaPaths is the single home for navigation paths (ruling CA); the source tripwire excludes any /dashboard-prefixed literal outside this module.
- L67: SPA_ROUTES (ruling BZ) is collated by a unit test against wrangler.jsonc's run_worker_first so the SPA's route space is never swallowed by the Worker.

### `apps/web/src/dashboard/sections.tsx`

- L3: sections.tsx holds the shared section parts (gap, heading, box, callout, server-reported caveat) under the §4 display discipline: only server-reported phrasing.
- L17: SECTION_GAP is 10 (40px) shared by every screen because a section boundary is marked by whitespace, not a line (ruling O), contrasting with the in-section gap of 4.
- L50: SectionBlock puts only the collection in a Card, not the section (amendment 10 owner ruling): heading and description stay on the page's content line so every text start aligns.

### `apps/web/src/dashboard/session-expiry.ts`

- L1: Session expiry reaches the shell only through this notification: the shell mounts once and cannot notice a mid-session 401 itself; it reacts to the first 401 and adds no per-navigation re-check.

### `apps/web/src/dashboard/use-api-resource.ts`

- L24: During a same-path reload the previous value stays rendered because swapping the table for a LoadingRow would drop the focused row's element and focus would fall to body.
- L36: useApiResource discards stale in-flight responses on path change or reload, so a late response for an old project never overwrites the newer screen.

### `apps/web/src/dashboard/use-revocation.ts`

- L3: Revocation state machine (ruling CO): single-row arming, re-fetch after completion regardless of outcome with no optimistic update, and state held outside the list so a failure display survives an unmount mid-refetch.
- L52: The in-flight guard blocks arm/confirm during a DELETE so a late completion cannot overwrite another row's armed state; the UI's disabling is a second layer, not the only one.

### `apps/web/src/pages/HomePage.tsx`

- L1: HomePage is the product origin's top (TCB): the LP/docs moved to the apex site, so it carries only minimal guidance and the dashboard funnel (DP2 ruling F).

### `apps/web/theme/maruhi.ts`

- L16: Vermilion light is the brand's source of truth (HCT hue 44 / chroma 76 / tone 44), kept 16 degrees of hue away from the danger crimson.
- L23: Dark vermilion is stated in tokens because Astryx's seed derivation pins the dark accent to a tone-80 pastel (chroma ~31), violating 'do not lower the chroma' (§1-1, ruling A).
- L29: Dark on-accent is stated explicitly because the seed-derived PD[20] reaches only 4.1:1 and does not meet AA; the warm-neutral tone 10 value reaches 6.0:1.
- L36: The system stack is named first because nothing loads Figtree on this origin — every browser fell back to this stack anyway, so naming it keeps the token honest.
- L58: Code-typed Text wraps anywhere with min-width 0 so long identifiers and audit payloads wrap instead of widening their flex parent (ruling H's HexText override, promoted here).

### `packages/core/src/crypto-services.ts`

- L1: Crypto services seam: randomness/digest/signature route through Effect services so every draw is auditable at one point and tests can substitute deterministic Layers; scope boundaries state what stays ambient and why
- L35: The composed crypto-services layer requires nothing from its environment — the Signature layer's own SecureRandom requirement is provided inside the composition

### `packages/core/src/ids.ts`

- L1: ID randomness draws go through the SecureRandom service so tests can substitute a deterministic source; the service's own ulid is deliberately not used — it would desync id timestamps from row timestamps and change the byte mapping
- L46: The modulo mapping is unbiased because 256 is divisible by 32

### `packages/crypto/src/internal.package/index.ts`

- L1: internal.package exposes only a minimal public surface through its index (CLAUDE.md boundary rule)

**Rationale**: A comment at the code site was the historical carrier for these records, but comments rot silently and cannot be reviewed as decisions. Concentrating the records in ADRs keeps them reviewable, and lets the comment ratchet (ADR-0020) hold the codebase at zero prose comments without losing the decisions.

**Consequences**: The comments are deleted from the code. Gate and operator configuration files keep a one-line `See ADR-NNNN.` pointer where a reader of that exact spot would otherwise make a wrong change; every pointer is counted in the ratchet baseline. New decisions in this area are recorded here or in a new ADR, never as code comments.
