# Session 29 memo (the design dialogue on the Web's trust boundary — the background of ADR-0018)

Date: 2026-08-16–18. Format: a design dialogue with no implementation (Q&A with the owner).
Scope: exploring a fundamental countermeasure to the hosted Web's TCB problem → considering and
rejecting localhost UI / Tunnel / screen sharing / Cloudflare Mesh → the owner's consent to a
staged-adoption plan. The deliverables are ADR-0018 and this note only (no code or spec-body changes).

## 1. The starting point (the owner's criterion)

- **Minimize the operator's potential wrongdoing**. The reasons for not choosing server-side
  encryption, for going OSS, and for wanting to offer it cheaply to individual developers all
  connect to this single line
- Strong concern about keys / plaintext touching "operator-served JS" on the hosted Web.
  Under E2EE decryption happens on the client, so Web XSS = all secrets leaked
  (CLAUDE.md's TCB section)

## 2. Research on mitigation techniques (none removes the structure)

- Strict CSP / excluding third-party scripts: already the adopted policy (spike-a), but it is
  **powerless against a malicious own-build** (operator compromise, supply chain)
- Transparency-log approaches (WEBCAT / CodeSeal / Code Verify): detection, not
  pre-execution blocking. A signed malicious build delivered to everyone passes. Co-locating the witness
  with the execution platform (Cloudflare) kills its independence
- IWA (Isolated Web Apps): the installable form can eliminate "fetching JS from the server every
  time", but it is Chrome-family-only and heavyweight to distribute — stays as a future candidate location
- Browser Isolation: decrypting in a remote browser is the inverse of E2EE. Rejected

## 3. Considering the localhost UI and "carrying it to another device"

- **The CLI serving a UI on 127.0.0.1** (`maruhi ui`) has keys in the OS keychain,
  decryption in the CLI process, and the browser doing only rendering — eliminating "the operator distributes the decryptor"
- Sending a valued screen to another device over a bare Quick Tunnel: **rejected**. A Tunnel
  terminates TLS at the edge, so already-decrypted HTML / JSON traverses the edge = re-opening
  yourself the "plaintext on the operator's path" that the hosted Web avoided. Access controls
  "who can reach it", not the secrecy of the contents
- For one's own other devices (a phone), 3 options were sorted: (a) a value-free remote control,
  (b) a private network (Tailscale etc. — stays an advanced-user document),
  (c) QR pairing + an E2EE session (reusing the same ceremony as invite fingerprint verification.
  If pursued, a CRYPTO_SPEC revision comes first). The product default is (a)

## 4. Team screen sharing (the owner's localhost to other members) — rejected

The idea of showing an owner / admin's screen to other members via a Tunnel etc. amounts to
dropping E2EE and **turning the owner's machine into the vault server**:

1. Permission becomes "the owner's key" rather than "the viewer's role" (hiding it on the
   screen still hides it inside the owner's process; the attack target shifts to one laptop)
2. Availability becomes that single machine (close the lid and the team's screen disappears)
3. Auditing becomes a lie (actor = the key that actually opened ≠ the viewer; AUDIT_SPEC's
   actor rule loses its meaning)
4. Invites become half-hearted (viewers are not members; run / push still needs
   each person's own key)
5. Plaintext rides the path (Tunnel / Mesh)

The answer to "I want people who don't want the CLI to see it" is not relaying through the
owner's machine, but giving them their own key, or handing them a value-free management view.

## 5. Cloudflare Mesh research (GA 2026-04)

- A reorganization of the old WARP Connector / peer-to-peer linking. Each device gets a
  Mesh IP from `100.96.0.0/12`; enrolled devices on the same Zero Trust account can
  reach each other over TCP/UDP/ICMP. The official docs include a concept-mapping table with Tailscale
- **Structural difference from Tailscale**: Tailscale direct-connects devices over WireGuard when
  possible (the relay cannot read the payload). Mesh is star-shaped — all traffic goes via Cloudflare,
  and Gateway inspection / logging is the design philosophy — the "path operator can see the contents" shape
- Verdict: real and useful as a tool for "narrowing who can reach it" (advanced users, for
  themselves). It does not change "who decrypts", so it does not solve the valued-screen sharing problem.
  Requiring everyone to install the Cloudflare One Client + Zero Trust enroll collides head-on with
  "the first 5 minutes", so it is not a product default

## 6. Delta from the original hosted-Web concept

The original concept (CRYPTO_SPEC §3 browser keys = IndexedDB, AUTH_SPEC §15-3 Web acceptance,
§6 token UI, spike-a/c's browser HPKE verification) was "an Infisical-style vault screen with only
decryption in the browser". The `maruhi ui` plan has **almost the same feature catalog**;
only 3 things change:

1. How you get in (a URL → a machine with the CLI. Web-complete invite acceptance hurts the most)
2. Where keys live (IndexedDB → the OS keychain. Since the original plan already needed
   recovery-code input for "any browser", this only adds honesty)
3. **Who serves the JS (the operator → yourself)** — only the operator's potential wrongdoing disappears

## 7. Flat evaluation (3 optimistic assumptions in the "maruhi ui = full CLI powers" idea)

The once-floated "ui can do everything the CLI does when it's the same person's key and same role" was
re-evaluated as containing 3 optimistic assumptions:

1. **Opposite direction to ADR-0016**: while the value-display boundary is being flipped to
   "both stdin/stdout are terminals" (fail-closed), localhost HTTP by definition
   carries values over a "not a terminal" path = a new hole in the boundary being narrowed. Agents
   can drive both a browser and curl, so deny-list-style blocking is not enough
2. **Browser extensions enter the TCB**: even though operator-served JS disappears,
   extension content scripts the user installed still inject into localhost pages.
   Extensions cannot touch a terminal's `pull --show`. The difference appears the moment a value
   enters the DOM (note that display spoofing of the 12-word fingerprint fails closed under
   the mutual / out-of-band verification structure — a failed check fails safe)
3. **Demand is unverified**: Phase 1 dogfooding runs on the CLI, and
   nobody has measured what "wanting a screen" actually means. The maintenance cost of
   2 artifacts does not fit an individual developer's scale

## 8. Ruling (owner consent → ADR-0018)

- The hosted / bundled-self-host Web holds **no keys and no plaintext** (a management
  screen that does not decrypt). The hosted bundle contains no decryption code path (merely
  hiding it behind a flag is forbidden)
- Value / key operations happen on each person's own machine. Screens are **staged**:
  stage 1 = polish the TUI (zero new attack surface) → stage 2 = `maruhi ui` v1 (value-free.
  Invite acceptance, fingerprint display, key generation can live here) → stage 3 = a valued ui needs
  demonstrated demand + an independent ADR (local API authentication / the relationship to ADR-0016 /
  explicit extension risk) as prerequisites
- No team screen sharing is built. One's own other devices (remote control / QR pairing) are
  future consideration. `maruhi ui` lives on the CLI side (MIT); the theme is shared but artifacts stay separate
  (since theme is currently under FSL coverage, re-placing it on the MIT side is a stage-2
  prerequisite — settled in the PR #82 review)
- Details and consequences (spec revision candidates, where W0 starts, the ROADMAP note) are in ADR-0018

## 9. References

- ADR-0018 (this session's deliverable) / ADR-0014 / ADR-0016 / ADR-0003
- CLAUDE.md "The Web dashboard is the Trusted Computing Base"
- CRYPTO_SPEC §3 (key storage locations) / §6.5 (mutual invite confirmation) / §14.3 (non-guarantees)
- AUTH_SPEC §6 (the token UI reservation) / §15-3 (the invite link format and Web acceptance)
- docs/notes/session-22.md §1 (Wave 3 W = starting from W0 screen design)
- docs/SECURITY_REVIEW_2026-08-14.md (CSRF on the valued pull = L-1. Fixed 2026-08-15)
- Cloudflare Mesh: developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/
  (the 2026-04-14 changelog. Explicit about all traffic via CF / Gateway inspection)
