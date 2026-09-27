# ADR-0010: Quality toolchain

**Decision**: oxlint + oxfmt (no Prettier), ImportLint (@public encapsulation), fallow (codebase health, baseline operation), React Doctor (web, diff mode). CI order: format → lint → tsc → ImportLint → fallow → React Doctor → tests (Vitest).
**Rationale**: Unified on the oxc family (speed, built-in Tailwind class sorting). ImportLint mechanizes the security design of enforcing the crypto core's API boundary. Every tool ships an agent skill, so the set works as guardrails for agent-assisted development.
