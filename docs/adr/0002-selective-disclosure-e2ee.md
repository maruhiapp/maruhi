# ADR-0002: The crypto architecture is selective-disclosure E2EE

**Context**: We compared server-side encryption (Shelve-style), pure E2EE, Git-native, threshold encryption, BYOK, and TEE.
**Decision**: A selective-disclosure model built on E2EE that treats the server as an "invited member N+1". Plus a signed membership log, head gossip, HPKE context binding, epochs, and crypto agility. Details in CRYPTO_SPEC.md.
**Rationale**: It is a strict superset of pure E2EE (identical when no one is invited); it solves the trust problem of solo development with crypto while enabling server-driven features (GitHub sync etc.) as per-project opt-ins.
**Consequences**: The most complex of the three designs. The MVP implements pure E2EE only; the server key is added when GitHub sync is implemented.
