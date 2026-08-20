# Reverse-analysis LLM evaluation fixtures

- Native baseline recorded: 2026-08-13
- Ghidra-shaped baseline recorded: 2026-08-15
- Model identifier: `synthetic-replay-v1`
- Mode: deterministic replay only in CI

Fixtures contain reviewed function-explanation responses for synthetic symbols.
No binary path, repository path, customer identifier, address, or credential is
recorded. The product's native LLM response has `name` and `purpose`; it does
not emit severity or confidence, so the gate validates those actual fields.

The backend is encoded in each case id and filename: `native-*.json` and
`ghidra-*.json`. The six native fixture payloads are unchanged from the 011
baseline; only their case ids moved to the backend-prefixed namespace.

The Ghidra baseline was generated from synthetic, recorded exporter output.
It is **not a real Ghidra run artifact**. A real run must follow
`docs/ghidra-backend.md` on a host with Ghidra and a compatible JVM, then be
reviewed before replacing any replay fixture.
