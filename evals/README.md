# Reverse-analysis LLM evaluation fixtures

- Baseline recorded: 2026-08-13
- Model identifier: `synthetic-replay-v1`
- Mode: deterministic replay only in CI

Fixtures contain reviewed function-explanation responses for synthetic symbols.
No binary path, repository path, customer identifier, address, or credential is
recorded. The product's native LLM response has `name` and `purpose`; it does
not emit severity or confidence, so the gate validates those actual fields.
