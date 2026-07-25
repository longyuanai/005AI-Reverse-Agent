# Phase-2 static-analysis implementation

Phase-2 implements Hook A (architecture-neutral deobfuscation rules) and Hook B
(bounded PE/ELF import extraction plus sorted-import MD5 imphash matching).

- All sample handling is static. No analysed binary is executed.
- Files over 100 MiB are rejected before a full read with `MagicError`.
- The malware database is the checked-in `src/ai_reverse_agent/data/malware_imphashes.json`; no
  network lookup is performed.
- CLI enrichment is opt-in with `enrich: ["imphash", "iat_list"]`. Requests
  without `enrich` retain the v0.5 envelope fields and existing finding order.
- Hook C (Ghidra headless) and Hook D (YARA generation) remain deferred to
  v1.0+ as required by §13.
