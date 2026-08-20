"""005 reverse engineering product adapter for v0.5 IntegrationGateway."""

from __future__ import annotations

from typing import Any, AsyncIterator

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource
from shared_llm_core.gateway import ProductAdapter

from ai_reverse_agent.decompilers.selector import DecompilerSelector
from ai_reverse_agent.scan import scan_binary


class ReverseProductAdapter(ProductAdapter):
    """Expose the existing binary scanner through the §10 adapter contract."""

    source = FindingSource.REVERSE

    def __init__(
        self,
        *,
        decompiler_selector: DecompilerSelector | None = None,
    ) -> None:
        self._decompiler_selector = decompiler_selector

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        effective_payload = dict(payload)
        architecture = effective_payload.get("arch") or "x64"
        effective_payload["arch"] = architecture
        envelope = scan_binary(
            effective_payload,
            decompiler_selector=self._decompiler_selector,
        )
        decompiler_backend = _decompiler_backend(envelope)

        for item in envelope.get("findings", []):
            evidence = list(item.get("evidence", ()))
            evidence.append(f"arch={architecture}")
            metadata = item.get("metadata")
            normalized_metadata = dict(metadata) if isinstance(metadata, dict) else {}
            normalized_metadata.setdefault("decompiler_backend", decompiler_backend)
            normalized = {
                **item,
                "id": "",
                "source": self.source.value,
                "evidence": evidence,
                "metadata": normalized_metadata,
            }
            if not normalized.get("description") and normalized.get("narrative"):
                normalized["description"] = normalized["narrative"]
            yield Finding.from_dict(normalized)

        if envelope.get("findings"):
            return

        errors = envelope.get("errors") or [
            {
                "code": "no_findings",
                "message": "binary analysis produced no findings",
            }
        ]
        for error in errors:
            if isinstance(error, dict):
                code = str(error.get("code", "analysis_warning"))
                message = str(error.get("message", code))
            else:
                code = "analysis_warning"
                message = str(error)
            binary = effective_payload.get("binary_path")
            yield Finding(
                id="",
                source=self.source,
                severity=FindingSeverity.LOW,
                confidence=0.5,
                title=f"Reverse analysis warning: {code}",
                description=message,
                host=str(binary) if binary else None,
                evidence=(f"arch={architecture}", f"error={code}"),
                tags=frozenset({"warning"}),
                metadata={
                    "error_code": code,
                    "decompiler_backend": decompiler_backend,
                },
            )

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "product": "005-reverse",
            "version": "0.5.0",
        }


def _decompiler_backend(envelope: dict[str, Any]) -> str:
    for item in envelope.get("findings", ()):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        backend = metadata.get("decompiler_backend")
        if isinstance(backend, str) and backend.strip():
            return backend
    return "native"
