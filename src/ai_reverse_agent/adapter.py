"""005 reverse engineering product adapter for v0.5 IntegrationGateway."""

from __future__ import annotations

from typing import Any, AsyncIterator

from shared_llm_core.finding import Finding, FindingSeverity, FindingSource
from shared_llm_core.gateway import ProductAdapter

from ai_reverse_agent.scan import scan_binary


class ReverseProductAdapter(ProductAdapter):
    """Expose the existing binary scanner through the §10 adapter contract."""

    source = FindingSource.REVERSE

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        effective_payload = dict(payload)
        architecture = effective_payload.get("arch") or "x64"
        effective_payload["arch"] = architecture
        envelope = scan_binary(effective_payload)

        for item in envelope.get("findings", []):
            evidence = list(item.get("evidence", ()))
            evidence.append(f"arch={architecture}")
            normalized = {
                **item,
                "id": "",
                "source": self.source.value,
                "evidence": evidence,
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
                metadata={"error_code": code},
            )

    def health(self) -> dict[str, Any]:
        return {
            "status": "ok",
            "product": "005-reverse",
            "version": "0.5.0",
        }
