from __future__ import annotations

from abc import ABC, abstractmethod

from solsoc.triage.models import Alert, TriageResult


class LLMProvider(ABC):
    """Base class for all LLM providers."""

    name: str = "base"

    @abstractmethod
    def triage(self, alert: Alert) -> TriageResult:
        """Triage a single alert and return a verdict."""
        ...

    def _parse_response(self, alert: Alert, raw_text: str) -> TriageResult:
        """Parse the JSON response from the LLM into a TriageResult."""
        import json
        import re

        # Strip markdown code fences if the LLM added them despite instructions
        cleaned = re.sub(r"```(?:json)?|```", "", raw_text).strip()

        try:
            data = json.loads(cleaned)
            # confidence_score is new — default to 50 if the LLM omits it
            raw_confidence = data.get("confidence_score", 50)
            confidence = max(0, min(100, int(raw_confidence)))
            return TriageResult(
                alert_id=alert.id,
                alert_title=alert.title,
                verdict=data["verdict"],
                severity=data["severity"],
                reason=data["reason"],
                recommended_action=data["recommended_action"],
                confidence_score=confidence,
                mitre_technique=data.get("mitre_technique") or None,
                provider=self.name,
            )
        except (json.JSONDecodeError, KeyError) as exc:
            return TriageResult(
                alert_id=alert.id,
                alert_title=alert.title,
                verdict="NEEDS_REVIEW",
                severity="MEDIUM",
                reason="SolSOC could not parse the LLM response — review manually.",
                recommended_action="Investigate this alert manually.",
                confidence_score=0,
                provider=self.name,
                error=f"Parse error: {exc} | Raw response: {raw_text[:200]}",
            )
