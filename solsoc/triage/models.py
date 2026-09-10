from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class Alert(BaseModel):
    """Normalized alert — common shape regardless of the source SIEM."""

    id: str
    title: str
    description: str | None = None
    severity: str | None = None       # severity as reported by the SIEM
    source: str | None = None         # e.g. Wazuh, Splunk, Sentinel
    timestamp: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)  # original object untouched


class TriageResult(BaseModel):
    """LLM verdict for a single alert."""

    alert_id: str
    alert_title: str
    verdict: Literal["TRUE_POSITIVE", "FALSE_POSITIVE", "NEEDS_REVIEW"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    reason: str                # one-line explanation of the verdict
    recommended_action: str    # what the analyst should do next
    confidence_score: int      # LLM confidence: 0–100
    mitre_technique: str | None = None  # e.g. "T1110 - Brute Force"
    provider: str              # which LLM produced this verdict
    error: str | None = None   # populated if triage failed for this alert

    @field_validator("confidence_score")
    @classmethod
    def validate_confidence(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError(f"confidence_score must be between 0 and 100, got {v}")
        return v


class TriageReport(BaseModel):
    """Full triage session — one result per alert."""

    total: int
    true_positives: int
    false_positives: int
    needs_review: int
    results: list[TriageResult]
    provider: str
