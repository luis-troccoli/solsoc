from __future__ import annotations
from abc import ABC, abstractmethod
from solsoc.triage.models import Alert


class SIEMIntegration(ABC):
    """Base class for all SIEM integrations."""

    name: str = "base"

    @abstractmethod
    def fetch_alerts(self, limit: int = 50) -> list[Alert]:
        """Fetch alerts from the SIEM and return normalized Alert objects."""
        ...
