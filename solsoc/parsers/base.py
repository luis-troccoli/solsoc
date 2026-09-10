from __future__ import annotations

from abc import ABC, abstractmethod

from solsoc.triage.models import Alert


class BaseParser(ABC):
    """Base class for all input parsers."""

    @abstractmethod
    def parse(self, content: str) -> list[Alert]:
        """Parse raw content string into a list of normalized Alerts."""
        ...
