from __future__ import annotations
from solsoc.llm.base import LLMProvider
from solsoc.triage.models import Alert, TriageResult
from solsoc.triage.prompt import SYSTEM_PROMPT, build_user_prompt


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def triage(self, alert: Alert) -> TriageResult:
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": build_user_prompt(alert)}],
            )
            raw_text = message.content[0].text
            return self._parse_response(alert, raw_text)
        except Exception as exc:
            return TriageResult(
                alert_id=alert.id,
                alert_title=alert.title,
                verdict="NEEDS_REVIEW",
                severity="MEDIUM",
                reason="Anthropic API call failed — review manually.",
                recommended_action="Check your ANTHROPIC_API_KEY and retry.",
                confidence_score=0,
                provider=self.name,
                error=str(exc),
            )
