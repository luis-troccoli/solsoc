from __future__ import annotations
from solsoc.llm.base import LLMProvider
from solsoc.triage.models import Alert, TriageResult
from solsoc.triage.prompt import SYSTEM_PROMPT, build_user_prompt


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, api_key: str, model: str = "gpt-4o-mini"):
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.model = model

    def triage(self, alert: Alert) -> TriageResult:
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=512,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(alert)},
                ],
            )
            raw_text = response.choices[0].message.content or ""
            return self._parse_response(alert, raw_text)
        except Exception as exc:
            return TriageResult(
                alert_id=alert.id,
                alert_title=alert.title,
                verdict="NEEDS_REVIEW",
                severity="MEDIUM",
                reason="OpenAI API call failed — review manually.",
                recommended_action="Check your OPENAI_API_KEY and retry.",
                confidence_score=0,
                provider=self.name,
                error=str(exc),
            )
