from __future__ import annotations
from solsoc.llm.base import LLMProvider
from solsoc.triage.models import Alert, TriageResult
from solsoc.triage.prompt import SYSTEM_PROMPT, build_user_prompt


class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self, api_key: str, model: str = "gemini-1.5-flash"):
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name=model,
            system_instruction=SYSTEM_PROMPT,
        )

    def triage(self, alert: Alert) -> TriageResult:
        try:
            response = self.model.generate_content(build_user_prompt(alert))
            raw_text = response.text or ""
            return self._parse_response(alert, raw_text)
        except Exception as exc:
            return TriageResult(
                alert_id=alert.id,
                alert_title=alert.title,
                verdict="NEEDS_REVIEW",
                severity="MEDIUM",
                reason="Gemini API call failed — review manually.",
                recommended_action="Check your GEMINI_API_KEY and retry.",
                confidence_score=0,
                provider=self.name,
                error=str(exc),
            )
