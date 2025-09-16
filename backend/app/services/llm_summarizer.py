from openai import AsyncOpenAI
from typing import Dict, Any
import logging
from ..core.config import settings

logger = logging.getLogger(__name__)


class LLMSummarizer:
    def __init__(self):
        if settings.openai_api_key:
            self.client = AsyncOpenAI(api_key=settings.openai_api_key)
        else:
            self.client = None
            logger.warning("OpenAI API key not configured. LLM summarization will be disabled.")

    async def generate_swedish_summary(self, analysis_result: Dict[str, Any]) -> str:
        """Generate Swedish summary of analysis results"""

        if not self.client:
            return self._generate_fallback_summary(analysis_result)

        try:
            risk_assessment = analysis_result.get("risk_assessment", {})
            verdict = risk_assessment.get("verdict", "unknown")
            confidence = risk_assessment.get("confidence", 0)
            evidence = risk_assessment.get("evidence", [])

            # Get redirect chain info if available
            steps = analysis_result.get("steps", {})
            http_analysis = steps.get("http_analysis", {})
            redirect_chain = http_analysis.get("redirect_chain", [])

            system_prompt = """Du är FortAI-assistenten. Du får strukturerad analysdata (verdict, confidence, evidence list, redirect chain, cert-summary). Skriv en kort svensk summering (max 4 meningar) med:
1) Verdict (Blockera / Granska / Säker)
2) Confidence i procent
3) Top-3 bevispunkter
4) Rekommenderad åtgärd (konkret)
Använd inte tekniska termer utan förklara enkelt."""

            user_prompt = f"""Analyserad länk: {analysis_result.get('job_id', 'N/A')}, verdict: {verdict}, confidence: {confidence}%, evidence: {evidence[:3]}, redirects: {len(redirect_chain)}
Skriv rekommendation enligt system prompt."""

            response = await self.client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=300,
                temperature=0.3
            )

            return response.choices[0].message.content.strip()

        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            return self._generate_fallback_summary(analysis_result)

    def _generate_fallback_summary(self, analysis_result: Dict[str, Any]) -> str:
        """Generate fallback summary when LLM is not available"""
        risk_assessment = analysis_result.get("risk_assessment", {})
        verdict = risk_assessment.get("verdict", "unknown")
        confidence = risk_assessment.get("confidence", 0)
        evidence = risk_assessment.get("evidence", [])

        verdict_map = {
            "safe": "Säker",
            "suspicious": "Misstänkt",
            "dangerous": "Farlig"
        }

        action_map = {
            "safe": "Länken verkar säker att besöka.",
            "suspicious": "Var försiktig. Granska länken manuellt innan du besöker den.",
            "dangerous": "Blockera denna länk. Den kan vara skadlig eller innehålla bedrägerier."
        }

        swedish_verdict = verdict_map.get(verdict, "Okänd")
        recommended_action = action_map.get(verdict, "Kunde inte bestämma säkerhetsnivå.")

        summary = f"Bedömning: {swedish_verdict}. "
        summary += f"Säkerhetsnivå: {confidence:.0f}%. "

        if evidence:
            summary += f"Viktiga fynd: {', '.join(evidence[:2])}. "

        summary += recommended_action

        return summary