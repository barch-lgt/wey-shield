"""
Wey Shield — AI Interpreter
Multilingual security report generation via Groq.
Prompt versioning built in — every version tracked for training.
Trainable: bump PROMPT_VERSION when you improve the prompt,
the training archive records which version produced each report
so you can compare quality over time.
"""

import json
import logging
import os

from groq import AsyncGroq

from core.models import (
    ReconData, VulnData, DragonResult, ChaosResult, AIInterpretation
)

logger = logging.getLogger("wey_shield.ai")

# Bump this every time you change the system prompt.
# The training archive stores this — lets you A/B compare prompt quality.
PROMPT_VERSION = "v1.2"

MODEL = "llama-3.3-70b-versatile"

# Supported languages — add codes as Wey Shield expands across Africa
LANGUAGES = {
    "en":   "English",
    "am":   "Amharic",       # Ethiopia — primary market
    "om":   "Oromo",         # Ethiopia — Oromia region (Jimma, Adama)
    "ti":   "Tigrinya",      # Ethiopia / Eritrea
    "so":   "Somali",        # Horn of Africa
    "sw":   "Swahili",       # East Africa
    "ar":   "Arabic",        # North Africa / Middle East
    "fr":   "French",        # West Africa / francophone
    "pt":   "Portuguese",    # Mozambique / Angola
    "ha":   "Hausa",         # Nigeria, Niger, Ghana
    "auto": "English",       # fallback
}


class ShieldAI:

    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = AsyncGroq(api_key=api_key) if api_key else None
        self.model = MODEL
        if not self.client:
            logger.warning("⚠️  GROQ_API_KEY not set — AI in mock mode.")

    async def load(self):
        if self.client:
            logger.info(f"✅ ShieldAI ready — model: {self.model}, prompt: {PROMPT_VERSION}")

    async def detect_language(self, requested: str, client_id: str) -> str:
        """Resolve language code. Future: pull per-client preference from Supabase."""
        return requested if requested in LANGUAGES else "en"

    async def interpret(
        self,
        recon: ReconData,
        vulnerabilities: VulnData,
        dragon: DragonResult,
        chaos: ChaosResult,
        language: str,
        client_id: str,
    ) -> AIInterpretation:
        """
        Generate a multilingual security report.
        - executive_summary, top_risks, remediation_plan → client's language
        - technical_detail → always English (dev teams need this)
        """
        if not self.client:
            return self._mock(language)

        target_lang = LANGUAGES.get(language, "English")
        context = self._build_context(recon, vulnerabilities, dragon, chaos)

        system_prompt = f"""You are Wey Shield, an elite multilingual cybersecurity AI built in Ethiopia for African enterprises.

Analyze the scan data and produce a structured JSON security report.

STRICT LANGUAGE RULES:
- "executive_summary": MUST be in {target_lang}. Plain language. Non-technical. A business owner must understand it.
- "top_risks": MUST be in {target_lang}
- "remediation_plan" action fields: MUST be in {target_lang}
- "technical_detail": ALWAYS in English. This is for developers and security engineers.

OUTPUT: Valid JSON ONLY. No markdown. No preamble. No explanation outside the JSON.

JSON Schema:
{{
  "executive_summary": "plain-language overview in {target_lang}",
  "risk_score": 0-100,
  "top_risks": ["risk in {target_lang}", "risk in {target_lang}"],
  "remediation_plan": [
    {{"priority": 1, "action": "in {target_lang}", "effort": "low|medium|high", "impact": "low|medium|high"}}
  ],
  "technical_detail": "full technical breakdown always in English",
  "confidence_note": "any caveats about coverage or potential false positives"
}}"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(context, default=str)},
                ],
                response_format={"type": "json_object"},
                temperature=0.15,
                max_tokens=2000,
            )
            data = json.loads(response.choices[0].message.content)
            tokens = getattr(response.usage, "total_tokens", 0)

            return AIInterpretation(
                language=language,
                executive_summary=data.get("executive_summary", ""),
                risk_score=int(data.get("risk_score", 0)),
                top_risks=data.get("top_risks", []),
                remediation_plan=data.get("remediation_plan", []),
                technical_detail=data.get("technical_detail", ""),
                model_used=self.model,
                prompt_version=PROMPT_VERSION,
                tokens_used=tokens,
            )

        except Exception as e:
            logger.error(f"❌ AI failed: {e}")
            return self._mock(language)

    def _build_context(self, recon, vulns, dragon, chaos) -> dict:
        """Lean context — only what the model needs, nothing extra."""
        return {
            "targets": recon.targets,
            "open_ports": recon.open_ports,
            "technologies": recon.technologies,
            "subdomains_found": len(recon.subdomains),
            "environment": dragon.system_type.value,
            "environment_notes": dragon.environment_notes,
            "vulnerabilities": [
                {
                    "name": f.name,
                    "severity": f.severity.value,
                    "target": f.target,
                    "cve": f.cve,
                    "dragon_confirmed": f.id in dragon.confirmed_critical,
                }
                for f in vulns.findings
            ],
            "counts": {
                s.value: sum(1 for f in vulns.findings if f.severity == s)
                for s in ["critical", "high", "medium", "low"]
            },
            "dragon_confirmed_count": len(dragon.confirmed_critical),
            "chaos_breaking_point_rps": chaos.breaking_point_rps,
            "chaos_status": chaos.status,
        }

    def _mock(self, language: str) -> AIInterpretation:
        return AIInterpretation(
            language=language,
            executive_summary="[Mock] AI offline. Configure GROQ_API_KEY.",
            risk_score=0,
            top_risks=[],
            remediation_plan=[],
            technical_detail="No API key.",
            model_used="mock",
            prompt_version=PROMPT_VERSION,
            tokens_used=0,
        )
