"""
Wey Shield — Training Data Exporter
Prepares the training archive for model fine-tuning.

The long game:
  Scan 1       → generic Groq model interprets results
  Scan 100     → patterns emerging, prompt getting refined
  Scan 1000    → enough labelled data to fine-tune a small security LLM
  Scan 10,000  → Wey Shield's own model, trained on African enterprise data
                 in Amharic, Oromo, English — a moat nobody else can build

This module handles the export step: pulls training records,
formats them for fine-tuning (OpenAI JSONL format, compatible with
most fine-tuning APIs), filters by quality label.
"""

import json
import logging
import os
from datetime import datetime

from supabase import create_client, Client

logger = logging.getLogger("wey_shield.training")


class TrainingExporter:

    def __init__(self):
        self.client: Client = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_KEY"],
        )

    def export_fine_tune_dataset(
        self,
        output_path: str = "training/dataset.jsonl",
        min_feedback_score: int = 4,
        language_filter: str = None,
    ) -> int:
        """
        Export high-quality training records as JSONL for fine-tuning.
        Filters to only 'high_quality' labelled records with good feedback.

        Format: OpenAI fine-tune JSONL — works with most fine-tune APIs.
        Each line: {"messages": [{"role": "system", ...}, {"role": "user", ...}, {"role": "assistant", ...}]}
        """
        query = (
            self.client.table("training_archive")
            .select("*")
            .eq("outcome_label", "high_quality")
            .gte("client_feedback_score", min_feedback_score)
        )
        if language_filter:
            query = query.eq("language", language_filter)

        records = query.execute().data or []
        logger.info(f"Exporting {len(records)} training records...")

        exported = 0
        with open(output_path, "w") as f:
            for record in records:
                entry = self._format_for_finetune(record)
                if entry:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                    exported += 1

        logger.info(f"Exported {exported} records to {output_path}")
        return exported

    def _format_for_finetune(self, record: dict) -> dict:
        """
        Convert a training record into a fine-tune example.
        Input: raw scan data. Output: the AI interpretation that got high feedback.
        """
        try:
            payload = record.get("raw_scan_payload", {})
            ai_output = record.get("ai_output", {})
            language = record.get("language", "en")
            environment = record.get("system_environment", "unknown")

            system_msg = (
                f"You are Wey Shield, an elite multilingual cybersecurity AI. "
                f"Analyze scan data and produce structured JSON security reports. "
                f"Respond in the language specified by the user."
            )

            user_msg = json.dumps({
                "language": language,
                "environment": environment,
                "scan_data": payload,
            }, ensure_ascii=False)

            assistant_msg = json.dumps(ai_output, ensure_ascii=False)

            return {
                "messages": [
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                    {"role": "assistant", "content": assistant_msg},
                ]
            }
        except Exception as e:
            logger.warning(f"Skipping malformed record: {e}")
            return None

    def get_stats(self) -> dict:
        """How much training data has accumulated."""
        all_records = self.client.table("training_archive").select(
            "language, system_environment, outcome_label, client_feedback_score"
        ).execute().data or []

        return {
            "total_records": len(all_records),
            "high_quality": sum(1 for r in all_records if r.get("outcome_label") == "high_quality"),
            "needs_review": sum(1 for r in all_records if r.get("outcome_label") == "needs_review"),
            "with_feedback": sum(1 for r in all_records if r.get("client_feedback_score")),
            "languages": list(set(r["language"] for r in all_records if r.get("language"))),
            "environments": list(set(r["system_environment"] for r in all_records if r.get("system_environment"))),
            "ready_for_finetune": sum(
                1 for r in all_records
                if r.get("outcome_label") == "high_quality"
                and (r.get("client_feedback_score") or 0) >= 4
            ),
            "milestone_progress": {
                "current": len(all_records),
                "next_milestone": _next_milestone(len(all_records)),
                "note": _milestone_note(len(all_records)),
            }
        }


def _next_milestone(count: int) -> int:
    for m in [100, 500, 1000, 5000, 10000]:
        if count < m:
            return m
    return count + 10000


def _milestone_note(count: int) -> str:
    if count < 100:
        return "Building foundation. Every scan counts."
    if count < 500:
        return "Patterns emerging. Prompt refinement phase."
    if count < 1000:
        return "Approaching fine-tune threshold. Quality improving."
    if count < 5000:
        return "Fine-tune viable. Consider training a small security LLM."
    if count < 10000:
        return "Strong corpus. Wey Shield's own model is within reach."
    return "Model training overdue. You have a world-class dataset."
