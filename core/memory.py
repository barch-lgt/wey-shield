"""
Wey Shield — Memory Layer
Supabase-backed persistence. Every scan stored. Every interaction logged.
This is the foundation of Wey Shield's long-term learning.
"""

import json
import logging
import os
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional

from supabase import create_client, Client

from core.models import (
    ScanJob, ScanResult, TrainingRecord,
    AuthRecord, ScanStatus
)

logger = logging.getLogger("wey_shield.memory")


class ShieldMemory:
    """
    Persistent memory for Wey Shield.

    Two layers:
    1. Operational — jobs, results, auth records (current state)
    2. Training archive — immutable record of every scan ever run
       This is what lets Wey Shield grow smarter over time.
    """

    def __init__(self):
        self.client: Optional[Client] = None

    async def connect(self):
        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_SERVICE_KEY"]
        self.client = create_client(url, key)
        logger.info("✅ Supabase connected.")

    # ------------------------------------------------------------------ #
    #  Scan Jobs                                                           #
    # ------------------------------------------------------------------ #

    async def save_job(self, job: ScanJob):
        data = {
            "id": job.id,
            "client_id": job.client_id,
            "targets": job.targets,
            "scan_type": job.scan_type,
            "language": job.language,
            "status": job.status.value,
            "scope_token": job.scope_token,
            "created_at": job.created_at.isoformat(),
            "authorisation_id": job.authorisation_id,
            "error": job.error,
        }
        self.client.table("scan_jobs").upsert(data).execute()

    async def get_job(self, job_id: str) -> ScanJob:
        res = (
            self.client.table("scan_jobs")
            .select("*")
            .eq("id", job_id)
            .single()
            .execute()
        )
        d = res.data
        return ScanJob(
            id=d["id"],
            client_id=d["client_id"],
            targets=d["targets"],
            scan_type=d["scan_type"],
            language=d["language"],
            status=ScanStatus(d["status"]),
            created_at=datetime.fromisoformat(d["created_at"]),
            authorisation_id=d["authorisation_id"],
            error=d.get("error"),
        )

    # ------------------------------------------------------------------ #
    #  Results                                                             #
    # ------------------------------------------------------------------ #

    async def save_result(self, result: ScanResult):
        data = {
    "job_id": result.job_id,
    "recon_data": asdict(result.recon),
    "vuln_data": asdict(result.vulnerabilities),
    "ai_summary": asdict(result.ai_summary),
    "completed_at": result.completed_at.isoformat(),
}
        self.client.table("scan_results").upsert(data).execute()

    async def get_result(self, job_id: str) -> Optional[ScanResult]:
        res = (
            self.client.table("scan_results")
            .select("*")
            .eq("job_id", job_id)
            .single()
            .execute()
        )
        return res.data  # Return raw dict — deserialise as needed

    # ------------------------------------------------------------------ #
    #  Step logging (for debugging + training)                             #
    # ------------------------------------------------------------------ #

    async def log_step(self, job_id: str, step: str, data: any):
        """Log every pipeline step. Invaluable for debugging and training."""
        self.client.table("scan_steps").insert({
            "id": str(uuid.uuid4()),
            "job_id": job_id,
            "step": step,
            "data": asdict(data) if hasattr(data, "__dataclass_fields__") else data,
            "logged_at": datetime.now(timezone.utc).isoformat(),
        }).execute()

    # ------------------------------------------------------------------ #
    #  Training archive — the self-improvement engine                     #
    # ------------------------------------------------------------------ #

async def archive_for_training(self, job: ScanJob, result: ScanResult):
        import hashlib
        anon_client = hashlib.sha256(
            f"{job.client_id}:training_salt".encode()
        ).hexdigest()[:16]

        record = {
            "id": str(uuid.uuid4()),
            "job_id": job.id,
            "client_id_anon": anon_client,
            "language": job.language,
            "scan_type": job.scan_type,
            "targets_count": len(job.targets),
            "raw_scan_payload": asdict(result.recon),
            "ai_output": asdict(result.ai_summary),
            "ai_prompt_version": result.ai_summary.prompt_version,
            "finding_count": len(result.vulnerabilities.findings),
            "critical_count": result.vulnerabilities.critical_count(),
            "risk_score": result.ai_summary.risk_score,
            "model_used": result.ai_summary.model_used,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "client_feedback_score": None,
            "false_positives": [],
            "outcome_label": None,
        }
        self.client.table("training_archive").insert(record).execute()
        logger.info(f"📚 Training record archived for job {job.id}")
    async def submit_feedback(
        self,
        job_id: str,
        score: int,
        false_positives: list[str] = None,
        notes: str = None,
    ):
        """
        Client submits feedback on a scan report.
        This is gold — supervised signal for future training.
        """
        self.client.table("training_archive").update({
            "client_feedback_score": score,
            "false_positives_flagged": false_positives or [],
            "improvement_notes": notes,
            "outcome_label": "high_quality" if score >= 4 else "needs_review",
        }).eq("job_id", job_id).execute()
        logger.info(f"📝 Feedback recorded for job {job_id}: score={score}")

    async def get_training_stats(self) -> dict:
        """How much has Wey Shield learned so far."""
        res = self.client.table("training_archive").select("*").execute()
        records = res.data or []
        return {
            "total_scans": len(records),
            "languages_seen": list(set(r["language"] for r in records)),
            "avg_risk_score": (
                sum(r["risk_score"] for r in records) / len(records)
                if records else 0
            ),
            "feedback_collected": sum(
                1 for r in records if r.get("client_feedback_score")
            ),
            "high_quality_reports": sum(
                1 for r in records if r.get("outcome_label") == "high_quality"
            ),
        }
