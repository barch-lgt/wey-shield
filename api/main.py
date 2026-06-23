"""
Wey Shield — FastAPI Entry Point
REST API surface. Thin layer — all logic lives in orchestrator.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from core.orchestrator import WeyShieldOrchestrator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wey_shield.api")

orchestrator = WeyShieldOrchestrator()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await orchestrator.start()
    yield


app = FastAPI(
    title="Wey Shield API",
    description="AI-powered security penetration testing — built in Ethiopia.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Models ─────────────────────────────────────────────── #

class ScanRequest(BaseModel):
    targets: list[str]
    scan_type: str = "standard"
    language: str = "en"
    authorisation_token: str = None

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v):
        allowed = ["quick", "standard", "deep"]
        if v not in allowed:
            raise ValueError(f"scan_type must be one of {allowed}")
        return v

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, v):
        if not v or len(v) > 10:
            raise ValueError("Provide 1–10 targets per scan.")
        return v


class FeedbackRequest(BaseModel):
    score: int           # 1–5
    false_positives: list[str] = []
    notes: str = None


class AuthVerifyRequest(BaseModel):
    target: str
    method: str = "dns_txt_record"


# ── Health ────────────────────────────────────────────────────────────────── #

@app.get("/health")
async def health():
    """UptimeRobot pings this to keep Render warm."""
    return {"status": "ok", "service": "wey-shield"}


@app.get("/")
async def root():
    return {
        "service": "Wey Shield",
        "tagline": "AI security penetration testing — built in Ethiopia.",
        "docs": "/docs",
    }


# ── Auth / Verification ───────────────────────────────────────────────────── #

@app.post("/api/v1/auth/challenge")
async def get_auth_challenge(
    body: AuthVerifyRequest,
    x_client_id: str = Header(...),
):
    """
    Step 1 of target verification.
    Returns a DNS TXT record or HTTP file challenge for the client to set.
    """
    challenge = await orchestrator.auth_gate.initiate_verification(
        client_id=x_client_id,
        target=body.target,
        method=body.method,
    )
    return challenge


@app.post("/api/v1/auth/confirm")
async def confirm_auth(
    body: AuthVerifyRequest,
    x_client_id: str = Header(...),
    x_auth_token: str = Header(...),
):
    """Step 2 — client has set the challenge, we verify and record ownership."""
    auth = await orchestrator.auth_gate.verify(
        client_id=x_client_id,
        targets=[body.target],
        token=x_auth_token,
    )
    return {"approved": auth.approved, "reason": auth.reason}


# ── Scans ─────────────────────────────────────────────────────────────────── #

@app.post("/api/v1/scan", status_code=202)
async def submit_scan(
    body: ScanRequest,
    x_client_id: str = Header(...),
):
    """Submit a scan job. Returns immediately with job_id."""
    try:
        job = await orchestrator.submit_scan(
            client_id=x_client_id,
            targets=body.targets,
            scan_type=body.scan_type,
            language=body.language,
            authorisation_token=body.authorisation_token,
        )
        return {
            "job_id": job.id,
            "status": job.status.value,
            "message": "Scan queued. The Dragon is patient.",
            "poll_url": f"/api/v1/scan/{job.id}",
        }
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


@app.get("/api/v1/scan/{job_id}")
async def get_scan_status(job_id: str, x_client_id: str = Header(...)):
    """Poll scan status."""
    try:
        job = await orchestrator.get_job(job_id, x_client_id)
        return {
            "job_id": job.id,
            "status": job.status.value,
            "targets": job.targets,
            "language": job.language,
            "created_at": job.created_at.isoformat(),
            "error": job.error,
        }
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception:
        raise HTTPException(status_code=404, detail="Job not found.")


@app.get("/api/v1/scan/{job_id}/results")
async def get_scan_results(job_id: str, x_client_id: str = Header(...)):
    """Fetch full results. Only available when status=complete."""
    try:
        result = await orchestrator.get_results(job_id, x_client_id)
        if not result:
            raise HTTPException(status_code=202, detail="Scan not yet complete.")
        return result
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


# ── Feedback (Training Signal) ────────────────────────────────────────────── #

@app.post("/api/v1/scan/{job_id}/feedback")
async def submit_feedback(
    job_id: str,
    body: FeedbackRequest,
    x_client_id: str = Header(...),
):
    """
    Client rates the scan report quality (1–5).
    This feeds directly into the training archive —
    the most valuable signal for improving Wey Shield's AI.
    """
    if not 1 <= body.score <= 5:
        raise HTTPException(status_code=400, detail="Score must be 1–5.")
    try:
        await orchestrator.get_job(job_id, x_client_id)  # ownership check
        await orchestrator.memory.submit_feedback(
            job_id=job_id,
            score=body.score,
            false_positives=body.false_positives,
            notes=body.notes,
        )
        return {"message": "Feedback recorded. Thank you — this trains Wey Shield."}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))


# ── Training Stats (internal) ─────────────────────────────────────────────── #

@app.get("/api/v1/internal/training-stats")
async def training_stats(x_internal_key: str = Header(...)):
    """Internal endpoint — view training data accumulation."""
    import os
    if x_internal_key != os.environ.get("INTERNAL_API_KEY", ""):
        raise HTTPException(status_code=403, detail="Not authorised.")
    stats = await orchestrator.memory.get_training_stats()
    return stats


# ── Error handlers ────────────────────────────────────────────────────────── #

@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal error. Our team has been notified."},
    )
