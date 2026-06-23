"""
Wey Shield — Master Orchestrator
5-phase pipeline: Profile → Recon → Vuln → Dragon → Chaos → AI Report
Every scan archived for future model training.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from core.memory import ShieldMemory
from core.models import ScanJob, ScanStatus, ScanResult
from core.auth_gate import AuthGate
from core.security import TitaniumAuthGate
from scanner.engine import WeyShieldScanner
from ai.interpreter import ShieldAI

logger = logging.getLogger("wey_shield.orchestrator")


class WeyShieldOrchestrator:

    def __init__(self):
        self.memory = ShieldMemory()
        self.auth_gate = AuthGate()
        self.titanium = TitaniumAuthGate()
        self.scanner = WeyShieldScanner(self.titanium)
        self.ai = ShieldAI()
        self._active_jobs: dict[str, asyncio.Task] = {}

    async def start(self):
        await self.memory.connect()
        await self.ai.load()
        logger.info("Shield online. Dragon patient. Titanium locked.")

    async def submit_scan(
        self,
        client_id: str,
        targets: list[str],
        scan_type: str = "standard",
        language: str = "en",
        authorisation_token: str = None,
    ) -> ScanJob:
        auth = await self.auth_gate.verify(
            client_id=client_id, targets=targets, token=authorisation_token,
        )
        if not auth.approved:
            raise PermissionError(f"Scan not authorised: {auth.reason}")

        scope_token = self.titanium.generate_scope_token(client_id, targets)
        language = await self.ai.detect_language(language, client_id)

        job = ScanJob(
            id=str(uuid.uuid4()),
            client_id=client_id,
            targets=targets,
            scan_type=scan_type,
            language=language,
            status=ScanStatus.QUEUED,
            created_at=datetime.now(timezone.utc),
            authorisation_id=auth.id,
            scope_token=scope_token,
        )
        await self.memory.save_job(job)

        task = asyncio.create_task(self._run_pipeline(job))
        self._active_jobs[job.id] = task
        task.add_done_callback(lambda t: self._active_jobs.pop(job.id, None))
        logger.info(f"Job {job.id} queued for {client_id}")
        return job

    async def get_job(self, job_id: str, client_id: str) -> ScanJob:
        job = await self.memory.get_job(job_id)
        if job.client_id != client_id:
            raise PermissionError("Job not owned by this client.")
        return job

    async def get_results(self, job_id: str, client_id: str) -> Optional[ScanResult]:
        job = await self.get_job(job_id, client_id)
        if job.status != ScanStatus.COMPLETE:
            return None
        return await self.memory.get_result(job_id)

    async def _run_pipeline(self, job: ScanJob):
        try:
            await self._set_status(job, ScanStatus.RUNNING)

            # Phase 1: Profile
            profiles = {}
            for target in job.targets:
                profiles[target] = await self.scanner.profile_target(target)
            primary = profiles[job.targets[0]]
            await self.memory.log_step(job.id, "profiling",
                {t: p.system_type.value for t, p in profiles.items()})

            # Phase 2: Recon
            recon = await self.scanner.recon(job.targets)
            recon.profiles = profiles
            await self.memory.log_step(job.id, "recon",
                {"subdomains": len(recon.subdomains)})

            # Phase 3: Vuln scan
            vulns = await self.scanner.scan_vulnerabilities(
                targets=job.targets, scan_type=job.scan_type, recon=recon)
            await self.memory.log_step(job.id, "vuln_scan",
                {"findings": len(vulns.findings), "critical": vulns.critical_count()})

            # Phase 4: Dragon
            dragon = await self.scanner.unleash_dragon(
                profile=primary, vulns=vulns,
                scope_token=job.scope_token, allowed_targets=job.targets)
            await self.memory.log_step(job.id, "dragon",
                {"confirmed": len(dragon.confirmed_critical)})

            # Phase 5: Chaos
            chaos = await self.scanner.run_chaos_test(
                target=job.targets[0],
                scope_token=job.scope_token, allowed_targets=job.targets)
            await self.memory.log_step(job.id, "chaos",
                {"breaking_point": chaos.breaking_point_rps, "status": chaos.status})

            # AI interpretation
            ai_summary = await self.ai.interpret(
                recon=recon, vulnerabilities=vulns,
                dragon=dragon, chaos=chaos,
                language=job.language, client_id=job.client_id)

            result = ScanResult(
                job_id=job.id, profiles=profiles, recon=recon,
                vulnerabilities=vulns, dragon=dragon, chaos=chaos,
                ai_summary=ai_summary, completed_at=datetime.now(timezone.utc),
            )
            await self.memory.save_result(result)
            await self.memory.archive_for_training(job, result)
            await self._set_status(job, ScanStatus.COMPLETE)
            logger.info(f"Job {job.id} complete.")

        except Exception as e:
            logger.error(f"Job {job.id} failed: {e}", exc_info=True)
            await self._set_status(job, ScanStatus.FAILED, error=str(e))

    async def _set_status(self, job: ScanJob, status: ScanStatus, error: str = None):
        job.status = status
        job.error = error
        if status == ScanStatus.RUNNING:
            job.started_at = datetime.now(timezone.utc)
        elif status in (ScanStatus.COMPLETE, ScanStatus.FAILED):
            job.completed_at = datetime.now(timezone.utc)
        await self.memory.save_job(job)
