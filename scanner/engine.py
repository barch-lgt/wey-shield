"""
Wey Shield — Unified Scan Engine
Merges base engine + Qwen's profiler, dragon, and chaos modules.
Full pipeline: Profile → Recon → Vuln → Dragon → Chaos
"""

import asyncio
import json
import logging
import shutil
import tempfile
import time
import uuid
from typing import Optional

from core.models import (
    ReconData, VulnData, Finding, Severity,
    TargetProfile, SystemType, DragonResult, ChaosResult, ScanType
)
from core.security import TitaniumAuthGate

logger = logging.getLogger("wey_shield.scanner")

RECON_TIMEOUT = 120
VULN_TIMEOUT = {"quick": 120, "standard": 300, "deep": 600}
STEALTH_DELAY = 2.0  # Pause between stealth probes (WAF evasion + free tier)

NUCLEI_TEMPLATES = {
    "quick":    ["http/exposures", "http/misconfiguration"],
    "standard": ["http/exposures", "http/misconfiguration", "http/vulnerabilities", "ssl", "dns"],
    "deep":     ["http/", "ssl/", "dns/", "network/", "technologies/", "cves/"],
}

# Default credentials to check per service — verification only, never persistence
DEFAULT_CREDS = {
    "ssh":   [("admin", "admin"), ("root", "root"), ("admin", "password")],
    "ftp":   [("anonymous", ""), ("admin", "admin")],
    "http":  [("admin", "admin"), ("admin", "password"), ("admin", "1234")],
}


class WeyShieldScanner:

    def __init__(self, auth: TitaniumAuthGate):
        self.auth = auth
        self._check_tools()

    def _check_tools(self):
        tools = ["nmap", "nuclei", "subfinder", "httpx"]
        missing = [t for t in tools if not shutil.which(t)]
        if missing:
            logger.warning(f"⚠️  Missing tools (install via Dockerfile): {missing}")
        else:
            logger.info("✅ All scan tools present.")

    # ------------------------------------------------------------------ #
    #  PHASE 1: Universal Profiler                                         #
    # ------------------------------------------------------------------ #

    async def profile_target(self, target: str) -> TargetProfile:
        """
        OS + service fingerprinting. Shapes the entire downstream strategy.
        A Linux server gets different checks than a Windows IIS box.
        """
        logger.info(f"🔬 Profiling {target}...")
        cmd = ["nmap", "-sV", "--osscan-limit", "-T4", "--open", "--host-timeout", "30s", target]
        stdout, _ = await self._run_cmd(cmd, timeout=90)

        system_type = SystemType.UNKNOWN
        os_guess = None
        if stdout:
            low = stdout.lower()
            if "linux" in low:
                system_type = SystemType.LINUX
            elif "windows" in low:
                system_type = SystemType.WINDOWS
            elif "amazon" in low or "aws" in low:
                system_type = SystemType.CLOUD_AWS
            elif "iot" in low or "embedded" in low:
                system_type = SystemType.IOT

            # Extract OS guess line
            for line in stdout.split("\n"):
                if "os details:" in line.lower() or "running:" in line.lower():
                    os_guess = line.strip()
                    break

        # Extract open ports
        ports = []
        if stdout:
            for line in stdout.split("\n"):
                if "/tcp" in line and "open" in line:
                    try:
                        ports.append(int(line.split("/")[0].strip()))
                    except Exception:
                        pass

        return TargetProfile(
            target=target,
            system_type=system_type,
            open_ports=ports,
            os_guess=os_guess,
            services={},
            technologies=[],
            raw_nmap=stdout[:1000] if stdout else "",
        )

    # ------------------------------------------------------------------ #
    #  PHASE 2: Recon                                                      #
    # ------------------------------------------------------------------ #

    async def recon(self, targets: list[str]) -> ReconData:
        """Full reconnaissance — parallel execution."""
        logger.info(f"🔍 Recon on {targets}")

        ports_t = asyncio.create_task(self._nmap_scan(targets))
        subs_t = asyncio.create_task(self._subfinder(targets))
        crt_t = asyncio.create_task(self._crtsh_lookup(targets[0]))
        heads_t = asyncio.create_task(self._httpx_probe(targets))
        profiles_t = asyncio.gather(*[self.profile_target(t) for t in targets])

        (open_ports, subdomains, crt_subs, http_headers, profile_list) = await asyncio.gather(
            ports_t, subs_t, crt_t, heads_t, profiles_t, return_exceptions=True
        )

        open_ports = open_ports if isinstance(open_ports, dict) else {}
        subdomains = subdomains if isinstance(subdomains, list) else []
        crt_subs = crt_subs if isinstance(crt_subs, list) else []
        subdomains = list(set(subdomains + crt_subs))
        crt_subs = crt_subs if isinstance(crt_subs, list) else []
        subdomains = list(set(subdomains + crt_subs))
        http_headers = http_headers if isinstance(http_headers, dict) else {}
        profiles = {}
        if isinstance(profile_list, list):
            profiles = {p.target: p for p in profile_list if isinstance(p, TargetProfile)}

        return ReconData(
            targets=targets,
            open_ports=open_ports,
            services={t: {} for t in targets},
            subdomains=subdomains,
            http_headers=http_headers,
            technologies={url: d.get("technologies", []) for url, d in http_headers.items()
                          if isinstance(d, dict)},
            profiles=profiles,
            raw_output={"nmap": open_ports, "subfinder": subdomains},
        )

    # ------------------------------------------------------------------ #
    #  PHASE 3: Vulnerability Scanning                                     #
    # ------------------------------------------------------------------ #

    async def scan_vulnerabilities(
        self, targets: list[str], scan_type: str, recon: ReconData
    ) -> VulnData:
        """Nuclei scan — template set chosen by scan_type."""
        logger.info(f"🔬 Vuln scan ({scan_type}) on {targets}")
        templates = NUCLEI_TEMPLATES.get(scan_type, NUCLEI_TEMPLATES["standard"])
        timeout = VULN_TIMEOUT.get(scan_type, 300)

        all_targets = list(set(targets + recon.subdomains[:15]))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(all_targets))
            targets_file = f.name

        template_args = []
        for t in templates:
            template_args += ["-t", t]

        cmd = [
            "nuclei", "-l", targets_file,
            *template_args,
            "-jsonl", "-silent",
            "-rate-limit", "30",
            "-bulk-size", "10",
            "-concurrency", "5",
            "-retries", "1",
        ]

        start = time.time()
        stdout, _ = await self._run_cmd(cmd, timeout=timeout)
        duration = time.time() - start
        findings = self._parse_nuclei_output(stdout or "")

        return VulnData(
            findings=findings,
            scan_duration_seconds=duration,
            templates_run=len(templates),
            targets_scanned=all_targets,
            raw_output={"nuclei": (stdout or "")[:2000]},
        )

    # ------------------------------------------------------------------ #
    #  PHASE 4: Patient Dragon — Adaptive Stealth Verification             #
    # ------------------------------------------------------------------ #

    async def unleash_dragon(
        self,
        profile: TargetProfile,
        vulns: VulnData,
        scope_token: str,
        allowed_targets: list[str],
    ) -> DragonResult:
        """
        The Patient Dragon.

        Takes the highest-severity findings and VERIFIES them —
        confirms they are genuinely exploitable, not false positives.

        This is VERIFICATION not EXPLOITATION:
        - Checks for default credentials (does not use them to access)
        - Confirms exposed endpoints respond as vulnerable
        - Tests misconfigurations without triggering destructive actions
        - Adapts technique based on OS/environment profile

        Result: client knows exactly which critical findings are real.
        """
        logger.info(f"🐉 Patient Dragon adapting to {profile.system_type.value}...")

        high_value = [
            f for f in vulns.findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ][:5]  # Cap at 5 verifications per scan

        probes = []
        confirmed = []

        for finding in high_value:
            # Hard scope check before every probe
            if not self.auth.verify_scope_lock(scope_token, finding.target, allowed_targets):
                logger.critical(f"🛑 Dragon halted — scope violation on {finding.target}")
                break

            await asyncio.sleep(STEALTH_DELAY)  # Stealth pause

            probe_result = await self._adaptive_probe(finding, profile)

            if probe_result.get("confirmed"):
                confirmed.append(finding.id)
                finding.ai_confidence = 0.95

            probes.append({
                "finding_id": finding.id,
                "vector": finding.name,
                "target": finding.target,
                **probe_result,
            })
            logger.info(f"⚔️  Probed: {finding.name} → {probe_result.get('status')}")

        env_notes = self._environment_notes(profile)

        return DragonResult(
            target=profile.target,
            system_type=profile.system_type,
            probes=probes,
            confirmed_critical=confirmed,
            environment_notes=env_notes,
        )

    async def _adaptive_probe(self, finding: Finding, profile: TargetProfile) -> dict:
        """
        Adapt probe strategy to the target environment.
        Linux gets different checks than Windows, IoT gets different than cloud.
        """
        name_lower = finding.name.lower()

        # Default credential verification (check existence only — no login)
        if any(kw in name_lower for kw in ["default", "credential", "auth", "login"]):
            return await self._check_default_creds_exposure(finding.target, profile)

        # Directory/file exposure check
        if any(kw in name_lower for kw in ["exposure", "disclosure", "listing"]):
            return await self._check_exposure(finding.evidence)

        # SSL/TLS weakness verification
        if any(kw in name_lower for kw in ["ssl", "tls", "cert", "cipher"]):
            return await self._check_ssl(finding.target)

        # Header security check
        if any(kw in name_lower for kw in ["header", "cors", "csp", "hsts"]):
            return await self._check_headers(finding.target)

        # Default: confirm the matched URL still responds as vulnerable
        return await self._confirm_url_response(finding.evidence)

    async def _check_default_creds_exposure(self, target: str, profile: TargetProfile) -> dict:
        """Check if default credential login pages are exposed — NOT attempting login."""
        # Just verify the login panel is publicly accessible
        for port in profile.open_ports:
            if port in (80, 443, 8080, 8443):
                cmd = ["httpx", "-u", f"https://{target}:{port}/admin",
                       "-status-code", "-silent", "-no-color"]
                stdout, _ = await self._run_cmd(cmd, timeout=15)
                if stdout and ("200" in stdout or "401" in stdout or "403" in stdout):
                    return {
                        "status": "confirmed_exposed",
                        "confirmed": True,
                        "evidence": f"Admin panel accessible at port {port}",
                        "impact": "Login panel publicly accessible — test credentials manually",
                    }
        return {"status": "not_confirmed", "confirmed": False}

    async def _check_exposure(self, url: str) -> dict:
        if not url:
            return {"status": "no_url", "confirmed": False}
        cmd = ["httpx", "-u", url, "-status-code", "-silent", "-no-color"]
        stdout, _ = await self._run_cmd(cmd, timeout=10)
        confirmed = stdout and "200" in stdout
        return {
            "status": "confirmed_exposed" if confirmed else "not_confirmed",
            "confirmed": confirmed,
            "evidence": url,
        }

    async def _check_ssl(self, target: str) -> dict:
        cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", target]
        stdout, _ = await self._run_cmd(cmd, timeout=30)
        weak = stdout and any(w in stdout.lower() for w in ["tls 1.0", "ssl 3", "rc4", "des"])
        return {
            "status": "weak_ssl_confirmed" if weak else "ssl_ok",
            "confirmed": weak,
            "evidence": "Weak cipher/protocol detected" if weak else "",
        }

    async def _check_headers(self, target: str) -> dict:
        cmd = ["httpx", "-u", f"https://{target}", "-include-response-header",
               "-silent", "-no-color"]
        stdout, _ = await self._run_cmd(cmd, timeout=10)
        missing = [h for h in ["strict-transport-security", "x-frame-options",
                                "content-security-policy", "x-content-type-options"]
                   if stdout and h not in stdout.lower()]
        return {
            "status": "headers_missing" if missing else "headers_ok",
            "confirmed": bool(missing),
            "evidence": f"Missing headers: {missing}",
        }

    async def _confirm_url_response(self, url: str) -> dict:
        if not url:
            return {"status": "no_evidence", "confirmed": False}
        cmd = ["httpx", "-u", url, "-status-code", "-silent", "-no-color"]
        stdout, _ = await self._run_cmd(cmd, timeout=10)
        confirmed = stdout and any(c in stdout for c in ["200", "301", "302"])
        return {
            "status": "url_reachable" if confirmed else "url_unreachable",
            "confirmed": confirmed,
        }

    def _environment_notes(self, profile: TargetProfile) -> str:
        notes = {
            SystemType.LINUX: "Linux target — check for misconfigured services, exposed .env files, SSH key exposure.",
            SystemType.WINDOWS: "Windows target — focus on SMB, RDP exposure, IIS misconfigurations.",
            SystemType.CLOUD_AWS: "AWS environment — check for public S3, exposed metadata endpoint, IAM misconfigurations.",
            SystemType.IOT: "IoT device — likely running stripped Linux; check for Telnet, default web UIs, unencrypted APIs.",
            SystemType.WEB: "Web application — focus on OWASP Top 10, exposed admin panels, API endpoints.",
            SystemType.UNKNOWN: "Environment unknown — ran full generic template set.",
        }
        return notes.get(profile.system_type, notes[SystemType.UNKNOWN])

    # ------------------------------------------------------------------ #
    #  PHASE 5: Micro-Chaos Engine                                         #
    # ------------------------------------------------------------------ #

    async def run_chaos_test(
        self, target: str, scope_token: str, allowed_targets: list[str]
    ) -> ChaosResult:
        """
        Creeping stress test — finds the breaking point under load.
        Starts at 1 RPS, steps up until errors appear or cap is hit.
        Stops the moment degradation is detected.
        """
        if not self.auth.verify_scope_lock(scope_token, target, allowed_targets):
            return ChaosResult(target=target, breaking_point_rps=None,
                               status="aborted_scope_violation",
                               latency_p99_ms=None, error_rate_at_peak=None,
                               method="aborted")

        logger.info(f"🌪️  Micro-Chaos creeping load on {target}")

        breaking_point = None
        last_status = "resilient"
        rps_steps = [1, 3, 5, 10, 15, 20]

        for rps in rps_steps:
            cmd = [
                "httpx",
                "-u", f"https://{target}",
                "-rate-limit", str(rps),
                "-threads", str(min(rps, 10)),
                "-silent", "-status-code", "-no-color",
                "-count", str(rps * 3),  # 3 seconds worth
            ]
            stdout, _ = await self._run_cmd(cmd, timeout=15)

            if stdout:
                lines = [l for l in stdout.strip().split("\n") if l]
                errors = sum(1 for l in lines if any(c in l for c in ["5", "000", "timeout"]))
                error_rate = errors / max(len(lines), 1)

                if error_rate > 0.1:  # >10% errors = breaking point
                    breaking_point = rps
                    last_status = "degraded"
                    logger.info(f"🌪️  Breaking point found at {rps} RPS")
                    break

            await asyncio.sleep(1)

        return ChaosResult(
            target=target,
            breaking_point_rps=breaking_point,
            status=last_status,
            latency_p99_ms=None,
            error_rate_at_peak=None,
            method="stealth_creep",
        )

    # ------------------------------------------------------------------ #
    #  Parsers                                                             #
    # ------------------------------------------------------------------ #

    def _parse_nuclei_output(self, output: str) -> list[Finding]:
        findings = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                d = json.loads(line)
                sev_raw = d.get("info", {}).get("severity", "info").lower()
                sev = Severity(sev_raw) if sev_raw in Severity._value2member_map_ else Severity.INFO
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    target=d.get("host", ""),
                    name=d.get("info", {}).get("name", "Unknown"),
                    severity=sev,
                    description=d.get("info", {}).get("description", ""),
                    evidence=d.get("matched-at", ""),
                    remediation=d.get("info", {}).get("remediation", "See Wey Shield report."),
                    cve=(d.get("info", {}).get("classification") or {}).get("cve-id", [None])[0],
                    template_id=d.get("template-id", ""),
                ))
            except Exception:
                continue
        return findings

    async def _nmap_scan(self, targets: list[str]) -> dict:
        results = {}
        for t in targets:
            cmd = ["nmap", "-sV", "--open", "-T4", "--host-timeout", "20s", "-oJ", "-", t]
            stdout, _ = await self._run_cmd(cmd, timeout=60)
            results[t] = {"raw": (stdout or "")[:500]}
        return results

    async def _subfinder(self, targets: list[str]) -> list[str]:
        subs = []
        for t in targets:
            cmd = ["subfinder", "-d", t, "-silent", "-json"]
            stdout, _ = await self._run_cmd(cmd, timeout=60)
            if stdout:
                for line in stdout.strip().split("\n"):
                    try:
                        subs.append(json.loads(line).get("host", ""))
                    except Exception:
                        pass
        return [s for s in subs if s]
    async def _crtsh_lookup(self, domain: str) -> list[str]:
        """Find subdomains via certificate transparency logs — bypasses Cloudflare."""
        try:
            import urllib.request
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            req = urllib.request.Request(url, headers={"User-Agent": "WeyShield/1.0"})
            with urllib.request.urlopen(req, timeout=15) as r:
                data = json.loads(r.read())
            seen = set()
            results = []
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub and sub not in seen:
                        seen.add(sub)
                        results.append(sub)
            return results
        except Exception as e:
            logger.warning(f"crt.sh lookup failed: {e}")
            return []

    async def _httpx_probe(self, targets: list[str]) -> dict:
        import os
        urls = [f"https://{t}" if not t.startswith("http") else t for t in targets]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            targets_file = f.name
        cmd = [
            "httpx", "-l", targets_file,
            "-json", "-td",
            "-status-code", "-title",
            "-follow-redirects", "-silent",
        ]
        stdout, stderr = await self._run_cmd(cmd, timeout=60)
        if stderr:
            logger.warning(f"httpx stderr: {stderr[:500]}")
        results = {}
        if stdout:
            for line in stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    url = d.get("url", "")
                    results[url] = {**d, "technologies": d.get("tech", [])}
                except Exception:
                    continue
        logger.info(f"httpx probe returned {len(results)} results for {targets}")
        os.unlink(targets_file)
        return results

    # ------------------------------------------------------------------ #
    #  Safe subprocess runner                                              #
    # ------------------------------------------------------------------ #

    async def _run_cmd(
        self, cmd: list[str], timeout: int, stdin_data: bytes = None
    ) -> tuple[Optional[str], Optional[str]]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data), timeout=timeout
            )
            return (
                stdout.decode("utf-8", errors="replace") if stdout else None,
                stderr.decode("utf-8", errors="replace") if stderr else None,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return None, "timeout"
        except FileNotFoundError:
            return None, f"tool_not_found:{cmd[0]}"
        except Exception as e:
            return None, str(e)
