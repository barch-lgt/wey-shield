"""
Wey Shield — Unified Data Models
Merged from base + Qwen additions. Single source of truth.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class ScanType(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CONTINUOUS = "continuous"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SystemType(str, Enum):
    """Target OS/environment — detected during profiling phase."""
    LINUX = "linux"
    WINDOWS = "windows"
    CLOUD_AWS = "aws"
    CLOUD_GCP = "gcp"
    CLOUD_AZURE = "azure"
    IOT = "iot"
    WEB = "web"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    id: str
    target: str
    name: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    template_id: Optional[str] = None
    # Self-improvement fields
    ai_confidence: Optional[float] = None
    false_positive_flag: bool = False
    human_verified: bool = False


@dataclass
class TargetProfile:
    """Result of Universal Profiler — shapes the entire scan strategy."""
    target: str
    system_type: SystemType
    open_ports: list[int]
    os_guess: Optional[str]
    services: dict[str, str]      # port → service name
    technologies: list[str]
    raw_nmap: str = ""


@dataclass
class ReconData:
    targets: list[str]
    open_ports: dict[str, list[int]]
    services: dict[str, dict]
    subdomains: list[str]
    http_headers: dict[str, dict]
    technologies: dict[str, list[str]]
    profiles: dict[str, TargetProfile] = field(default_factory=dict)
    raw_output: dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnData:
    findings: list[Finding]
    scan_duration_seconds: float
    templates_run: int
    targets_scanned: list[str]
    raw_output: dict[str, Any] = field(default_factory=dict)

    def by_severity(self) -> dict:
        result = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)


@dataclass
class DragonResult:
    """
    Patient Dragon — adaptive stealth probe results.
    Verifies whether high-severity findings are genuinely exploitable.
    This is VERIFICATION not exploitation — confirms exposure, never persists.
    """
    target: str
    system_type: SystemType
    probes: list[dict]            # Each probe: {vector, status, impact, evidence}
    confirmed_critical: list[str] # Finding IDs confirmed exploitable
    environment_notes: str        # What the dragon learned about this environment


@dataclass
class ChaosResult:
    """Micro-Chaos stress test — finds breaking points under load."""
    target: str
    breaking_point_rps: Optional[int]
    status: str                   # resilient / degraded / crashed
    latency_p99_ms: Optional[float]
    error_rate_at_peak: Optional[float]
    method: str


@dataclass
class AIInterpretation:
    language: str
    executive_summary: str
    risk_score: int               # 0-100
    top_risks: list[str]
    remediation_plan: list[dict]
    technical_detail: str
    model_used: str
    prompt_version: str
    tokens_used: int
    feedback_score: Optional[int] = None
    improvement_notes: Optional[str] = None


@dataclass
class ScanJob:
    id: str
    client_id: str
    targets: list[str]
    scan_type: str
    language: str
    status: ScanStatus
    created_at: datetime
    authorisation_id: str
    scope_token: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


@dataclass
class ScanResult:
    job_id: str
    profiles: dict[str, TargetProfile]
    recon: ReconData
    vulnerabilities: VulnData
    dragon: DragonResult
    chaos: ChaosResult
    ai_summary: AIInterpretation
    completed_at: datetime
    pdf_report_url: Optional[str] = None


@dataclass
class AuthRecord:
    id: str
    client_id: str
    targets: list[str]
    approved: bool
    reason: Optional[str]
    approved_at: Optional[datetime]
    expires_at: Optional[datetime]


@dataclass
class TrainingRecord:
    """
    Immutable record of every scan. The flywheel.
    Every problem Wey Shield solves makes it smarter.
    Enough of these and it trains its own model.
    """
    id: str
    job_id: str
    client_id_anon: str
    language: str
    scan_type: str
    system_environment: str
    raw_scan_payload: dict        # Everything: recon, vulns, dragon, chaos
    ai_prompt_version: str
    ai_output: dict
    created_at: datetime
    client_feedback_score: Optional[int] = None
    false_positives: Optional[list] = None
    outcome_label: Optional[str] = None   # 'high_quality' | 'needs_review'
