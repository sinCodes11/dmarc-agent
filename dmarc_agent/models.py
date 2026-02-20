"""Shared data contracts between all dmarc-agent modules. Zero logic here."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ── Enums ──────────────────────────────────────────────────────────────────────

class RiskLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class DmarcPolicy(Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class SpfQualifier(Enum):
    PASS = "+"
    FAIL = "-"
    SOFTFAIL = "~"
    NEUTRAL = "?"


class DnsStatus(Enum):
    NOERROR = "NOERROR"
    NXDOMAIN = "NXDOMAIN"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class ReportFormat(Enum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"


# ── DNS Layer ──────────────────────────────────────────────────────────────────

@dataclass
class DnsRecord:
    record_type: str
    value: str
    ttl: int


@dataclass
class DnsResponse:
    domain: str
    record_type: str
    status: DnsStatus
    records: list = field(default_factory=list)  # list[DnsRecord]
    resolver_used: str = ""
    response_time_ms: float = 0.0
    cache_hit: bool = False
    queried_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class CacheEntry:
    key: str
    response: DnsResponse
    expires_at: datetime


# ── SPF Layer ──────────────────────────────────────────────────────────────────

@dataclass
class SpfMechanism:
    order: int
    raw: str
    mtype: str
    qualifier: SpfQualifier
    argument: Optional[str]
    lookup_count: int = 0


@dataclass
class SpfLookupBreakdown:
    mechanism: str
    direct_lookups: int
    recursive_lookups: int
    subtotal: int
    chain: list = field(default_factory=list)  # list[str]


@dataclass
class SpfMisconfiguration:
    id: str
    name: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    remediation: str


@dataclass
class SpfResult:
    domain: str
    present: bool
    raw_record: Optional[str]
    mechanisms: list = field(default_factory=list)      # list[SpfMechanism]
    all_qualifier: Optional[SpfQualifier] = None
    total_lookups: int = 0
    lookup_limit_status: str = "unknown"                # within_limit / at_limit / exceeded
    lookup_breakdown: list = field(default_factory=list)  # list[SpfLookupBreakdown]
    misconfigurations: list = field(default_factory=list) # list[SpfMisconfiguration]
    risk_contribution: str = "unknown"
    recommended_record: Optional[str] = None
    duplicate_records: bool = False
    warnings: list = field(default_factory=list)        # list[str]


# ── DKIM Layer ─────────────────────────────────────────────────────────────────

@dataclass
class DkimResult:
    domain: str
    selector: Optional[str]
    checked: bool
    present: bool
    raw_record: Optional[str]
    risk_contribution: str = "unknown"


# ── DMARC Layer ────────────────────────────────────────────────────────────────

@dataclass
class DmarcResult:
    domain: str
    present: bool
    raw_record: Optional[str]
    policy: Optional[DmarcPolicy] = None
    subdomain_policy: Optional[DmarcPolicy] = None
    rua: list = field(default_factory=list)  # list[str]
    ruf: list = field(default_factory=list)  # list[str]
    fo: Optional[str] = None
    pct: int = 100
    aspf: str = "r"
    adkim: str = "r"
    issues: list = field(default_factory=list)  # list[str]
    risk_contribution: str = "unknown"
    recommended_record: Optional[str] = None
    progression_stage: int = 0  # 0=absent, 1-4 per staged rollout


# ── Risk Layer ─────────────────────────────────────────────────────────────────

@dataclass
class Issue:
    id: str
    component: str   # "SPF", "DKIM", "DMARC"
    severity: str    # "critical", "high", "medium", "low"
    title: str
    description: str
    remediation: str
    priority: int    # 1 = highest


@dataclass
class RiskAssessment:
    level: RiskLevel
    justification: list  # list[str]
    issues: list         # list[Issue]


# ── Record Generation ──────────────────────────────────────────────────────────

@dataclass
class DnsRecordSpec:
    """A copy-paste-ready DNS record for remediation."""
    record_type: str
    name: str
    value: str
    purpose: str
    stage: Optional[int] = None
    next_step: Optional[str] = None


@dataclass
class ImplementationPhase:
    phase: int
    title: str
    steps: list       # list[str]
    verification: str
    timeline: str


@dataclass
class RemediationPlan:
    spf: Optional[DnsRecordSpec]
    dmarc: Optional[DnsRecordSpec]
    dkim_action: Optional[str]
    implementation_phases: list  # list[ImplementationPhase]


# ── Top-Level Result ───────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    domain: str
    analyzed_at: datetime
    spf: SpfResult
    dkim: DkimResult
    dmarc: DmarcResult
    risk: RiskAssessment
    remediation: RemediationPlan
    client_explanation: str


# ── DMARC Report Parser Layer ──────────────────────────────────────────────────

@dataclass
class DkimAuthResult:
    domain: str
    result: str
    selector: Optional[str] = None


@dataclass
class SpfAuthResult:
    domain: str
    result: str
    scope: Optional[str] = None


@dataclass
class PolicyEvaluated:
    disposition: str
    dkim: str   # "pass" | "fail"
    spf: str    # "pass" | "fail"


@dataclass
class ReportRecord:
    source_ip: str
    count: int
    policy_evaluated: PolicyEvaluated
    header_from: str
    dkim_auth: list  # list[DkimAuthResult]
    spf_auth: list   # list[SpfAuthResult]
    envelope_from: Optional[str] = None


@dataclass
class ReportMetadata:
    org_name: str
    email: str
    report_id: str
    begin: datetime
    end: datetime
    extra_contact_info: Optional[str] = None

    @property
    def duration_hours(self) -> float:
        return (self.end - self.begin).total_seconds() / 3600


@dataclass
class PolicyPublished:
    domain: str
    adkim: str = "r"
    aspf: str = "r"
    policy: str = "none"          # "none" | "quarantine" | "reject"
    subdomain_policy: Optional[str] = None
    pct: int = 100


@dataclass
class ReportStatistics:
    total_messages: int
    dkim_pass: int
    dkim_fail: int
    spf_pass: int
    spf_fail: int
    fully_aligned: int      # both DKIM and SPF pass
    fully_failed: int       # both DKIM and SPF fail
    disposition_none: int
    disposition_quarantine: int
    disposition_reject: int
    unique_sources: int
    pass_rate_dkim: float
    pass_rate_spf: float
    pass_rate_overall: float  # DMARC pass = DKIM pass OR SPF pass


@dataclass
class SourceClassification:
    source_ip: str
    classification: str  # "legitimate" | "forwarding" | "suspicious" | "unknown"
    confidence: str      # "high" | "medium" | "low"
    evidence: list       # list[str]
    message_count: int
    pass_rate: float


@dataclass
class ParsedReport:
    metadata: ReportMetadata
    policy_published: PolicyPublished
    records: list          # list[ReportRecord]
    statistics: ReportStatistics
    source_classifications: list   # list[SourceClassification]
    validation_messages: list      # list[str]
    recommendations: list          # list[dict]
    parsed_at: datetime = field(default_factory=datetime.utcnow)
