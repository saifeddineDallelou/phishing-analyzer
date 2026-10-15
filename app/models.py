"""Data models shared across the analyzer."""
from enum import Enum

from pydantic import BaseModel, Field


class Link(BaseModel):
    href: str
    text: str = ""  # visible text of the link (empty for URLs found in plain text)


class Attachment(BaseModel):
    filename: str | None
    content_type: str
    size: int
    md5: str
    sha256: str
    # Raw bytes for the analyzers. Excluded from API responses: never send a malicious file back out.
    data: bytes = Field(default=b"", exclude=True, repr=False)


class ParsedEmail(BaseModel):
    """Everything extracted from a raw .eml, before any detection logic runs."""
    subject: str = ""
    from_: str = Field("", alias="from")
    to: str = ""
    reply_to: str = ""
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    mailer: str = ""  # X-Mailer or User-Agent: the software that sent the email
    header_names: list[str] = []
    received: list[str] = []
    authentication_results: list[str] = []
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = []
    attachments: list[Attachment] = []

    model_config = {"populate_by_name": True}


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"


class Finding(BaseModel):
    """One suspicious thing an analyzer noticed. Findings are what make the report explainable."""
    rule_id: str
    description: str
    severity: Severity
    score: int  # contribution to the final risk score (0-100 scale)
    mitre: str | None = None  # ATT&CK technique, e.g. "T1566.001"


class Verdict(str, Enum):
    clean = "clean"
    suspicious = "suspicious"
    malicious = "malicious"


class IOCs(BaseModel):
    """Indicators of compromise extracted from the email, ready to look up or to block."""
    hashes: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    ips: list[str] = []


class AnalysisReport(BaseModel):
    verdict: Verdict
    score: int
    findings: list[Finding]
    iocs: IOCs
    # Shadow mode: shown next to the rule score, but doesn't change the verdict until we trust it.
    ml_probability: float | None = None
    email: ParsedEmail
