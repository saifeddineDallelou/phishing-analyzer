"""Attachment analysis.  (Week 3 - your turn)

Ideas:
    ATT-001  risky extension (.html, .htm, .iso, .img, .lnk, .js, .vbs, .exe, .scr...)
    ATT-002  double extension (facture.pdf.exe)
    ATT-003  declared content type does not match the extension
    ATT-004  Office document with macros (`oletools` -> olevba)
    ATT-005  YARA rule match (`yara-python`)
The sha256 of each attachment is already computed by the parser (for IOC lookups later).
"""
from app.models import Finding, ParsedEmail


def analyze(email: ParsedEmail) -> list[Finding]:
    return []
