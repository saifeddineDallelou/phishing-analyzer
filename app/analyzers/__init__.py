"""Each analyzer module exposes analyze(ParsedEmail) -> list[Finding]."""
from app.analyzers import attachments, auth, headers, organization, urls

ANALYZERS = [auth, headers, organization, urls, attachments]
