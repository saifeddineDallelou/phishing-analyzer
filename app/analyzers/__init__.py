"""Each analyzer module exposes analyze(ParsedEmail) -> list[Finding]."""
from app.analyzers import attachments, auth, headers, urls

ANALYZERS = [auth, headers, urls, attachments]
