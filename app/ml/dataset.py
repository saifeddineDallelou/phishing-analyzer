"""Load labeled emails from disk for training.

Supports mbox files (many emails in one file, like the Nazario phishing corpus) and folders
of single-email files (.eml, or SpamAssassin's numbered files). Emails are only parsed as
text: nothing is opened, rendered or executed.
"""
import hashlib
import logging
import mailbox
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger(__name__)
SKIP_NAMES = {"cmds", "readme", "readme.txt", "license.txt", ".ds_store"}


def _is_mbox(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(5) == b"From "


def iter_raw_emails(root: Path) -> Iterator[bytes]:
    """Yield every email under root as raw bytes, skipping exact duplicates."""
    seen: set[str] = set()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        if path.name.lower() in SKIP_NAMES or path.suffix.lower() in {".bz2", ".gz", ".tar", ".zip"}:
            continue
        try:
            if _is_mbox(path):
                messages = (msg.as_bytes() for msg in mailbox.mbox(path, create=False))
            else:
                messages = iter([path.read_bytes()])
            for raw in messages:
                digest = hashlib.sha256(raw).hexdigest()
                if digest not in seen:
                    seen.add(digest)
                    yield raw
        except (OSError, ValueError) as error:  # e.g. a file quarantined by the antivirus mid-read
            log.warning("Skipping %s: %s", path.name, type(error).__name__)
