"""Attachment analysis: could this file run code when the victim opens it?

Three claims describe a file: its extension, its Content-Type header and its bytes.
The attacker controls the first two. Only the bytes (magic bytes) tell the truth.

Nothing here executes or extracts anything: we only read headers and file listings.
"""
import io
import logging
import re
import zipfile

from oletools.olevba import VBA_Parser

from app.models import Attachment, Finding, ParsedEmail, Severity

logging.getLogger("olevba").setLevel(logging.CRITICAL)  # oletools is very talkative on odd files

# extension -> (what it is, score)
DANGEROUS_EXTENSIONS = {
    **dict.fromkeys(["exe", "scr", "com", "pif", "msi", "bat", "cmd", "ps1", "vbs", "vbe",
                     "js", "jse", "wsf", "wsh", "hta", "cpl", "jar", "reg"], ("program or script", 40)),
    **dict.fromkeys(["lnk", "url"], ("shortcut that can launch any command", 35)),
    **dict.fromkeys(["iso", "img", "vhd", "vhdx"], ("disk image", 25)),
    **dict.fromkeys(["html", "htm", "shtml", "xhtml", "svg"], ("web page / script-capable image", 25)),
    **dict.fromkeys(["docm", "xlsm", "pptm", "dotm", "xlam"], ("macro-enabled Office file", 20)),
}
# Extensions victims trust, used as a disguise in front of the real one.
DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png",
                    "gif", "txt", "csv", "rtf", "zip", "mp3", "mp4"}
OFFICE_EXTENSIONS = {"doc", "docx", "docm", "dot", "dotm", "xls", "xlsx", "xlsm", "xlam",
                     "ppt", "pptx", "pptm"}

# Unicode characters that reorder or hide text: no legitimate reason to be in a file name.
BIDI_CONTROLS = re.compile("[‎‏‪-‮⁦-⁩]")

MAGIC_BYTES = [
    (b"MZ", "executable"),
    (b"%PDF", "pdf"),
    (b"PK\x03\x04", "zip"),                            # also docx/xlsx/pptx/jar/apk
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),      # old Office, msi, encrypted Office
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF8", "gif"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
]
EXECUTABLE_EXTENSIONS = {"exe", "dll", "scr", "com", "sys", "cpl"}
# What the bytes should be for a given extension. Encrypted Office files are OLE, even .docx.
EXPECTED_TYPE = {
    "pdf": {"pdf"},
    **dict.fromkeys(["docx", "docm", "xlsx", "xlsm", "pptx", "pptm"], {"zip", "ole"}),
    **dict.fromkeys(["doc", "xls", "ppt", "msi"], {"ole"}),
    **dict.fromkeys(["zip", "jar", "apk", "odt", "ods"], {"zip"}),
    "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "iso": {"iso"}, "lnk": {"lnk"},
}
PASSWORD_IN_TEXT = re.compile(r"\b(password|passwd|pwd|passcode|mot de passe|mdp)\b\s*[:=\-]?\s*\S+",
                              re.IGNORECASE)


def real_type(data: bytes) -> str | None:
    """Identify the file from its first bytes, whatever its name says."""
    for magic, kind in MAGIC_BYTES:
        if data.startswith(magic):
            return kind
    if data[0x8001:0x8006] == b"CD001":  # ISO 9660 signature lives at byte 32769
        return "iso"
    return None


def extensions(filename: str) -> list[str]:
    """'Invoice.PDF   .exe' -> ['pdf', 'exe']"""
    return [part.strip().lower() for part in filename.split(".")[1:]]


def _finding(rule_id: str, severity: Severity, score: int, text: str, mitre: str = "T1566.001") -> Finding:
    return Finding(rule_id=rule_id, description=text, severity=severity, score=score, mitre=mitre)


def _name_findings(name: str) -> list[Finding]:
    findings = []
    exts = extensions(name)
    last = exts[-1] if exts else ""

    if last in DANGEROUS_EXTENSIONS:
        kind, score = DANGEROUS_EXTENSIONS[last]
        findings.append(_finding("ATT-001", Severity.high if score >= 25 else Severity.medium, score,
                                 f"Attachment {name!r} is a {kind} (.{last})"))

    if len(exts) >= 2 and last in DANGEROUS_EXTENSIONS and exts[-2] in DECOY_EXTENSIONS:
        padded = " padded with spaces," if re.search(r"\s{3,}", name) else ""
        findings.append(_finding("ATT-002", Severity.high, 30,
            f"Double extension{padded} {name!r}: Windows shows '.{exts[-2]}' and hides '.{last}'",
            mitre="T1036.007"))

    if BIDI_CONTROLS.search(name):
        findings.append(_finding("ATT-003", Severity.high, 45,
            f"File name {name!r} contains invisible text-direction characters (RTLO trick): "
            f"the extension the victim sees is not the real one", mitre="T1036.002"))
    return findings


def _content_mismatch(name: str, data: bytes) -> Finding | None:
    exts = extensions(name)
    ext = exts[-1] if exts else ""
    kind = real_type(data)
    if kind == "executable" and ext not in EXECUTABLE_EXTENSIONS:
        return _finding("ATT-004", Severity.high, 45,
            f"{name!r} is actually a Windows program (starts with 'MZ') disguised as '.{ext}'",
            mitre="T1036.008")
    if kind and ext in EXPECTED_TYPE and kind not in EXPECTED_TYPE[ext]:
        return _finding("ATT-004", Severity.medium, 20,
            f"{name!r}: content is {kind.upper()} but the extension says '.{ext}'", mitre="T1036.008")
    return None


def _macro_finding(name: str, data: bytes) -> Finding | None:
    """Read VBA macros statically with oletools. Nothing is executed."""
    try:
        parser = VBA_Parser(name, data=data)
        try:
            if not parser.detect_vba_macros():
                return None
            autoexec = sorted({keyword for kind, keyword, _ in parser.analyze_macros() if kind == "AutoExec"})
        finally:
            parser.close()
    except Exception:  # corrupted or deliberately malformed file: can't say more
        return None
    if autoexec:
        return _finding("ATT-005", Severity.high, 40,
            f"{name!r} contains VBA macros that run automatically on open ({', '.join(autoexec)})",
            mitre="T1204.002")
    return _finding("ATT-005", Severity.medium, 25, f"{name!r} contains VBA macros", mitre="T1204.002")


def _archive_findings(name: str, data: bytes, password_in_body: bool) -> list[Finding]:
    """Read the ZIP's file listing without extracting anything (no zip-bomb risk, works if encrypted)."""
    try:
        entries = zipfile.ZipFile(io.BytesIO(data)).infolist()
    except (zipfile.BadZipFile, ValueError):
        return []
    findings = []
    inner = [e.filename for e in entries if (extensions(e.filename) or [""])[-1] in DANGEROUS_EXTENSIONS]
    if inner:
        findings.append(_finding("ATT-007", Severity.high, 35,
            f"Archive {name!r} contains dangerous file(s): {', '.join(inner[:5])}"))
    if any(e.flag_bits & 0x1 for e in entries):  # bit 0 of each entry's header = encrypted
        if password_in_body:
            findings.append(_finding("ATT-006", Severity.high, 35,
                f"Encrypted archive {name!r} with the password in the email body: "
                f"built to blind email scanners", mitre="T1027.013"))
        else:
            findings.append(_finding("ATT-006", Severity.medium, 20,
                f"Encrypted archive {name!r}: its content cannot be scanned", mitre="T1027.013"))
    return findings


def analyze_attachment(att: Attachment, password_in_body: bool = False) -> list[Finding]:
    name = att.filename or ""
    findings = _name_findings(name)

    mismatch = _content_mismatch(name, att.data)
    if mismatch:
        findings.append(mismatch)

    kind = real_type(att.data)
    ext = (extensions(name) or [""])[-1]
    if kind in ("ole", "zip") and ext in OFFICE_EXTENSIONS:
        macro = _macro_finding(name, att.data)
        if macro:
            findings.append(macro)
    elif kind == "zip":
        findings.extend(_archive_findings(name, att.data, password_in_body))
    elif kind in ("rar", "7z") and password_in_body:
        findings.append(_finding("ATT-006", Severity.medium, 20,
            f"Archive {name!r} with a password in the email body (likely encrypted)", mitre="T1027.013"))
    return findings


def analyze(email: ParsedEmail) -> list[Finding]:
    password_in_body = bool(PASSWORD_IN_TEXT.search(email.text_body) or PASSWORD_IN_TEXT.search(email.html_body))
    seen: dict[str, Finding] = {}
    for att in email.attachments:
        for finding in analyze_attachment(att, password_in_body):
            seen.setdefault(finding.rule_id, finding)
    return list(seen.values())
