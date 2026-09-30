import hashlib
import io
import struct
import zipfile
from pathlib import Path

import pytest

from app.analyzers.attachments import analyze, analyze_attachment, real_type
from app.models import Attachment, ParsedEmail
from app.parser import parse_email

SAMPLE = (Path(__file__).parent / "samples" / "phishing_example.eml").read_bytes()
PDF = b"%PDF-1.7\n..."
EXE = b"MZ\x90\x00" + b"\x00" * 60


def att(name: str, data: bytes = b"") -> Attachment:
    return Attachment(filename=name, content_type="application/octet-stream", size=len(data),
                      md5=hashlib.md5(data).hexdigest(), sha256=hashlib.sha256(data).hexdigest(), data=data)


def ids(attachment: Attachment, password_in_body: bool = False) -> set[str]:
    return {f.rule_id for f in analyze_attachment(attachment, password_in_body)}


def make_zip(files: dict[str, bytes], encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    data = bytearray(buf.getvalue())
    if encrypted:
        # Python can't create encrypted ZIPs, so set the "encrypted" bit (bit 0 of the flags field)
        # by hand in every local header (flags at +6) and central directory entry (flags at +8).
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(signature)
            while pos != -1:
                (flags,) = struct.unpack_from("<H", data, pos + offset)
                struct.pack_into("<H", data, pos + offset, flags | 0x1)
                pos = data.find(signature, pos + 4)
    return bytes(data)


def test_sample_html_attachment():
    assert {f.rule_id for f in analyze(parse_email(SAMPLE))} == {"ATT-001", "ATT-002"}


# The 8 files from Exercise 5 (content chosen to match what the name claims, except where noted)
@pytest.mark.parametrize("name, data, expected", [
    ("Rapport_final.pdf", PDF, set()),
    ("Rapport_final.pdf.exe", EXE, {"ATT-001", "ATT-002"}),
    ("photo_vacances.jpg.lnk", b"L\x00\x00\x00\x01\x14\x02\x00", {"ATT-001", "ATT-002"}),
    ("contrat.docx", make_zip({"word/document.xml": b"<w:document/>"}), set()),
    ("scan_2026.iso", b"\x00" * 0x8001 + b"CD001", {"ATT-001"}),
    ("facture.js", b"WScript.Echo('hi')", {"ATT-001"}),
], ids=lambda value: value if isinstance(value, str) else "")  # name tests by file, not by 32 KB of bytes
def test_exercise_files(name, data, expected):
    assert ids(att(name, data)) == expected


def test_docm_extension_flagged():
    assert "ATT-001" in ids(att("contrat.docm"))


def test_space_padding_is_reported():
    findings = analyze_attachment(att("invoice.pdf                    .exe", EXE))
    double = next(f for f in findings if f.rule_id == "ATT-002")
    assert "padded with spaces" in double.description


def test_rtlo_trick():
    # Displays as "invoice_exe.pdf", really ends in .exe
    assert {"ATT-001", "ATT-003"} <= ids(att("invoice_‮fdp.exe", EXE))


def test_program_disguised_as_pdf():
    findings = analyze_attachment(att("invoice.pdf", EXE))
    assert [(f.rule_id, f.score) for f in findings] == [("ATT-004", 45)]


def test_content_type_mismatch():
    assert ids(att("photo.jpg", PDF)) == {"ATT-004"}


def test_zip_containing_program():
    assert ids(att("documents.zip", make_zip({"invoice.pdf.exe": EXE}))) == {"ATT-007"}


def test_encrypted_zip_scores_higher_with_password_in_body():
    data = make_zip({"report.txt": b"hello"}, encrypted=True)
    without = analyze(ParsedEmail(attachments=[att("archive.zip", data)]))
    with_pwd = analyze(ParsedEmail(text_body="The password is: 4491", attachments=[att("archive.zip", data)]))
    assert [(f.rule_id, f.score) for f in without] == [("ATT-006", 20)]
    assert [(f.rule_id, f.score) for f in with_pwd] == [("ATT-006", 35)]


def test_real_type_ignores_name():
    assert real_type(EXE) == "executable"
    assert real_type(PDF) == "pdf"
    assert real_type(b"plain text") is None


def test_normal_names_not_flagged():
    assert ids(att("report.2026.pdf", PDF)) == set()
    assert ids(att("photo.png", b"\x89PNG\r\n\x1a\n")) == set()
