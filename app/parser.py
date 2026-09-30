"""Turn a raw .eml into a ParsedEmail: headers, bodies, links and attachments."""
import hashlib
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from html.parser import HTMLParser

from app.models import Attachment, Link, ParsedEmail

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collects <a href> targets together with their visible text.

    Keeping the text matters: '<a href="http://evil.xyz">https://paypal.com</a>'
    is a classic phishing trick, and you can only catch it if you have both.
    """

    def __init__(self) -> None:
        super().__init__()
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append(Link(href=self._href.strip(), text="".join(self._text).strip()))
            self._href = None


def _body(msg: EmailMessage, subtype: str) -> str:
    part = msg.get_body(preferencelist=(subtype,))
    if part is None:
        return ""
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError):
        return part.get_payload(decode=True).decode("utf-8", errors="replace")


def _links(text_body: str, html_body: str) -> list[Link]:
    links: list[Link] = []
    if html_body:
        extractor = _LinkExtractor()
        extractor.feed(html_body)
        links.extend(extractor.links)
    seen = {link.href for link in links}
    for url in URL_RE.findall(text_body):
        if url not in seen:
            links.append(Link(href=url))
            seen.add(url)
    return links


def _attachments(msg: EmailMessage) -> list[Attachment]:
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append(Attachment(
            filename=part.get_filename(),
            content_type=part.get_content_type(),
            size=len(data),
            md5=hashlib.md5(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            data=data,
        ))
    return attachments


def parse_email(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    text_body = _body(msg, "plain")
    html_body = _body(msg, "html")
    return ParsedEmail(
        subject=str(msg.get("Subject", "")),
        from_=str(msg.get("From", "")),
        to=str(msg.get("To", "")),
        reply_to=str(msg.get("Reply-To", "")),
        return_path=str(msg.get("Return-Path", "")),
        date=str(msg.get("Date", "")),
        message_id=str(msg.get("Message-ID", "")),
        received=[str(h) for h in msg.get_all("Received", [])],
        authentication_results=[str(h) for h in msg.get_all("Authentication-Results", [])],
        text_body=text_body,
        html_body=html_body,
        links=_links(text_body, html_body),
        attachments=_attachments(msg),
    )
