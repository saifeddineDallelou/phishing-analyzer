"""Pull the indicators of compromise (IOCs) out of a parsed email."""
import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from app.analyzers.urls import is_ip, registrable_domain
from app.brands import BRANDS, FREE_WEBMAIL
from app.models import IOCs, ParsedEmail

MAX_PER_TYPE = 5  # outside services have quotas: an email with 200 links shouldn't burn them all
IP_IN_BRACKETS = re.compile(r"\[([0-9a-fA-F:.]+)\]")
# Domains not worth looking up: free webmail and brands' own domains are known and huge.
WELL_KNOWN = FREE_WEBMAIL | set().union(*BRANDS.values())


def _unique(items) -> list:
    return list(dict.fromkeys(i for i in items if i))  # keeps order, drops duplicates and blanks


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip("[]")).is_global
    except ValueError:
        return False


def sender_ip(email: ParsedEmail) -> str:
    """The IP that delivered the email to our server, from the top Received header (written by us).
    Lower Received headers can be forged by the attacker, like Authentication-Results."""
    if not email.received:
        return ""
    for candidate in IP_IN_BRACKETS.findall(email.received[0]):
        if _is_public_ip(candidate):
            return candidate
    return ""


def extract_iocs(email: ParsedEmail) -> IOCs:
    urls, domains, ips = [], [], [sender_ip(email)]
    for link in email.links:
        try:
            parts = urlsplit(link.href)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if parts.scheme.lower() not in ("http", "https") or not host:
            continue
        urls.append(link.href)
        if is_ip(host):
            ips.append(host.strip("[]"))
        else:
            domains.append(registrable_domain(host))

    for header in (email.from_, email.reply_to):
        addr = parseaddr(header)[1]
        if "@" in addr:
            domains.append(registrable_domain(addr.rpartition("@")[2].lower()))

    return IOCs(
        hashes=_unique(a.sha256 for a in email.attachments)[:MAX_PER_TYPE],
        domains=[d for d in _unique(domains) if d not in WELL_KNOWN][:MAX_PER_TYPE],
        urls=_unique(urls)[:MAX_PER_TYPE],
        ips=[ip for ip in _unique(ips) if _is_public_ip(ip)][:MAX_PER_TYPE],
    )
