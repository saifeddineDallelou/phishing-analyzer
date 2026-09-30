"""The profile of the organization this analyzer protects: its domains, VIPs and departments.

The real profile contains names of people with power over money and data, so it lives in
config/organization.json, which is git-ignored. config/organization.example.json shows the format.
Set ORG_PROFILE to use another path. No profile = the organization rules are simply skipped.
"""
import logging
import os
import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel

log = logging.getLogger(__name__)
DEFAULT_PATH = Path(__file__).resolve().parent.parent / "config" / "organization.json"


class VIP(BaseModel):
    name: str
    role: str = ""


class OrganizationProfile(BaseModel):
    names: list[str] = []          # how people refer to the organization, e.g. "ESPRIT"
    domains: list[str] = []        # registrable domains it really owns, e.g. "esprit.tn"
    vips: list[VIP] = []
    service_names: list[str] = []  # internal departments, e.g. "Scolarité", "IT Support"


@lru_cache
def get_profile() -> OrganizationProfile:
    """Load the profile once, on first use."""
    path = Path(os.environ.get("ORG_PROFILE", DEFAULT_PATH))
    if not path.exists():
        log.warning("No organization profile at %s: organization rules disabled", path)
        return OrganizationProfile()
    # A broken profile raises here on purpose: silently running without protection is worse.
    return OrganizationProfile.model_validate_json(path.read_text(encoding="utf-8"))


def normalize(text: str) -> list[str]:
    """'Karïm BEN-ALI (Direction)' -> ['karim', 'ben', 'ali', 'direction']"""
    decomposed = unicodedata.normalize("NFKD", text)  # 'ï' -> 'i' + a separate accent mark
    no_accents = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return [w for w in re.split(r"[^\w]+", no_accents.lower()) if w]
