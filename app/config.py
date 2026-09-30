"""Secrets and settings, read from environment variables (or a local .env file).

The real .env is git-ignored. .env.example lists the variable names with empty values.
"""
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, SecretStr

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseModel):
    # SecretStr prints as '**********' in logs, errors and repr: keys never end up in a log file.
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    urlhaus_auth_key: SecretStr = SecretStr("")
    intel_timeout: float = 5.0  # seconds before we give up on an outside service


@lru_cache
def get_settings() -> Settings:
    load_dotenv(ENV_FILE)  # real environment variables win over the .env file
    return Settings(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
        urlhaus_auth_key=os.getenv("URLHAUS_AUTH_KEY", ""),
        intel_timeout=float(os.getenv("INTEL_TIMEOUT", "5")),
    )
