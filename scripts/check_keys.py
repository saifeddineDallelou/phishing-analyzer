"""Check that the API keys in .env work, using harmless lookups. Never prints the keys.

Run from the project folder:  python -m scripts.check_keys
"""
import asyncio

import httpx

from app.config import get_settings
from app.intel.providers import URLhaus, AbuseIPDB, VirusTotal

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # harmless AV test file


async def main() -> None:
    settings = get_settings()
    async with httpx.AsyncClient(timeout=settings.intel_timeout) as client:
        checks = {
            "VirusTotal (EICAR test hash)": (settings.virustotal_api_key,
                lambda key: VirusTotal(client, key).file(EICAR_SHA256)),
            "AbuseIPDB (8.8.8.8)": (settings.abuseipdb_api_key,
                lambda key: AbuseIPDB(client, key).check("8.8.8.8")),
            "URLhaus (https://example.com/)": (settings.urlhaus_auth_key,
                lambda key: URLhaus(client, key).url("https://example.com/")),
        }
        for name, (secret, lookup) in checks.items():
            key = secret.get_secret_value()
            if not key:
                print(f"[skip] {name}: no key in .env")
                continue
            try:
                print(f"[ok]   {name}: {await lookup(key)}")
            except httpx.HTTPStatusError as error:
                print(f"[FAIL] {name}: HTTP {error.response.status_code} (wrong key or quota exceeded?)")
            except httpx.HTTPError as error:
                print(f"[FAIL] {name}: {type(error).__name__} (network problem?)")


if __name__ == "__main__":
    asyncio.run(main())
