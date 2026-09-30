"""Clients for outside reputation services.

Each lookup returns {"found": False} when the service doesn't know the IOC, a dict of
facts when it does, and raises httpx.HTTPError on network/API problems.
We only ever send hashes, URLs, domains and IPs: never file contents (see Lesson 8, OPSEC).
"""
import base64

import httpx


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self.client = client
        self.api_key = api_key

    async def _get(self, path: str) -> dict:
        response = await self.client.get(f"{self.BASE}/{path}", headers={"x-apikey": self.api_key})
        if response.status_code == 404:
            return {"found": False}
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        return {
            "found": True,
            "stats": attributes.get("last_analysis_stats", {}),
            "creation_date": attributes.get("creation_date"),  # domains only, unix timestamp
        }

    async def file(self, sha256: str) -> dict:
        return await self._get(f"files/{sha256}")

    async def domain(self, domain: str) -> dict:
        return await self._get(f"domains/{domain}")

    async def url(self, url: str) -> dict:
        # VirusTotal identifies a URL by its base64url encoding without "=" padding.
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"urls/{url_id}")


class AbuseIPDB:
    URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, client: httpx.AsyncClient, api_key: str):
        self.client = client
        self.api_key = api_key

    async def check(self, ip: str) -> dict:
        response = await self.client.get(
            self.URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()["data"]
        return {
            "found": data.get("totalReports", 0) > 0,
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "whitelisted": bool(data.get("isWhitelisted")),
        }


class URLhaus:
    URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self, client: httpx.AsyncClient, auth_key: str):
        self.client = client
        self.auth_key = auth_key

    async def url(self, url: str) -> dict:
        response = await self.client.post(self.URL, data={"url": url}, headers={"Auth-Key": self.auth_key})
        response.raise_for_status()
        data = response.json()
        if data.get("query_status") != "ok":
            return {"found": False}
        return {"found": True, "threat": data.get("threat") or "malware", "status": data.get("url_status")}
