"""NIST NVD 2.0 API client with on-disk caching.

Only performs read-only HTTP GET requests against the public NVD API.
Results are cached as JSON under the configured cache directory so the
tool works offline after an initial fetch, and to respect NVD rate limits.

Every returned :class:`CveRecord` carries a ``source_url`` pointing at the
canonical NVD page, satisfying the "every finding must include its source
URL" requirement.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger
from ..models import CveRecord

log = get_logger()

NVD_WEB_BASE = "https://nvd.nist.gov/vuln/detail/"


class NvdError(RuntimeError):
    pass


class NvdClient:
    def __init__(
        self,
        api_base: str,
        cache_dir: Path,
        api_key: str = "",
        timeout: float = 30.0,
        cache_ttl: int = 604800,
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.cache_dir = cache_dir
        self.api_key = api_key
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ---- cache helpers ----------------------------------------------------
    def _cache_file(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()[:24]
        return self.cache_dir / f"nvd_{digest}.json"

    def _load_cache(self, key: str) -> dict[str, Any] | None:
        f = self._cache_file(key)
        if not f.is_file():
            return None
        try:
            payload = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        if time.time() - payload.get("_cached_at", 0) > self.cache_ttl:
            log.debug("cache expired for %s", key)
            return None
        return payload.get("data")

    def _store_cache(self, key: str, data: dict[str, Any]) -> None:
        f = self._cache_file(key)
        try:
            f.write_text(json.dumps({"_cached_at": time.time(), "data": data}))
        except OSError as exc:  # pragma: no cover
            log.warning("could not write NVD cache: %s", exc)

    # ---- HTTP -------------------------------------------------------------
    def _request(self, params: dict[str, str]) -> dict[str, Any]:
        key = json.dumps(params, sort_keys=True)
        cached = self._load_cache(key)
        if cached is not None:
            log.info("NVD cache hit (%s)", params)
            return cached

        try:
            import httpx
        except Exception as exc:  # pragma: no cover
            raise NvdError(
                "httpx is required for live NVD queries. Install it, or use "
                "cached/offline data."
            ) from exc

        headers = {"User-Agent": "wisebreak-research/0.1 (read-only)"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        log.info("NVD query %s", params)
        try:
            with httpx.Client(timeout=self.timeout, headers=headers) as client:
                resp = client.get(self.api_base, params=params)
        except Exception as exc:  # network failure
            raise NvdError(f"NVD request failed: {exc}") from exc

        if resp.status_code == 403:
            raise NvdError("NVD returned 403 (rate limited). Add an API key or wait.")
        if resp.status_code != 200:
            raise NvdError(f"NVD returned HTTP {resp.status_code}")
        try:
            data = resp.json()
        except Exception as exc:  # pragma: no cover
            raise NvdError(f"NVD returned non-JSON response: {exc}") from exc
        self._store_cache(key, data)
        # Courteous pacing; NVD recommends >=6s between keyless requests.
        time.sleep(0.5 if self.api_key else 6.0)
        return data

    # ---- public API -------------------------------------------------------
    def get_cve(self, cve_id: str) -> CveRecord | None:
        data = self._request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._parse_cve(vulns[0]["cve"])

    def search(
        self,
        keyword: str = "",
        cpe_name: str = "",
        results_per_page: int = 50,
        start_index: int = 0,
    ) -> list[CveRecord]:
        params: dict[str, str] = {
            "resultsPerPage": str(min(results_per_page, 2000)),
            "startIndex": str(start_index),
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cpe_name:
            params["cpeName"] = cpe_name
        data = self._request(params)
        out: list[CveRecord] = []
        for item in data.get("vulnerabilities", []):
            try:
                out.append(self._parse_cve(item["cve"]))
            except Exception as exc:  # pragma: no cover
                log.debug("skipping malformed CVE: %s", exc)
        return out

    # ---- parsing ----------------------------------------------------------
    @staticmethod
    def _parse_cve(cve: dict[str, Any]) -> CveRecord:
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "",
        )
        metrics = cve.get("metrics", {})
        score: float | None = None
        severity = ""
        version = ""
        for mkey in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if mkey in metrics and metrics[mkey]:
                primary = metrics[mkey][0]
                cvss = primary.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = (
                    cvss.get("baseSeverity")
                    or primary.get("baseSeverity")
                    or ""
                )
                version = cvss.get("version", "")
                break
        refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
        return CveRecord(
            cve_id=cve_id,
            description=desc,
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            cvss_version=version,
            cvss_score=score,
            cvss_severity=severity,
            source_url=f"{NVD_WEB_BASE}{cve_id}",
            references=refs,
            raw=cve,
        )
