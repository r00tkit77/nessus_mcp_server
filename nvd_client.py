import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# With API key: 50 req/30s. Without: 5 req/30s
REQUEST_DELAY = 0.6 if NVD_API_KEY else 6.0


def _headers() -> dict:
    return {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}


def _extract_cvss(metrics: dict) -> dict:
    """Extract CVSS data preferring v3.1 → v3.0 → v2."""
    cvss = (
        metrics.get("cvssMetricV31", [{}])[0].get("cvssData") or
        metrics.get("cvssMetricV30", [{}])[0].get("cvssData") or
        metrics.get("cvssMetricV2",  [{}])[0].get("cvssData") or
        {}
    )
    return {
        "severity": cvss.get("baseSeverity", "N/A"),
        "score":    cvss.get("baseScore",    "N/A"),
        "vector":   cvss.get("vectorString", "N/A"),
    }


# ── Public API ────────────────────────────────────────────────────────────────

def enrich_cves(cve_ids: list) -> dict:
    """
    Enrich a list of CVE IDs with NVD data.
    Returns dict keyed by CVE ID with severity, score, description, references.
    Caps at 50 CVEs per call to respect NVD rate limits.
    """
    enriched = {}
    cve_ids  = list(dict.fromkeys(cve_ids))[:50]   # deduplicate + cap

    for i, cve_id in enumerate(cve_ids):
        try:
            resp = requests.get(
                NVD_BASE_URL,
                params={"cveId": cve_id},
                headers=_headers(),
                timeout=10
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])

            if not vulns:
                enriched[cve_id] = {"error": "Not found in NVD"}
                continue

            cve  = vulns[0]["cve"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available"
            )
            cvss = _extract_cvss(cve.get("metrics", {}))
            cwes = [
                w["description"][0]["value"]
                for w in cve.get("weaknesses", [])
                if w.get("description")
            ]

            enriched[cve_id] = {
                "description": desc[:350],
                "severity":    cvss["severity"],
                "score":       cvss["score"],
                "vector":      cvss["vector"],
                "cwe":         cwes[:2],
                "published":   cve.get("published",    "N/A")[:10],
                "modified":    cve.get("lastModified", "N/A")[:10],
                "references":  [r["url"] for r in cve.get("references", [])[:3]],
            }

        except requests.HTTPError as e:
            enriched[cve_id] = {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            enriched[cve_id] = {"error": str(e)}

        # Respect NVD rate limit between requests
        if i < len(cve_ids) - 1:
            time.sleep(REQUEST_DELAY)

    return {
        "enriched_cves":   enriched,
        "total_requested": len(cve_ids),
        "total_enriched":  sum(1 for v in enriched.values() if "error" not in v),
        "total_failed":    sum(1 for v in enriched.values() if "error" in v),
        "api_key_used":    bool(NVD_API_KEY),
    }


def get_cve_details(cve_id: str) -> dict:
    """Fetch full details for a single CVE ID."""
    try:
        resp  = requests.get(NVD_BASE_URL, params={"cveId": cve_id}, headers=_headers(), timeout=10)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])

        if not vulns:
            return {"error": f"{cve_id} not found in NVD"}

        cve  = vulns[0]["cve"]
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "N/A")
        cvss = _extract_cvss(cve.get("metrics", {}))
        cwes = [w["description"][0]["value"] for w in cve.get("weaknesses", []) if w.get("description")]

        return {
            "cve_id":      cve_id,
            "description": desc,
            "severity":    cvss["severity"],
            "score":       cvss["score"],
            "vector":      cvss["vector"],
            "cwe":         cwes,
            "published":   cve.get("published",    "N/A")[:10],
            "modified":    cve.get("lastModified", "N/A")[:10],
            "references":  [r["url"] for r in cve.get("references", [])],
        }

    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    print("Testing NVD API...")
    test_cve = "CVE-2021-41773"    # Apache path traversal — known KEV entry
    result   = get_cve_details(test_cve)
    if "error" not in result:
        print(f"✅ {test_cve}: {result['severity']} (CVSS {result['score']})")
        print(f"   {result['description'][:100]}...")
    else:
        print(f"❌ {result['error']}")
