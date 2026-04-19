import os
import json
import time
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_PATH     = os.getenv("KEV_CACHE_PATH", "kev_cache.json")
CACHE_TTL_SECS = 6 * 60 * 60


def _cache_is_fresh():
    if not os.path.exists(CACHE_PATH):
        return False
    return (time.time() - os.path.getmtime(CACHE_PATH)) < CACHE_TTL_SECS

def _load_cache():
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_cache(data):
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f)

def _fetch_kev():
    resp = requests.get(KEV_URL, timeout=20)
    resp.raise_for_status()
    data = {v["cveID"]: v for v in resp.json().get("vulnerabilities", [])}
    _save_cache(data)
    return data

def _get_kev_catalog():
    if _cache_is_fresh():
        return _load_cache()
    return _fetch_kev()


def check_kev(cve_ids, force_refresh: bool = False):
    try:
        if force_refresh:
            _fetch_kev()
        catalog = _get_kev_catalog()
        results = {}
        for cve_id in cve_ids:
            entry = catalog.get(cve_id)
            if entry:
                results[cve_id] = {
                    "in_kev": True,
                    "vendor_project":     entry.get("vendorProject"),
                    "product":            entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "date_added":         entry.get("dateAdded"),
                    "due_date":           entry.get("dueDate"),
                    "required_action":    entry.get("requiredAction"),
                    "short_description":  entry.get("shortDescription", "")[:250],
                    "known_ransomware":   entry.get("knownRansomwareCampaignUse", "Unknown")
                }
            else:
                results[cve_id] = {"in_kev": False}

        kev_matches = [k for k, v in results.items() if v["in_kev"]]
        kev_details = sorted(
            [results[k] | {"cve_id": k} for k in kev_matches],
            key=lambda x: x.get("due_date") or "9999-99-99"
        )
        return {
            "success":       True,
            "results":       results,
            "kev_matches":   kev_matches,
            "kev_details":   kev_details,
            "kev_count":     len(kev_matches),
            "total_checked": len(cve_ids),
            "catalog_size":  len(catalog)
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_kev_entry(cve_id):
    try:
        catalog = _get_kev_catalog()
        entry   = catalog.get(cve_id)
        if entry:
            return {"success": True, "in_kev": True, "cve_id": cve_id, **entry}
        return {"success": True, "in_kev": False, "cve_id": cve_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_catalog_stats():
    try:
        catalog = _get_kev_catalog()
        vendors = {}
        for entry in catalog.values():
            v = entry.get("vendorProject", "Unknown")
            vendors[v] = vendors.get(v, 0) + 1
        top_vendors = sorted(vendors.items(), key=lambda x: x[1], reverse=True)[:10]
        return {
            "success":        True,
            "total_entries":  len(catalog),
            "top_vendors":    dict(top_vendors),
            "cache_fresh":    _cache_is_fresh(),
            "last_refreshed": datetime.fromtimestamp(os.path.getmtime(CACHE_PATH)).isoformat()
                              if os.path.exists(CACHE_PATH) else None
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def refresh_catalog():
    try:
        catalog = _fetch_kev()
        return {"success": True, "total_entries": len(catalog),
                "refreshed_at": datetime.now().isoformat()}
    except Exception as e:
        return {"success": False, "error": str(e)}


def test_connection():
    try:
        resp = requests.head(KEV_URL, timeout=10)
        return {
            "success":     resp.status_code == 200,
            "status_code": resp.status_code,
            "url":         KEV_URL,
            "cache_exists": os.path.exists(CACHE_PATH),
            "cache_fresh":  _cache_is_fresh()
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# Alias so mcp_server.py can call either name
get_kev_summary = get_catalog_stats  # alias used by mcp_server.py
