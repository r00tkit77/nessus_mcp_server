import os
import requests
import urllib3
from datetime import datetime
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()


NESSUS_URL = os.getenv("NESSUS_URL", "https://localhost:8834")
HEADERS    = {
    "X-ApiKeys": (
        f"accessKey={os.getenv('NESSUS_ACCESS_KEY')}; "
        f"secretKey={os.getenv('NESSUS_SECRET_KEY')}"
    )
}
SCAN_ID    = int(os.getenv("NESSUS_SCAN_ID", "11"))


def _get(path: str, params: dict = None) -> dict:
    resp = requests.get(f"{NESSUS_URL}{path}", headers=HEADERS, params=params,
                        verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _post(path: str, body: dict = None) -> dict:
    resp = requests.post(f"{NESSUS_URL}{path}", headers=HEADERS, json=body or {}, verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _severity_label(n: int) -> str:
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(n, "Info")


# ── Public API ────────────────────────────────────────────────────────────────

def launch_scan() -> dict:
    """
    Launch the saved full_scan by SCAN_ID.
    Nessus sometimes drops the connection before sending the HTTP response —
    the scan still starts. We catch that and verify via get_scan_status().
    """
    import time
    try:
        result = _post(f"/scans/{SCAN_ID}/launch")
        return {
            "success":   True,
            "scan_id":   SCAN_ID,
            "scan_uuid": result.get("scan_uuid"),
            "message":   f"Scan {SCAN_ID} launched successfully"
        }
    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
        time.sleep(3)
        s = get_scan_status()
        if s.get("status") in ("running", "completed", "pending"):
            return {"success": True, "scan_id": SCAN_ID, "scan_uuid": None,
                    "message": f"Scan launched (connection dropped but scan is {s['status']})"}
        return {"success": False, "error": "Connection dropped and scan did not start"}
    except requests.HTTPError as e:
        return {"success": False, "error": str(e)}


def get_scan_status() -> dict:
    """Get current status of the saved scan (running | completed | paused | canceled)."""
    try:
        info = _get(f"/scans/{SCAN_ID}").get("info", {})
        return {
            "scan_id":   SCAN_ID,
            "scan_name": info.get("name"),
            "status":    info.get("status", "unknown"),
            "start":     datetime.fromtimestamp(info["scan_start"]).isoformat() if info.get("scan_start") else None,
            "end":       datetime.fromtimestamp(info["scan_end"]).isoformat()   if info.get("scan_end")   else None,
        }
    except requests.HTTPError as e:
        return {"success": False, "error": str(e)}


def get_scan_results() -> dict:
    """
    Fetch full scan results across all discovered hosts.
    KEY FIX: uses history_id from the most recent completed run so Nessus
    returns actual host data instead of an empty list (happens when multiple
    scan history entries exist and no history_id is specified).
    - Retries up to 3x if hosts still empty after history_id lookup
    - Filters out Info (severity 0) findings
    - Returns per-host vulnerability list sorted Critical -> Low
    - Returns deduplicated CVE ID list across all hosts
    """
    import time
    try:
        # Step 1: get scan overview to find the latest completed history_id
        overview   = _get(f"/scans/{SCAN_ID}")
        info       = overview.get("info", {})

        if info.get("status") not in ("completed", "imported"):
            return {"success": False,
                    "error": f"Scan not completed. Current status: {info.get('status')}"}

        # Pick newest completed history entry (Nessus returns newest-first)
        history    = overview.get("history", [])
        history_id = None
        if history:
            done = [h for h in history if h.get("status") in ("completed", "imported")]
            if done:
                history_id = done[0].get("history_id")

        # Step 2: fetch with history_id, retry up to 3x if hosts is empty
        params = {"history_id": history_id} if history_id else None
        scan_data = None
        for attempt in range(3):
            scan_data = _get(f"/scans/{SCAN_ID}", params=params)
            if scan_data.get("hosts"):
                break
            if attempt < 2:
                time.sleep(5)

        info = scan_data.get("info", {})
        result = {
            "success":    True,
            "scan_name":  info.get("name"),
            "status":     info.get("status"),
            "history_id": history_id,
            "start":      datetime.fromtimestamp(info["scan_start"]).isoformat() if info.get("scan_start") else None,
            "end":        datetime.fromtimestamp(info["scan_end"]).isoformat()   if info.get("scan_end")   else None,
            "hosts":      []
        }

        all_cves = set()
        for host in scan_data.get("hosts", []):
            hparams = {"history_id": history_id} if history_id else None
            detail  = _get(f"/scans/{SCAN_ID}/hosts/{host['host_id']}", params=hparams)
            filtered = sorted(
                [
                    {
                        "plugin_id":    v["plugin_id"],
                        "plugin_name":  v["plugin_name"],
                        "severity":     _severity_label(v["severity"]),
                        "severity_num": v["severity"],
                        "count":        v.get("count", 1),
                        "cve":          v.get("cve", []),
                    }
                    for v in detail.get("vulnerabilities", [])
                    if v.get("severity", 0) > 0
                ],
                key=lambda x: x["severity_num"],
                reverse=True
            )
            for v in filtered:
                all_cves.update(v.get("cve", []))

            result["hosts"].append({
                "ip":              host.get("hostname"),
                "critical_count":  host.get("critical", 0),
                "high_count":      host.get("high",     0),
                "medium_count":    host.get("medium",   0),
                "low_count":       host.get("low",      0),
                "vulnerabilities": filtered,
            })

        result["all_cve_ids"]    = sorted(all_cves)
        result["total_cves"]     = len(all_cves)
        result["total_hosts"]    = len(result["hosts"])
        result["total_findings"] = sum(
            h["critical_count"] + h["high_count"] + h["medium_count"] + h["low_count"]
            for h in result["hosts"]
        )
        return result

    except requests.HTTPError as e:
        return {"success": False, "error": str(e)}


def get_raw_scan_debug() -> dict:
    """
    DEBUG: Return the raw Nessus API response for this scan so you can see
    exactly what history entries exist and whether hosts are populated.
    Useful for diagnosing 0-host issues.
    """
    try:
        raw = _get(f"/scans/{SCAN_ID}")
        return {
            "success":      True,
            "info_status":  raw.get("info", {}).get("status"),
            "info_name":    raw.get("info", {}).get("name"),
            "hosts_count":  len(raw.get("hosts") or []),
            "hosts_sample": (raw.get("hosts") or [])[:2],
            "history":      raw.get("history", []),
            "raw_keys":     list(raw.keys()),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def test_connection() -> dict:
    """Verify Nessus API connectivity and credentials."""
    try:
        data = _get("/server/status")
        return {"success": True, "status": data.get("status"), "url": NESSUS_URL}
    except Exception as e:
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    print("Testing Nessus connection...")
    r = test_connection()
    if r["success"]:
        print(f"✅ Connected to {r['url']} — server status: {r['status']}")
        s = get_scan_status()
        print(f"   Scan '{s.get('scan_name')}' is {s.get('status')}")
    else:
        print(f"❌ {r['error']}")
