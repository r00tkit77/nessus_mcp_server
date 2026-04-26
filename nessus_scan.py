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


def _severity_label(n: int) -> str:
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}.get(n, "Info")


def _extract_cves_from_plugin(plugin_detail: dict) -> list:
    """
    Pull CVE IDs out of a plugin detail response.

    Nessus Essentials stores CVEs in multiple places depending on version:

    Path 1  — outputs[*].plugin_attributes.attribute[]
              attribute_name == "cve"  (older Nessus API)

    Path 2a — info.plugindescription.pluginattributes.cve[]
              Direct list of CVE strings  (some versions)

    Path 2b — info.plugindescription.pluginattributes.ref_information.ref[]
              ref[name="cve"].values.value  (modern Nessus Essentials — most common)
              This path was previously missing and is the root cause of 0 CVEs.
    """
    cves = set()

    # ── Path 1: outputs[*].plugin_attributes.attribute[] ─────────────────────
    for output in plugin_detail.get("outputs", []):
        attrs = output.get("plugin_attributes", {}).get("attribute", [])
        for attr in attrs:
            if attr.get("attribute_name", "").lower() == "cve":
                raw = attr.get("attribute_value", "")
                for part in raw.replace(";", ",").split(","):
                    part = part.strip()
                    if part.upper().startswith("CVE-"):
                        cves.add(part.upper())

    info         = plugin_detail.get("info", {})
    plugin_attrs = (info.get("plugindescription", {})
                        .get("pluginattributes", {}))

    # ── Path 2a: direct cve list ──────────────────────────────────────────────
    for attr in plugin_attrs.get("cve", []):
        if isinstance(attr, str) and attr.upper().startswith("CVE-"):
            cves.add(attr.upper())

    # ── Path 2b: ref_information.ref[] — modern Nessus Essentials ────────────
    # Structure: ref_information.ref[{name: "cve", values: {value: [...]}}]
    # `value` can be a single string or a list of strings.
    for ref in plugin_attrs.get("ref_information", {}).get("ref", []):
        if ref.get("name", "").lower() != "cve":
            continue
        values = ref.get("values", {}).get("value", [])
        if isinstance(values, str):          # single CVE comes back as a plain string
            values = [values]
        for v in values:
            if isinstance(v, str) and v.upper().startswith("CVE-"):
                cves.add(v.upper())

    return sorted(cves)


def _extract_host_results(scan_data: dict, history_id: int) -> tuple:
    """
    Parse hosts + vulnerabilities from a scan_data blob.
    Returns (hosts_list, all_cves_set).

    The Nessus host-level vulnerability list (/scans/{id}/hosts/{host_id})
    does NOT include CVE IDs — those only exist in the per-plugin detail
    endpoint (/scans/{id}/hosts/{host_id}/plugins/{plugin_id}).
    We fetch plugin detail for every non-info finding to populate CVEs correctly.
    """
    all_cves = set()
    hosts    = []

    for host in scan_data.get("hosts", []):
        host_id = host["host_id"]
        hparams = {"history_id": history_id} if history_id else None
        detail  = _get(f"/scans/{SCAN_ID}/hosts/{host_id}", params=hparams)

        filtered = []
        for v in detail.get("vulnerabilities", []):
            if v.get("severity", 0) == 0:          # skip Info
                continue

            plugin_id = v["plugin_id"]

            # Fetch plugin detail to get actual CVE IDs
            cves = []
            try:
                plugin_data = _get(
                    f"/scans/{SCAN_ID}/hosts/{host_id}/plugins/{plugin_id}",
                    params=hparams,
                )
                cves = _extract_cves_from_plugin(plugin_data)
            except Exception:
                pass                                # best-effort: no CVEs > wrong CVEs

            all_cves.update(cves)

            filtered.append({
                "plugin_id":    plugin_id,
                "plugin_name":  v["plugin_name"],
                "severity":     _severity_label(v["severity"]),
                "severity_num": v["severity"],
                "count":        v.get("count", 1),
                "cve":          cves,
            })

        filtered.sort(key=lambda x: x["severity_num"], reverse=True)

        hosts.append({
            "ip":              host.get("hostname"),
            "critical_count":  host.get("critical", 0),
            "high_count":      host.get("high",     0),
            "medium_count":    host.get("medium",   0),
            "low_count":       host.get("low",      0),
            "vulnerabilities": filtered,
        })

    return hosts, all_cves


# ── Public API ────────────────────────────────────────────────────────────────

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
    Fetch results from the most recent completed scan run.
    Walks the scan history to find the latest completed entry,
    fetches per-host findings and returns the full CVE list.

    NOTE: This makes (N_hosts × N_findings_per_host) plugin-detail API calls
    to correctly populate CVE IDs — which the host-level endpoint omits.
    For the lab environment (~4 hosts, ~24 findings) this is ~24-40 calls total.
    """
    try:
        overview = _get(f"/scans/{SCAN_ID}")
        info     = overview.get("info", {})

        if info.get("status") not in ("completed", "imported"):
            return {
                "success": False,
                "error":   f"Scan not completed. Current status: {info.get('status')}",
            }

        history    = overview.get("history", [])
        history_id = None
        scan_data  = None

        done = [h for h in history if h.get("status") in ("completed", "imported")]
        for candidate in done:
            candidate_id   = candidate.get("history_id")
            candidate_data = _get(f"/scans/{SCAN_ID}", params={"history_id": candidate_id})
            if candidate_data.get("hosts"):
                history_id = candidate_id
                scan_data  = candidate_data
                break

        if not scan_data:
            fallback_id = done[0].get("history_id") if done else None
            scan_data   = _get(f"/scans/{SCAN_ID}", params={"history_id": fallback_id} if fallback_id else None)
            history_id  = fallback_id

        info            = scan_data.get("info", {})
        hosts, all_cves = _extract_host_results(scan_data, history_id)

        return {
            "success":        True,
            "live_scan":      False,
            "history_id":     history_id,
            "scan_name":      info.get("name"),
            "status":         info.get("status"),
            "start":          datetime.fromtimestamp(info["scan_start"]).isoformat() if info.get("scan_start") else None,
            "end":            datetime.fromtimestamp(info["scan_end"]).isoformat()   if info.get("scan_end")   else None,
            "hosts":          hosts,
            "all_cve_ids":    sorted(all_cves),
            "total_cves":     len(all_cves),
            "total_hosts":    len(hosts),
            "total_findings": sum(
                h["critical_count"] + h["high_count"] + h["medium_count"] + h["low_count"]
                for h in hosts
            ),
        }

    except requests.HTTPError as e:
        return {"success": False, "error": str(e)}


def get_raw_scan_debug() -> dict:
    """
    Return raw Nessus API response — useful for diagnosing 0-host / 0-CVE issues.

    NOTE: hosts_count=0 is NORMAL when no scan is currently running or when
    reading the idle scan state. It does NOT mean targets are unconfigured.
    Targets are stored in the scan policy, not in the API overview response.
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


def debug_plugin_structure(host_id: int, plugin_id: int, history_id: int = None) -> dict:
    """
    Dump a raw plugin detail response to inspect where CVEs live in the response.
    Useful when CVEs are showing as empty — call with any known high/critical plugin_id.

    Example usage:
        from nessus_scan import debug_plugin_structure
        debug_plugin_structure(host_id=1, plugin_id=12345)
    """
    import json
    try:
        params = {"history_id": history_id} if history_id else None
        raw    = _get(f"/scans/{SCAN_ID}/hosts/{host_id}/plugins/{plugin_id}", params=params)
        info   = raw.get("info", {})
        print("=== Plugin info block (CVEs live here) ===")
        print(json.dumps(info, indent=2))
        cves   = _extract_cves_from_plugin(raw)
        print(f"\n=== Extracted CVEs: {cves} ===")
        return {"raw": raw, "extracted_cves": cves}
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
