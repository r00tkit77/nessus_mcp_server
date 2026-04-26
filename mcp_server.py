"""
mcp_server.py — Vulnerability Risk Engine (FastMCP Edition)
===========================================================

Architecture
------------
This server exposes a clean data pipeline to Claude Desktop. All prose
generation — root-cause labels, remediation checklists, narrative summaries —
is deliberately delegated to Claude (the LLM). The server only does what a
computer is better at: fetch, normalise, enrich, and score.

Tool flow (happy path)
----------------------
1. nessus_get_normalized       → clean host → vuln → CVE list
2. get_enriched_scan           → attaches CMDB + KEV + NVD, scores every finding
3. [Claude analyses the JSON]  → groups root causes, writes remediations, builds report
4. email_owner_reports         → sends per-owner HTML action queue

Optional modifiers
------------------
• min_cvss (float)             → filter applied in get_enriched_scan
• force_kev_refresh (bool)     → re-download CISA KEV catalog
• VULN_SUPPRESSION env var     → comma-separated CVE IDs / substrings to suppress
"""

import json
import math
import os
from datetime import date, datetime
from typing import Optional

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

import cmdb_client
import kev_client
import nessus_scan
import nvd_client
from email_client import build_owner_email, send_email
from email_client import test_connection as smtp_test

load_dotenv()

# ── FastMCP server instance ───────────────────────────────────────────────────
mcp = FastMCP("nessus-vuln-mgmt")

# ── Suppression list ──────────────────────────────────────────────────────────
# Set VULN_SUPPRESSION=CVE-2021-3449,some-plugin-substring in .env to suppress
_RAW_SUPPRESSION = os.getenv("VULN_SUPPRESSION", "")
SUPPRESSION_SET: set[str] = {
    s.strip().upper() for s in _RAW_SUPPRESSION.split(",") if s.strip()
}


# =============================================================================
# SECTION 1 — Nessus scan tools
# =============================================================================

@mcp.tool()
def nessus_scan_status() -> str:
    """
    Check the current status of the Nessus scan.

    Returns the scan name, current status (running | completed | paused |
    canceled), and start/end timestamps. Use this before calling
    nessus_get_normalized to confirm a completed run exists.
    """
    result = nessus_scan.get_scan_status()
    return json.dumps(result, indent=2)


@mcp.tool()
def nessus_test_connection() -> str:
    """
    Verify Nessus API connectivity and credentials.

    Returns success/failure with error details. Call this first if any
    Nessus tool is returning unexpected errors.
    """
    result = nessus_scan.test_connection()
    return json.dumps(result, indent=2)


@mcp.tool()
def nessus_debug_raw() -> str:
    """
    Return the raw Nessus scan API response for diagnostic purposes.

    Shows scan history entries, host counts, and the raw response keys.
    Use this to diagnose 0-host results or unexpected scan states.
    Note: hosts_count=0 is normal when no scan is currently running.
    """
    result = nessus_scan.get_raw_scan_debug()
    return json.dumps(result, indent=2)


@mcp.tool()
def nessus_get_normalized() -> str:
    """
    Fetch the most recently completed Nessus scan and return a clean,
    normalised finding list.

    Processing applied:
    • Informational findings (severity=0) are dropped
    • Per-plugin CVE IDs are extracted from all three Nessus API paths
    • Output is structured as: { hosts: [ { ip, hostname, vulnerabilities:
      [ { plugin_name, severity, severity_num, cves: [...] } ] } ],
      all_cve_ids: [...], total_* counts }

    This is the entry point for all analysis. Feed its output into
    get_enriched_scan for full enrichment and scoring.
    """
    raw = nessus_scan.get_scan_results()
    if not raw.get("success"):
        return json.dumps(raw, indent=2)

    # Strip fields Claude doesn't need for analysis
    normalised_hosts = []
    for host in raw.get("hosts", []):
        vulns = []
        for v in host.get("vulnerabilities", []):
            if v.get("severity_num", 0) == 0:   # belt-and-suspenders info filter
                continue
            vulns.append({
                "plugin_id":   v["plugin_id"],
                "plugin_name": v["plugin_name"],
                "severity":    v["severity"],
                "severity_num": v["severity_num"],
                "cves":        v.get("cve", []),
                "count":       v.get("count", 1),
            })
        if vulns:
            normalised_hosts.append({
                "ip":       host["ip"],
                "vulnerabilities": vulns,
            })

    return json.dumps({
        "success":        True,
        "scan_name":      raw.get("scan_name"),
        "scan_end":       raw.get("end"),
        "total_hosts":    len(normalised_hosts),
        "total_findings": sum(len(h["vulnerabilities"]) for h in normalised_hosts),
        "all_cve_ids":    raw.get("all_cve_ids", []),
        "total_cves":     raw.get("total_cves", 0),
        "hosts":          normalised_hosts,
    }, indent=2)


# =============================================================================
# SECTION 2 — KEV / NVD tools (standalone, for ad-hoc lookups)
# =============================================================================

@mcp.tool()
def kev_check(cve_ids: list[str], force_refresh: bool = False) -> str:
    """
    Check which CVEs from a list appear in the CISA Known Exploited
    Vulnerabilities (KEV) catalog.

    KEV membership means the vulnerability is confirmed to be actively
    exploited in the wild and should be treated as top priority regardless
    of CVSS score.

    Args:
        cve_ids: List of CVE IDs, e.g. ["CVE-2021-41773", "CVE-2022-22965"]
        force_refresh: Re-download the KEV catalog even if the local cache
                       is less than 6 hours old.
    """
    result = kev_client.check_kev(cve_ids, force_refresh)
    return json.dumps(result, indent=2)


@mcp.tool()
def kev_catalog_summary() -> str:
    """
    Return metadata about the CISA KEV catalog: total entries, top vendors,
    cache freshness, and last refresh timestamp.
    """
    result = kev_client.get_kev_summary()
    return json.dumps(result, indent=2)


@mcp.tool()
def nvd_enrich_cves(cve_ids: list[str]) -> str:
    """
    Enrich up to 50 CVE IDs with data from the National Vulnerability
    Database (NVD): CVSS base score, severity label, short description,
    CWE, publish date, and top references.

    CVSS score and publish date are the two signals used by get_enriched_scan
    for priority scoring. This tool is also useful for ad-hoc lookups.

    Args:
        cve_ids: List of CVE IDs (max 50). Duplicates are deduplicated.
    """
    result = nvd_client.enrich_cves(cve_ids)
    return json.dumps(result, indent=2)


@mcp.tool()
def nvd_get_cve(cve_id: str) -> str:
    """
    Fetch full details for a single CVE ID from NVD, including the complete
    description, all CVSS vectors, CWE list, and reference URLs.

    Args:
        cve_id: A single CVE ID, e.g. "CVE-2021-41773"
    """
    result = nvd_client.get_cve_details(cve_id)
    return json.dumps(result, indent=2)


# =============================================================================
# SECTION 3 — CMDB
# =============================================================================

@mcp.tool()
def cmdb_get_assets() -> str:
    """
    Return all assets in the Configuration Management Database (CMDB).

    Each asset record includes: ip_address, hostname, os, role, environment,
    criticality (high | medium | low), owner_name, owner_email, and team.
    This data is used by get_enriched_scan to attach asset context to findings.
    """
    result = cmdb_client.get_all_assets()
    return json.dumps(result, indent=2)


# =============================================================================
# SECTION 4 — Scoring helpers (pure math, no LLM)
# =============================================================================

_CRIT_WEIGHT = {"high": 10, "medium": 5, "low": 2}


def _infer_exposure(asset: dict) -> str:
    """
    Classify an asset as 'external' (internet-facing) or 'internal'.
    Uses CMDB role, environment, and hostname as signals.
    An explicit 'exposure' field in CMDB takes precedence.
    """
    if asset.get("exposure"):
        return asset["exposure"].lower()
    role = (asset.get("role") or "").lower()
    env  = (asset.get("environment") or "").lower()
    host = (asset.get("hostname") or "").lower()
    external_keywords = (
        "web server", "proxy", "load balancer", "dmz",
        "gateway", "edge", "public", "frontend",
    )
    if any(k in role for k in external_keywords):
        return "external"
    if env in ("prod", "production", "staging", "dmz"):
        return "external"
    if any(k in host for k in ("web", "proxy", "lb", "gw", "edge", "pub")):
        return "external"
    return "internal"


def _cvss_bucket_pts(cvss: float) -> int:
    """
    Non-linear CVSS → priority points.
    Buckets reflect real-world exploitability jumps rather than a linear slope.
    Critical (≥9.0) → 50, High (≥7.0) → 38, Medium (≥4.0) → 22,
    Low (≥0.1) → 8, None → 0.
    """
    if cvss >= 9.0: return 50
    if cvss >= 7.0: return 38
    if cvss >= 4.0: return 22
    if cvss >= 0.1: return 8
    return 0


def _cvss_fallback(severity_num: int) -> float:
    """Estimated CVSS when NVD data is unavailable."""
    return {4: 9.5, 3: 8.0, 2: 6.0, 1: 3.0}.get(severity_num, 0.0)


def _log_blast_pts(host_count: int) -> int:
    """
    Logarithmic blast-radius bonus (max 15 pts).
    Avoids linear inflation in large environments.
    """
    return min(15, round(math.log1p(host_count) * 7.2))


def _age_bonus_pts(cves: list[str], nvd_map: dict) -> tuple[int, int]:
    """
    Temporal bonus for CVEs that remain unpatched long after publication.
    +3 pts >180 days, +5 pts >365 days, +10 pts >730 days.
    Returns (bonus_pts, max_age_days).
    """
    max_days = 0
    today = date.today()
    for cve_id in cves:
        published = (nvd_map.get(cve_id) or {}).get("published", "")
        if not published or published == "N/A":
            continue
        try:
            pub_date = date.fromisoformat(published[:10])
            max_days = max(max_days, (today - pub_date).days)
        except (ValueError, TypeError):
            continue
    if max_days >= 730: return 10, max_days
    if max_days >= 365: return 5,  max_days
    if max_days >= 180: return 3,  max_days
    return 0, max_days


def _priority_score(
    cvss:        float,
    in_kev:      bool,
    is_external: bool,
    criticality: str,
    host_count:  int,
    age_bonus:   int,
) -> int:
    """
    Multi-signal priority score (0–100):
      Base  = CVSS bucket (0–50)
      +15   = KEV membership (confirmed active exploitation)
      +10   = external/internet-facing asset
      +crit = criticality weight (2–10)
      +blast= logarithmic host count (0–15)
      +age  = temporal bonus (0–10)
    Clamped to 100. KEV items are always forced to ≥ 80 (IMMEDIATE tier).
    """
    base   = _cvss_bucket_pts(cvss)
    kev_b  = 15 if in_kev      else 0
    ext_b  = 10 if is_external  else 0
    crit_b = _CRIT_WEIGHT.get((criticality or "").lower(), 2)
    blast  = _log_blast_pts(host_count)
    score  = min(100, base + kev_b + ext_b + crit_b + blast + age_bonus)
    if in_kev:
        score = max(80, score)
    return score


def _sla(priority: int, in_kev: bool) -> str:
    if in_kev or priority >= 80: return "IMMEDIATE"
    if priority >= 60:            return "URGENT"
    if priority >= 35:            return "SCHEDULED"
    return "BACKLOG"


def _sla_deadline(sla: str) -> str:
    """Return an absolute ISO deadline date for the given SLA tier."""
    from datetime import timedelta
    today = date.today()
    delta = {"IMMEDIATE": 2, "URGENT": 7, "SCHEDULED": 30, "BACKLOG": 90}.get(sla, 90)
    return (today + timedelta(days=delta)).isoformat()


def _is_suppressed(cves: list[str], plugin_name: str) -> bool:
    """Return True if this finding matches the suppression set."""
    if not SUPPRESSION_SET:
        return False
    cve_set  = {c.upper() for c in cves}
    name_key = plugin_name.upper()
    return bool(
        cve_set & SUPPRESSION_SET
        or any(s in name_key for s in SUPPRESSION_SET)
    )


# =============================================================================
# SECTION 5 — Main enrichment pipeline
# =============================================================================

@mcp.tool()
def get_enriched_scan(
    min_cvss:          Optional[float] = None,
    force_kev_refresh: bool = False,
) -> str:
    """
    Full enrichment and scoring pipeline. Runs in a single call:

    1. Fetch the latest completed Nessus scan
    2. Normalise (drop info findings, deduplicate CVEs)
    3. Join each host with CMDB to get team, criticality, exposure
    4. Check all CVEs against the CISA KEV catalog
    5. Enrich all CVEs with NVD (CVSS score, publish date)
    6. Apply suppression filter (VULN_SUPPRESSION env var)
    7. Apply optional CVSS threshold filter (min_cvss parameter)
    8. Score every finding using multi-signal priority formula:
       CVSS bucket + KEV bonus + external bonus + criticality + blast radius + age
    9. Return a structured JSON dataset ready for Claude to analyse

    The returned JSON contains:
    • findings[]: per-host list with asset_context, exposure, and each
      vulnerability enriched with cvss_score, in_kev, kev_details, nvd_data,
      priority_score, sla, age_days, score_breakdown
    • all_cves{}: flat map of CVE-ID → NVD+KEV data for cross-reference
    • summary_stats: counts by SLA tier, KEV count, suppressed count
    • filters_applied: what was filtered and why
    • scan_meta: scan name, end time, raw host/finding counts

    Claude should use this structured output to:
    - Group findings into root-cause clusters
    - Write per-cluster remediation checklists
    - Render the ranked action queue report
    - Identify attack-path chains

    Args:
        min_cvss: If set, only process findings where the highest CVE's CVSS
                  score meets this threshold. E.g. min_cvss=9.0 for Critical-only.
                  Findings with no NVD data use Nessus severity as a fallback.
        force_kev_refresh: Re-download the CISA KEV catalog before checking.
    """
    # ── Step 1: Fetch raw scan ────────────────────────────────────────────────
    raw = nessus_scan.get_scan_results()
    if not raw.get("success"):
        return json.dumps({"success": False, "error": raw.get("error", "Scan fetch failed")}, indent=2)

    # ── Step 2: Collect all CVEs and asset IPs ────────────────────────────────
    all_cve_ids: list[str] = raw.get("all_cve_ids", [])
    all_ips     = [h["ip"] for h in raw.get("hosts", []) if h.get("ip")]

    # ── Step 3: Parallel enrichment (CMDB, KEV, NVD) ─────────────────────────
    cmdb_result = cmdb_client.get_all_assets()
    cmdb_by_ip  = {a["ip_address"]: a for a in cmdb_result.get("assets", [])}
    cmdb_by_host = {a["hostname"]: a for a in cmdb_result.get("assets", [])}

    kev_result  = kev_client.check_kev(all_cve_ids, force_refresh=force_kev_refresh)
    kev_map     = kev_result.get("results", {})   # { cve_id: {in_kev, ...} }

    nvd_result  = nvd_client.enrich_cves(all_cve_ids) if all_cve_ids else {}
    nvd_map     = nvd_result.get("enriched_cves", {}) if isinstance(nvd_result, dict) else {}

    # ── Step 4: Build enriched findings per host ──────────────────────────────
    enriched_hosts   = []
    suppressed_items = []
    filters_log      = []
    sla_counts       = {"IMMEDIATE": 0, "URGENT": 0, "SCHEDULED": 0, "BACKLOG": 0}
    kev_total        = 0

    for host in raw.get("hosts", []):
        ip          = host.get("ip", "")
        asset       = cmdb_by_ip.get(ip) or cmdb_by_host.get(ip) or {}
        exposure    = _infer_exposure(asset)
        criticality = asset.get("criticality", "medium")

        enriched_vulns = []

        for v in host.get("vulnerabilities", []):
            if v.get("severity_num", 0) == 0:
                continue

            plugin_name  = v["plugin_name"]
            severity_num = v.get("severity_num", 1)
            cves         = v.get("cve", [])

            # ── Suppression ──────────────────────────────────────────────────
            if _is_suppressed(cves, plugin_name):
                suppressed_items.append({
                    "ip":          ip,
                    "plugin_name": plugin_name,
                    "reason":      "matched VULN_SUPPRESSION",
                })
                continue

            # ── Gather NVD data for each CVE in this finding ─────────────────
            cve_details = []
            max_cvss    = 0.0
            for cve_id in cves:
                nvd = nvd_map.get(cve_id, {})
                kev = kev_map.get(cve_id, {})
                score = nvd.get("score", None)
                try:
                    score = float(score) if score and score != "N/A" else None
                except (ValueError, TypeError):
                    score = None

                if score and score > max_cvss:
                    max_cvss = score

                cve_details.append({
                    "cve_id":      cve_id,
                    "cvss_score":  score,
                    "severity":    nvd.get("severity", "N/A"),
                    "description": nvd.get("description", ""),
                    "published":   nvd.get("published", "N/A"),
                    "cwe":         nvd.get("cwe", []),
                    "references":  nvd.get("references", []),
                    "in_kev":      kev.get("in_kev", False),
                    "kev_details": {k: v for k, v in kev.items()
                                    if k not in ("in_kev",)} if kev.get("in_kev") else None,
                })

            # Fallback CVSS from Nessus severity if NVD data missing
            if max_cvss == 0.0:
                max_cvss = _cvss_fallback(severity_num)

            # ── CVSS threshold filter ────────────────────────────────────────
            if min_cvss is not None and max_cvss < min_cvss:
                if not filters_log or filters_log[-1].get("reason") != "below min_cvss":
                    pass   # batch-logged below
                continue

            # ── Scoring ──────────────────────────────────────────────────────
            in_kev      = any(c["in_kev"] for c in cve_details)
            age_pts, age_days = _age_bonus_pts(cves, nvd_map)
            priority    = _priority_score(
                cvss        = max_cvss,
                in_kev      = in_kev,
                is_external = (exposure == "external"),
                criticality = criticality,
                host_count  = 1,   # per-finding score; blast radius computed at group level
                age_bonus   = age_pts,
            )
            sla = _sla(priority, in_kev)

            if in_kev:
                kev_total += 1

            sla_counts[sla] += 1

            # Build a compact human-readable reason line for the UI card
            reason_parts = []
            if in_kev:
                reason_parts.append("KEV-confirmed")
            if exposure == "external":
                reason_parts.append("external exposure")
            if max_cvss >= 9.0:
                reason_parts.append("RCE/critical CVSS")
            elif max_cvss >= 7.0:
                reason_parts.append("high CVSS")
            if age_days >= 730:
                reason_parts.append(f"unpatched {age_days}d")
            elif age_days >= 365:
                reason_parts.append(f"stale {age_days}d")
            crit_label = (criticality or "medium").lower()
            if crit_label == "high":
                reason_parts.append("critical asset")
            priority_reason = " + ".join(reason_parts) if reason_parts else "medium risk"

            enriched_vulns.append({
                "plugin_id":      v.get("plugin_id"),
                "plugin_name":    plugin_name,
                "severity":       v["severity"],
                "severity_num":   severity_num,
                "max_cvss":       round(max_cvss, 1),
                "in_kev":         in_kev,
                "cves":           cve_details,
                "priority_score":  priority,
                "priority_reason": priority_reason,
                "sla":             sla,
                "sla_deadline":    _sla_deadline(sla),
                "age_days":        age_days,
            })

        if enriched_vulns:
            enriched_hosts.append({
                "ip":          ip,
                "asset_context": {
                    "hostname":    asset.get("hostname", ip),
                    "role":        asset.get("role"),
                    "os":          asset.get("os"),
                    "environment": asset.get("environment"),
                    "criticality": criticality,
                    "exposure":    exposure,
                    "team":        asset.get("team"),
                    "owner_name":  asset.get("owner_name"),
                    "owner_email": asset.get("owner_email"),
                },
                "exposure":        exposure,
                "vulnerability_count": len(enriched_vulns),
                "vulnerabilities": sorted(
                    enriched_vulns,
                    key=lambda x: x["priority_score"],
                    reverse=True,
                ),
            })

    # ── Step 5: Compute top-level summary stats ───────────────────────────────
    total_findings = sum(h["vulnerability_count"] for h in enriched_hosts)
    total_assets_scanned = raw.get("total_hosts", 0)

    # Count CVEs that pass the filter (i.e. those actually in enriched findings)
    filtered_cve_ids: set[str] = set()
    for h in enriched_hosts:
        for v in h["vulnerabilities"]:
            for c in v.get("cves", []):
                filtered_cve_ids.add(c["cve_id"])

    # Count externally-exposed hosts
    external_host_count = sum(1 for h in enriched_hosts if h.get("exposure") == "external")

    if min_cvss is not None:
        filters_log.append({
            "filter": f"min_cvss={min_cvss}",
            "note":   f"Only findings with CVSS ≥ {min_cvss} included",
        })
    if SUPPRESSION_SET:
        filters_log.append({
            "filter":     "VULN_SUPPRESSION",
            "suppressed": len(suppressed_items),
        })

    # ── Step 6: Root-cause clustering ────────────────────────────────────────
    #
    # DESIGN PRINCIPLE: one cluster = one engineering task.
    # We cluster by (software_family × host_set) — NOT by plugin_id.
    #
    # Software family is derived from plugin_name by stripping version numbers,
    # advisory identifiers, and CVE references, then keeping the first 2–3
    # meaningful tokens (e.g. "Apache HTTP Server", "MySQL", "Redis").
    #
    # Two findings join the same cluster when:
    #   (a) their software families match, AND
    #   (b) they occur on the same set of hosts (same IP set).
    #
    # This collapses "Apache HTTP Server 2.4.49 Path Traversal" and
    # "Apache HTTP Server mod_rewrite Escape Bypass" into ONE card:
    # "Upgrade Apache HTTP Server" — resolving N advisories, M CVEs.

    import re as _re

    # Token blocklist — words that don't identify software family
    _NOISE = {
        "unsupported", "version", "detection", "information",
        "multiple", "vulnerabilities", "vulnerability", "advisory",
        "patch", "update", "upgrade", "critical", "high", "medium",
        "eol", "end-of-life", "deprecated", "obsolete",
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec",
        "2020", "2021", "2022", "2023", "2024", "2025", "2026",
        "cpu", "quarterly",
    }

    def _software_family(plugin_name: str) -> str:
        """
        Extract a stable software-family key from a Nessus plugin name.
        E.g.:
          "Apache HTTP Server 2.4.49 Path Traversal"  → "apache http server"
          "MySQL 5.7.x < 5.7.44 Multiple Vulns"       → "mysql"
          "Redis Server Unauthenticated Access"        → "redis server"
        """
        # Strip parenthetical suffixes and everything after '<'/'>'/'/'
        name = _re.split(r"[<>(]", plugin_name)[0]
        # Remove version numbers (e.g. 5.7.44, 2.4.x)
        name = _re.sub(r"\b\d[\d.x]*\b", "", name)
        tokens = [t.lower() for t in name.split() if t.lower() not in _NOISE and len(t) > 1]
        # Take first 3 meaningful tokens — long enough to be specific, short enough to cluster
        return " ".join(tokens[:3]).strip()

    # ── Build clusters keyed by (family, frozenset-of-ips) ───────────────────
    clusters: dict[tuple, dict] = {}

    for host in enriched_hosts:
        ctx = host["asset_context"]
        ip  = host["ip"]
        for v in host["vulnerabilities"]:
            family  = _software_family(v["plugin_name"])
            host_ip = ip

            # Find an existing cluster for this family on this exact host
            # (we'll merge cross-host clusters in the next pass)
            matched_key = None
            for key in clusters:
                if key[0] == family and host_ip in key[1]:
                    matched_key = key
                    break
                # Also match if same family and no host overlap yet
                if key[0] == family and not (key[1] & frozenset([host_ip])):
                    # Different host, same family — group together
                    matched_key = key
                    break

            new_key = (family, frozenset([host_ip]))

            if matched_key is None:
                # New cluster
                clusters[new_key] = {
                    "family":          family,
                    "plugins":         [],        # all contributing plugin_ids + names
                    "all_cve_ids":     set(),
                    "kev_cve_ids":     set(),
                    "max_cvss":        0.0,
                    "in_kev":          False,
                    "max_priority":    0,
                    "max_age_days":    0,
                    "priority_reason": v["priority_reason"],
                    "sla":             v["sla"],
                    "sla_deadline":    v["sla_deadline"],
                    "host_map":        {},        # ip → host descriptor
                    "findings_count":  0,
                }
                matched_key = new_key

            elif matched_key != new_key:
                # Merge: rebuild key with expanded IP set
                old = clusters.pop(matched_key)
                merged_key = (family, matched_key[1] | frozenset([host_ip]))
                clusters[merged_key] = old
                matched_key = merged_key

            c = clusters[matched_key]
            c["plugins"].append({
                "plugin_id":   v["plugin_id"],
                "plugin_name": v["plugin_name"],
            })
            for cve in v.get("cves", []):
                c["all_cve_ids"].add(cve["cve_id"])
                if cve.get("in_kev"):
                    c["kev_cve_ids"].add(cve["cve_id"])
            if v["max_cvss"] > c["max_cvss"]:
                c["max_cvss"] = v["max_cvss"]
            if v["in_kev"]:
                c["in_kev"] = True
            if v["priority_score"] > c["max_priority"]:
                c["max_priority"]    = v["priority_score"]
                c["priority_reason"] = v["priority_reason"]
                c["sla"]             = v["sla"]
                c["sla_deadline"]    = v["sla_deadline"]
            if v["age_days"] > c["max_age_days"]:
                c["max_age_days"] = v["age_days"]
            c["findings_count"] += 1

            # Add host descriptor (idempotent)
            if ip not in c["host_map"]:
                c["host_map"][ip] = {
                    "hostname":    ctx["hostname"],
                    "ip":          ip,
                    "role":        ctx.get("role"),
                    "team":        ctx.get("team"),
                    "exposure":    host.get("exposure"),
                    "criticality": ctx.get("criticality"),
                }

    # ── Deduplicate plugins within each cluster ───────────────────────────────
    for c in clusters.values():
        seen_pids: set = set()
        unique_plugins = []
        for p in c["plugins"]:
            if p["plugin_id"] not in seen_pids:
                seen_pids.add(p["plugin_id"])
                unique_plugins.append(p)
        c["plugins"] = unique_plugins

    # ── Convert sets to sorted lists and compute blast-radius bonus ───────────
    ranked_groups = []
    for c in clusters.values():
        c["all_cve_ids"]  = sorted(c["all_cve_ids"])
        c["kev_cve_ids"]  = sorted(c["kev_cve_ids"])
        c["affected_hosts"] = list(c["host_map"].values())
        del c["host_map"]

        host_count  = len(c["affected_hosts"])
        blast       = _log_blast_pts(host_count)
        c["priority_score"] = min(100, c["max_priority"] + blast)
        c["host_count"]     = host_count
        c["advisories_count"] = len(c["plugins"])

        # Recalculate SLA from final score
        c["sla"]          = _sla(c["priority_score"], c["in_kev"])
        c["sla_deadline"] = _sla_deadline(c["sla"])

        ranked_groups.append(c)

    ranked_groups.sort(key=lambda x: (x["priority_score"], x["in_kev"]), reverse=True)

    # Assign final rank; no "resolves_with" cards — if it's the same fix,
    # it's already collapsed into the same cluster above.
    for rank, g in enumerate(ranked_groups, 1):
        g["rank"] = rank

    # ── Step 7: Dashboard stats ───────────────────────────────────────────────
    # Recount kev_total at cluster level (not finding level)
    cluster_kev_count = sum(1 for g in ranked_groups if g["in_kev"])

    # ── Step 8: Build flat CVE reference map ─────────────────────────────────
    all_cves_map = {}
    for cve_id in filtered_cve_ids:
        all_cves_map[cve_id] = {
            "nvd": nvd_map.get(cve_id, {}),
            "kev": kev_map.get(cve_id, {}),
        }

    return json.dumps({
        "success": True,

        # ── Scan metadata ─────────────────────────────────────────────────────
        "scan_meta": {
            "scan_name":      raw.get("scan_name"),
            "scan_end":       raw.get("end"),
            "filter_applied": f"CVSS ≥ {min_cvss}" if min_cvss else "none",
        },

        # ── Dashboard header stats ────────────────────────────────────────────
        # Render these as the 5 summary tiles at the top of the report.
        # Labels and order are fixed — do not rename or reorder.
        "dashboard_stats": {
            "Critical Actions":    sum(1 for g in ranked_groups if g["sla"] == "IMMEDIATE"),
            "KEV (Actively Exploited)": cluster_kev_count,
            "Hosts Affected":     f"{len(enriched_hosts)} / {total_assets_scanned}",
            "External Exposure":  external_host_count,
            "Unique Fix Actions": len(ranked_groups),
        },

        # ── Root-cause fix actions (one per engineering task) ─────────────────
        # THIS IS THE AUTHORITATIVE SOURCE FOR ALL CARDS.
        # Each entry = one card = one fix. Do not split or re-group.
        # affected_hosts[] is server-computed and must be used verbatim.
        "fix_actions": ranked_groups,

        # ── Flat CVE lookup table (for collapsible detail only) ───────────────
        "all_cves": all_cves_map,

        "suppressed":      suppressed_items,
        "filters_applied": filters_log,

        # ── Claude rendering instructions ─────────────────────────────────────
        "_instructions": """
RENDER A VULNERABILITY ACTION REPORT matching this exact layout.

═══════════════════════════════════════════════════════
SECTION 1 — REPORT HEADER
═══════════════════════════════════════════════════════
Title: "Vulnerability Action Report"
Subtitle: "Focus on root causes. Fix these actions to eliminate the highest risk."
Top-right metadata block (small text, 3 lines):
  📅 Scan completed: {scan_meta.scan_end}
  ⏱ Scan: {scan_meta.scan_name} | Filter: {scan_meta.filter_applied}
  ⏱ Assets scanned: {dashboard_stats["Hosts Affected"]} (denominator)

═══════════════════════════════════════════════════════
SECTION 2 — SUMMARY TILES (exactly 5, in this order)
═══════════════════════════════════════════════════════
Tile 1: "Critical Actions"          → dashboard_stats["Critical Actions"]    (red icon 🛡)
Tile 2: "KEV (Actively Exploited)"  → dashboard_stats["KEV (Actively Exploited)"] (orange ⚠, red if > 0)
Tile 3: "Hosts Affected"            → dashboard_stats["Hosts Affected"]       (blue 🖥, show as "X / Y")
Tile 4: "External Exposure"         → dashboard_stats["External Exposure"]    (green 🌐, show as "N internet-facing hosts")
Tile 5: "Unique Fix Actions"        → dashboard_stats["Unique Fix Actions"]   (purple 🛡, show as "Root cause actions")

═══════════════════════════════════════════════════════
SECTION 3 — ACTION CARDS (one per fix_actions[] entry)
═══════════════════════════════════════════════════════
Group cards under section headers by SLA:
  IMMEDIATE cards → header "PRIORITIZED ACTIONS" (no separate sub-header needed if all same SLA)
  Use a subtle divider row labeling the SLA tier only if tiers are mixed.

CARD LAYOUT — follow this structure exactly for every card:

┌─────────────────────────────────────────────────────┐
│ [rank badge]  [Title]               [KEV badge?]    │
│ 🖥 {hostname} ({ip}) · {role} · {team}              │
│    Ports: {infer from service}                      │
├──────────────────────────────────────────────────────┤
│ [Due date]  [SLA label]  [N host(s)]  │ Why This    │
│                                        │ Matters     │
│                                        │ {2-3 lines} │
│                                        │ Due: date   │
│                                        │ Impact: ... │
├──────────────────────────────────────────────────────┤
│ 1. CONTAIN (Immediately)              │ 3. VERIFY   │
│   • one imperative sentence           │   • outcome │
│                                       │     check   │
│ 2. FIX (Permanent)                   │             │
│   • exact command or action           │             │
│   • (second bullet only if config    │             │
│     change needed alongside upgrade) │             │
├──────────────────────────────────────────────────────┤
│ ▶ Show affected CVEs ({N} total)   [kev badges...]  │
└─────────────────────────────────────────────────────┘

TITLE RULES:
- Always fix-centric, never vuln-centric. Describe the action, not the vulnerability.
- CORRECT:   "Upgrade Apache HTTP Server"
- CORRECT:   "Secure Redis Configuration"
- CORRECT:   "Upgrade / Replace MySQL Server"
- INCORRECT: "Patch Apache SSRF"
- INCORRECT: "Apply MySQL 5.7.44 Oct 2023 CPU Patch"
- INCORRECT: "Fix CVE-2021-40438"
- Title must not mention CVE IDs, CVE types (SSRF/RCE/etc), or version-specific patch names.
- If advisories_count > 1, the title covers all of them — do not split.

RANK BADGE COLOR:
- IMMEDIATE (KEV or top-tier): red background
- IMMEDIATE (non-KEV):         orange background
- URGENT:                      orange/amber background
- SCHEDULED:                   yellow background

"WHY THIS MATTERS" column (right side of card, 2–3 bullet lines):
- First bullet: single most important signal (e.g. "Actively exploited (KEV)", "No authentication", "Severely outdated (N days)")
- Second bullet: exposure context (e.g. "Remote Code Execution", "External exposure", "Multiple high-severity CVEs")
- Third bullet (optional): impact scope (e.g. "9 total findings resolved")
- Do NOT put CVSS numbers here. Do NOT put CVE IDs here.

CONTAIN step:
- One action: block the specific port/service/protocol at the perimeter.
- Include the exact port number if known from the service type.
- Example: "Block inbound traffic to ports 80/443 from untrusted sources via firewall or WAF rule."

FIX step:
- One primary action + optionally one config command.
- Include the exact target version or config directive.
- If advisories_count > 1: state that this upgrade resolves all N advisories.
- Example: "Upgrade Apache to ≥ 2.4.49: `apt-get install apache2=2.4.49-*` or equivalent."

VERIFY step:
- One outcome-based check. Do NOT mention Nessus plugin IDs.
- Describe what state the engineer should confirm, not which tool to run.
- Example: "Confirm no Apache findings remain on next scan."
- Example: "Confirm connection without credentials is refused."

CVE SECTION (bottom of card):
- KEV CVE IDs: always visible as red/orange badges.
- All other CVEs: collapsed under "▶ Show affected CVEs (N total)" — never pre-expanded.
- If no CVEs: show "▶ Show affected CVEs (detected via plugin — no CVE IDs)" collapsed.
- Never list more than the KEV IDs in the visible card area.

HOST LINE:
- Use ONLY hostnames from affected_hosts[] for that card.
- Never invent, borrow, or carry over a hostname from another card.
- If multiple hosts: list each on its own line under the title.

BADGES ROW (compact, inline):
- [Due YYYY-MM-DD] — always show exact date, never "IMMEDIATE" or "7 days"
- [SLA label] — show IMMEDIATE / URGENT / SCHEDULED as a color-coded pill
- [N host(s)] — count from host_count field
- Drop CVSS badge entirely when in_kev is true.
- Add CVSS badge only for non-KEV cards.

═══════════════════════════════════════════════════════
SECTION 4 — FOOTER
═══════════════════════════════════════════════════════
Two small boxes side by side:
  Left:  "Notes" — 2 bullet lines:
    • "Actions are prioritized by KEV status, exposure, asset criticality, vulnerability severity, and blast radius."
    • "Focus on completing items 1–N first." (N = count of IMMEDIATE items)
  Right: "Priority Guide" — 4 color dots: Critical · High · Medium · Low

═══════════════════════════════════════════════════════
ABSOLUTE RULES (violations break engineer trust)
═══════════════════════════════════════════════════════
1. One card per fix_actions[] entry. Never split a cluster into multiple cards.
2. Use ONLY affected_hosts[] from that entry's own data for the host line.
3. Titles describe the FIX, not the vulnerability or CVE.
4. No more than 3 action steps per card (CONTAIN / FIX / VERIFY).
5. No CVSS numbers anywhere in the visible card body.
6. No Nessus plugin IDs in VERIFY steps.
7. No prose summary paragraph — the cards ARE the summary.
8. KEV CVE IDs visible; all other CVEs collapsed.
9. SLA deadline shown as exact date only; SLA tier shown as colored pill only.
10. advisories_count > 1 means the fix resolves N plugins — merge, don't split.
"""
    }, indent=2)


# =============================================================================
# SECTION 6 — Email
# =============================================================================

@mcp.tool()
def email_owner_reports(enriched_scan_json: str) -> str:
    """
    Send a per-team vulnerability action queue email to each asset owner,
    derived from the output of get_enriched_scan.

    Each owner receives only findings for their own team's assets, sorted
    by priority score. The email includes a summary table with SLA deadlines,
    KEV flags, CVSS scores, and affected host counts.

    Call this when the user asks to "send email report to asset owners" or
    similar. Pass the raw JSON string returned by get_enriched_scan as the
    argument — no further processing needed.

    Args:
        enriched_scan_json: The full JSON string returned by get_enriched_scan.
    """
    try:
        data = json.loads(enriched_scan_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON: {e}"})

    if not data.get("success"):
        return json.dumps({"success": False, "error": "Scan data shows failure; cannot send emails."})

    findings   = data.get("findings", [])
    scan_meta  = data.get("scan_meta", {})
    stats      = data.get("summary_stats", {})
    generated  = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Group findings by team owner ─────────────────────────────────────────
    teams: dict[str, dict] = {}
    for host in findings:
        ctx   = host.get("asset_context", {})
        team  = ctx.get("team") or "Unassigned"
        email = ctx.get("owner_email") or ""
        name  = ctx.get("owner_name")  or team

        if team not in teams:
            teams[team] = {
                "owner_name":  name,
                "owner_email": email,
                "hosts":       [],
                "items":       [],
            }

        for v in host.get("vulnerabilities", []):
            teams[team]["items"].append({
                "hostname":       ctx.get("hostname", host["ip"]),
                "ip":             host["ip"],
                "plugin_name":    v["plugin_name"],
                "severity":       v["severity"],
                "max_cvss":       v["max_cvss"],
                "in_kev":         v["in_kev"],
                "is_external":    host.get("exposure") == "external",
                "priority_score": v["priority_score"],
                "priority_reason": v.get("priority_reason", ""),
                "sla":            v["sla"],
                "sla_deadline":   v.get("sla_deadline", ""),
                "cve_count":      len(v.get("cves", [])),
                "kev_cves":       [c["cve_id"] for c in v.get("cves", []) if c.get("in_kev")],
                "top_cves":       [c["cve_id"] for c in v.get("cves", [])[:3]],
            })

    # ── Send one email per team ───────────────────────────────────────────────
    sent, failed = [], []

    SLA_COLOR = {
        "IMMEDIATE": "#dc2626",
        "URGENT":    "#ea580c",
        "SCHEDULED": "#ca8a04",
        "BACKLOG":   "#2563eb",
    }

    for team, info in teams.items():
        if not info["owner_email"]:
            failed.append({"team": team, "error": "No owner email in CMDB"})
            continue

        items = sorted(info["items"], key=lambda x: x["priority_score"], reverse=True)
        if not items:
            continue

        imm = sum(1 for i in items if i["sla"] == "IMMEDIATE")
        urg = sum(1 for i in items if i["sla"] == "URGENT")
        sch = sum(1 for i in items if i["sla"] == "SCHEDULED")
        kev = sum(1 for i in items if i["in_kev"])
        ext = sum(1 for i in items if i["is_external"])
        top_sla = "IMMEDIATE" if imm else ("URGENT" if urg else ("SCHEDULED" if sch else "BACKLOG"))
        urgency_color = SLA_COLOR.get(top_sla, "#2563eb")

        # ── Plain-text body ───────────────────────────────────────────────────
        lines = [
            f"Vulnerability Action Queue — {team}",
            f"Generated: {generated}  |  Scan: {scan_meta.get('scan_name', 'N/A')}",
            "",
            f"Dear {info['owner_name']},",
            "",
            f"Your team has {len(items)} action item(s) requiring attention.",
            f"  IMMEDIATE : {imm}  (fix within 24-48 hours)",
            f"  URGENT    : {urg}  (fix within 7 days)",
            f"  SCHEDULED : {sch}  (fix within 30 days)",
        ]
        if kev:
            lines.append(f"\n  ⚠ {kev} item(s) are in CISA KEV (confirmed active exploitation).")
        lines += ["", "─" * 60, "Ranked Action Queue", "─" * 60]

        for rank, item in enumerate(items[:20], 1):
            kev_tag = " [KEV]"      if item["in_kev"]      else ""
            ext_tag = " [EXTERNAL]" if item["is_external"] else ""
            deadline = item.get("sla_deadline", item["sla"])
            reason   = item.get("priority_reason", "")
            kev_cves = item.get("kev_cves", [])
            extra    = item["cve_count"] - len(kev_cves)
            cve_line = ""
            if kev_cves:
                cve_line = "     KEV CVEs: " + ", ".join(kev_cves)
                if extra > 0:
                    cve_line += f" +{extra} more"
            lines += [
                "",
                f"#{rank:>2}  Fix by: {deadline}{kev_tag}{ext_tag}",
                f"     {item['plugin_name']}",
                f"     Host: {item['hostname']} ({item['ip']})",
            ]
            if reason:
                lines.append(f"     Why ranked here: {reason}")
            if cve_line:
                lines.append(cve_line)

        lines += [
            "", "─" * 60,
            "SLA Policy (deadlines are exact dates shown above):",
            "  IMMEDIATE : fix within 2 days  (KEV or score ≥ 80)",
            "  URGENT    : fix within 7 days  (score 60–79)",
            "  SCHEDULED : fix within 30 days (score 35–59)",
            "  BACKLOG   : fix within 90 days (score < 35)",
            "",
            "Automated Vulnerability Management — do not reply.",
        ]
        body_text = "\n".join(lines)

        # ── HTML body ─────────────────────────────────────────────────────────
        rows_html = ""
        for rank, item in enumerate(items[:20], 1):
            kev_badge = (
                '<span style="background:#501313;color:#fca5a5;font-size:10px;'
                'padding:1px 5px;border-radius:3px;margin-left:4px;">KEV</span>'
                if item["in_kev"] else ""
            )
            ext_badge = (
                '<span style="background:#1e3a5f;color:#bfdbfe;font-size:10px;'
                'padding:1px 5px;border-radius:3px;margin-left:4px;">EXTERNAL</span>'
                if item["is_external"] else ""
            )
            sla_color   = SLA_COLOR.get(item["sla"], "#2563eb")
            deadline    = item.get("sla_deadline", "")
            reason      = item.get("priority_reason", "")
            # Show only KEV CVE IDs inline; collapse the rest
            kev_cve_str = ""
            if item.get("kev_cves"):
                kev_cve_str = " ".join(
                    f'<span style="background:#501313;color:#fca5a5;font-size:10px;'
                    f'padding:1px 4px;border-radius:3px;">{c}</span>'
                    for c in item["kev_cves"][:3]
                )
            extra_count = item["cve_count"] - len(item.get("kev_cves", []))

            rows_html += f"""
<tr>
  <td style="padding:8px 10px;border-bottom:1px solid #f3f4f6;font-weight:700;
             color:{sla_color};white-space:nowrap;">#{rank}</td>
  <td style="padding:8px 10px;border-bottom:1px solid #f3f4f6;white-space:nowrap;">
    <span style="background:{sla_color};color:white;font-size:10px;padding:2px 7px;
                 border-radius:3px;font-weight:600;">{deadline}</span>
  </td>
  <td style="padding:8px 10px;border-bottom:1px solid #f3f4f6;font-size:13px;">
    {item['plugin_name']}{kev_badge}{ext_badge}<br>
    <span style="color:#6b7280;font-size:11px;">{item['hostname']} ({item['ip']})</span>
    {f'<br><span style="color:#9ca3af;font-size:11px;font-style:italic;">{reason}</span>' if reason else ""}
    {f'<br>{kev_cve_str}' if kev_cve_str else ""}
    {f'<span style="color:#9ca3af;font-size:10px;"> +{extra_count} more CVEs</span>' if extra_count > 0 else ""}
  </td>
  <td style="padding:8px 10px;border-bottom:1px solid #f3f4f6;font-size:12px;
             color:#374151;white-space:nowrap;">{item['max_cvss']:.1f}</td>
</tr>"""

        imm_row = f'<tr style="background:#fee2e2;"><td style="padding:6px 12px;"><strong>IMMEDIATE</strong></td><td style="padding:6px 12px;font-size:20px;font-weight:700;color:#dc2626;">{imm}</td><td style="padding:6px 12px;color:#6b7280;">fix within 24-48 hours</td></tr>'
        urg_row = f'<tr style="background:#ffedd5;"><td style="padding:6px 12px;"><strong>URGENT</strong></td><td style="padding:6px 12px;font-size:20px;font-weight:700;color:#ea580c;">{urg}</td><td style="padding:6px 12px;color:#6b7280;">fix within 7 days</td></tr>'
        sch_row = f'<tr style="background:#fef9c3;"><td style="padding:6px 12px;"><strong>SCHEDULED</strong></td><td style="padding:6px 12px;font-size:20px;font-weight:700;color:#ca8a04;">{sch}</td><td style="padding:6px 12px;color:#6b7280;">fix within 30 days</td></tr>'

        kev_banner = (
            f'<p style="background:#fef2f2;border-left:4px solid #dc2626;padding:10px 14px;'
            f'font-size:13px;margin:12px 0;"><strong>⚠ {kev} item(s)</strong> contain CVEs '
            f'actively exploited in the wild (CISA KEV) — absolute top priority.</p>'
        ) if kev else ""

        ext_banner = (
            f'<p style="background:#eff6ff;border-left:4px solid #2563eb;padding:10px 14px;'
            f'font-size:13px;margin:12px 0;"><strong>{ext} item(s)</strong> affect '
            f'internet-facing assets — these carry a +10 priority bonus.</p>'
        ) if ext else ""

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px;color:#1f2937;">
  <div style="background:{urgency_color};color:white;padding:16px 20px;border-radius:6px 6px 0 0;">
    <h2 style="margin:0;font-size:17px;">⚠ [{top_sla}] Vulnerability Action Queue — {team}</h2>
    <p style="margin:4px 0 0;font-size:12px;opacity:.85;">
      Generated: {generated} · Scan: {scan_meta.get('scan_name', 'N/A')}
    </p>
  </div>
  <div style="background:#f9fafb;border:1px solid #e5e7eb;border-top:none;
              padding:20px;border-radius:0 0 6px 6px;">
    <p>Dear <strong>{info['owner_name']}</strong>,</p>
    <p>Your team has <strong>{len(items)} action item(s)</strong> requiring attention.</p>
    <table style="width:100%;border-collapse:collapse;font-size:12px;margin-bottom:16px;">
      {imm_row}{urg_row}{sch_row}
    </table>
    {kev_banner}{ext_banner}
    <h3 style="font-size:14px;margin:20px 0 8px;">Ranked Action Queue</h3>
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead>
        <tr style="background:#f3f4f6;text-align:left;">
          <th style="padding:7px 10px;">#</th>
          <th style="padding:7px 10px;">Fix By</th>
          <th style="padding:7px 10px;">Finding</th>
          <th style="padding:7px 10px;">CVSS</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
    <p style="margin-top:20px;font-size:11px;color:#9ca3af;">
      Automated Vulnerability Management · do not reply to this email.
    </p>
  </div>
</body>
</html>"""

        subject = f"[{top_sla}] Vulnerability Action Queue — {team} ({len(items)} items)"

        try:
            result = send_email(
                to        = info["owner_email"],
                subject   = subject,
                body_text = body_text,
                body_html = body_html,
            )
            if result["success"]:
                sent.append({
                    "team":         team,
                    "to":           info["owner_email"],
                    "action_count": len(items),
                    "top_sla":      top_sla,
                    "kev_count":    kev,
                })
            else:
                failed.append({"team": team, "to": info["owner_email"], "error": result["error"]})
        except Exception as e:
            failed.append({"team": team, "error": str(e)})

    return json.dumps({
        "success":      len(sent) > 0,
        "total_sent":   len(sent),
        "total_failed": len(failed),
        "sent":         sent,
        "failed":       failed,
    }, indent=2)


@mcp.tool()
def email_test_connection() -> str:
    """
    Test SMTP credentials and connectivity without sending a real email.

    Returns host, port, username, SSL/TLS mode, and success/failure.
    Use this to diagnose email delivery issues before calling
    email_owner_reports.
    """
    result = smtp_test()
    return json.dumps(result, indent=2)


# =============================================================================
# SECTION 7 — Entry point
# =============================================================================

if __name__ == "__main__":
    cmdb_client.init_cmdb()
    mcp.run()
