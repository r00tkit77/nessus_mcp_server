import asyncio
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

import nessus_scan
import nvd_client
import kev_client
import cmdb_client
from email_client import send_email, build_owner_email, test_connection as smtp_test

load_dotenv()

server = Server("nessus-vuln-mgmt")


# ── Tool Registry ─────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools():
    return [
        # ── Nessus ──────────────────────────────────────────────────────────
        Tool(
            name="nessus_launch_scan",
            description="Launch the saved full_scan in Nessus (scan ID from .env). Use before get_scan_results.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="nessus_scan_status",
            description="Check the current status of the Nessus scan (running | completed | paused).",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="nessus_get_results",
            description="Fetch completed Nessus scan results for all hosts. Filters out Info severity. Returns per-host findings and full CVE list.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="nessus_test_connection",
            description="Test Nessus API connectivity and credentials.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="nessus_debug_raw",
            description="DEBUG: Return raw Nessus scan API response — shows history entries and host counts. Use to diagnose 0-host issues.",
            inputSchema={"type": "object", "properties": {}}
        ),

        # ── NVD ─────────────────────────────────────────────────────────────
        Tool(
            name="nvd_enrich_cves",
            description="Enrich a list of CVE IDs with NVD data: CVSS score, severity, description, CWE, references. Max 50 CVEs per call.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_ids": {"type": "array", "items": {"type": "string"},
                                "description": "List of CVE IDs e.g. ['CVE-2021-41773']"}
                },
                "required": ["cve_ids"]
            }
        ),
        Tool(
            name="nvd_get_cve",
            description="Get full details for a single CVE ID from NVD.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE ID e.g. CVE-2021-41773"}
                },
                "required": ["cve_id"]
            }
        ),

        # ── CISA KEV ────────────────────────────────────────────────────────
        Tool(
            name="kev_check",
            description="Check which CVEs from a list are in the CISA Known Exploited Vulnerabilities catalog. KEV = actively exploited in the wild.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_ids": {"type": "array", "items": {"type": "string"}},
                    "force_refresh": {"type": "boolean", "description": "Force re-download of KEV catalog", "default": False}
                },
                "required": ["cve_ids"]
            }
        ),
        Tool(
            name="kev_catalog_summary",
            description="Get CISA KEV catalog metadata: version, release date, total entries.",
            inputSchema={"type": "object", "properties": {}}
        ),

        # ── CMDB ────────────────────────────────────────────────────────────
        Tool(
            name="cmdb_get_assets",
            description="Get all assets from the CMDB including owner names, emails, roles, and criticality.",
            inputSchema={"type": "object", "properties": {}}
        ),

        # ── Analysis ────────────────────────────────────────────────────────
        Tool(
            name="generate_summary",
            description=(
                "Generate a full vulnerability assessment report using Claude AI. "
                "Pass in scan results, NVD enrichment, KEV results, and CMDB data as JSON strings. "
                "Produces: executive summary, critical findings, priority list, misconfigs table, "
                "per-host remediation steps, and risk summary table."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "scan_data": {"type": "string", "description": "JSON from nessus_get_results"},
                    "nvd_data":  {"type": "string", "description": "JSON from nvd_enrich_cves"},
                    "kev_data":  {"type": "string", "description": "JSON from kev_check"},
                    "cmdb_data": {"type": "string", "description": "JSON from cmdb_get_assets"},
                },
                "required": ["scan_data", "nvd_data", "kev_data", "cmdb_data"]
            }
        ),

        # ── Email ────────────────────────────────────────────────────────────
        Tool(
            name="email_send_owner_reports",
            description=(
                "Send vulnerability report emails to each asset owner. "
                "Before calling this tool, prepare summary_data as a JSON string mapping "
                "each hostname to its findings and urgency level. "
                "Format: {\"hostname\": {\"findings\": \"...\", \"urgency\": \"HIGH\"}, ...}. "
                "Urgency must be CRITICAL, HIGH, or MEDIUM. "
                "Emails are sent with HTML formatting and urgency-based color coding."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "summary_data": {
                        "type": "string",
                        "description": (
                            "JSON string mapping hostname -> {findings: str, urgency: str}. "
                            "Example: {\"target-apache\": {\"findings\": \"CVE-2021-41773 CVSS 7.5...\", \"urgency\": \"CRITICAL\"}}"
                        )
                    }
                },
                "required": ["summary_data"]
            }
        ),
        Tool(
            name="email_test_connection",
            description="Test SMTP connection and credentials without sending a real email.",
            inputSchema={"type": "object", "properties": {}}
        ),
    ]


# ── Tool Dispatch ─────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    # ── Nessus tools ──────────────────────────────────────────────────────────
    if   name == "nessus_launch_scan":      result = nessus_scan.launch_scan()
    elif name == "nessus_scan_status":      result = nessus_scan.get_scan_status()
    elif name == "nessus_get_results":      result = nessus_scan.get_scan_results()
    elif name == "nessus_test_connection":  result = nessus_scan.test_connection()
    elif name == "nessus_debug_raw":         result = nessus_scan.get_raw_scan_debug()

    # ── NVD tools ─────────────────────────────────────────────────────────────
    elif name == "nvd_enrich_cves":         result = nvd_client.enrich_cves(arguments["cve_ids"])
    elif name == "nvd_get_cve":             result = nvd_client.get_cve_details(arguments["cve_id"])

    # ── KEV tools ─────────────────────────────────────────────────────────────
    elif name == "kev_check":               result = kev_client.check_kev(
                                                arguments["cve_ids"],
                                                arguments.get("force_refresh", False)
                                            )
    elif name == "kev_catalog_summary":     result = kev_client.get_kev_summary()

    # ── CMDB tools ────────────────────────────────────────────────────────────
    elif name == "cmdb_get_assets":         result = cmdb_client.get_all_assets()

    # ── Analysis tools ────────────────────────────────────────────────────────
    elif name == "generate_summary":
        text = _generate_summary(
            arguments["scan_data"],
            arguments["nvd_data"],
            arguments["kev_data"],
            arguments["cmdb_data"]
        )
        return [TextContent(type="text", text=text)]

    # ── Email tools ───────────────────────────────────────────────────────────
    elif name == "email_send_owner_reports": result = _send_owner_emails(arguments["summary_data"])
    elif name == "email_test_connection":    result = smtp_test()

    else:
        result = {"error": f"Unknown tool: {name}"}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


# ── Analysis implementation ───────────────────────────────────────────────────

def _generate_summary(scan_data: str, nvd_data: str, kev_data: str, cmdb_data: str) -> str:
    """
    Return all four data sources combined into one structured block.
    Claude Desktop reads this and generates the report itself — no internal API call needed.
    """
    return f"""# VULNERABILITY ASSESSMENT DATA
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}

=== NESSUS SCAN RESULTS ===
{scan_data}

=== NVD CVE ENRICHMENT ===
{nvd_data}

=== CISA KEV (Known Exploited Vulnerabilities) ===
{kev_data}

=== CMDB (Asset Inventory) ===
{cmdb_data}
"""


# ── Email implementation ──────────────────────────────────────────────────────

def _send_owner_emails(summary_data: str) -> dict:
    """
    Send vulnerability report emails to asset owners.

    summary_data format (Claude Desktop prepares this before calling the tool):
      JSON string: {"hostname": {"findings": "...", "urgency": "HIGH"}, ...}
      OR plain text report (falls back to sending the full report to each owner).

    Claude Desktop extracts per-host findings from the report and passes them here
    as structured JSON — no internal API call needed.
    """
    assets = cmdb_client.get_all_assets().get("assets", [])
    sent, failed = [], []

    # Try to parse as structured JSON first (preferred path from Claude Desktop)
    try:
        host_findings = json.loads(summary_data)
        structured = True
    except (json.JSONDecodeError, TypeError):
        host_findings = {}
        structured = False

    for asset in assets:
        ip          = asset["ip_address"]
        hostname    = asset["hostname"]
        owner_name  = asset["owner_name"]
        owner_email = asset["owner_email"]
        team        = asset["team"]

        try:
            if structured and hostname in host_findings:
                entry         = host_findings[hostname]
                findings_text = entry.get("findings", summary_data)
                urgency       = entry.get("urgency", "HIGH").upper()
            else:
                # Fallback: send the full report as-is
                findings_text = summary_data
                first_line    = summary_data.split("\n")[0].strip().upper()
                urgency = (
                    "CRITICAL" if "CRITICAL" in first_line else
                    "HIGH"     if "HIGH"     in first_line else
                    "MEDIUM"
                )

            subject, body_text, body_html = build_owner_email(
                owner_name=owner_name,
                hostname=hostname,
                ip=ip,
                findings_text=findings_text,
                urgency=urgency
            )

            result = send_email(
                to=owner_email,
                subject=subject,
                body_text=body_text,
                body_html=body_html
            )

            if result["success"]:
                sent.append({"to": owner_email, "host": hostname, "ip": ip,
                             "urgency": urgency, "team": team})
            else:
                failed.append({"to": owner_email, "host": hostname, "error": result["error"]})

        except Exception as e:
            failed.append({"to": owner_email, "host": hostname, "error": str(e)})

    return {
        "sent":         sent,
        "failed":       failed,
        "total_sent":   len(sent),
        "total_failed": len(failed),
    }


# ── Entry Point ───────────────────────────────────────────────────────────────

async def main():
    cmdb_client.init_cmdb()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
