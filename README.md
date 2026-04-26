# NESSUS MCP Server

A **Model Context Protocol (MCP)** server that converts raw vulnerability scan data into **prioritized, root-cause–based remediation actions**. It integrates Tenable Nessus, NVD enrichment, CISA KEV intelligence, and CMDB context to produce **actionable fix queues instead of CVE-heavy reports**.

---

## Overview

This MCP server enables an AI agent (e.g., Claude Desktop) to:

* Execute and monitor Nessus vulnerability scans
* Extract vulnerabilities and CVEs at plugin level (accurate CVE mapping)
* Enrich vulnerabilities using NVD (CVSS, severity, metadata)
* Identify actively exploited vulnerabilities (KEV)
* Correlate vulnerabilities with assets using CMDB (ownership, exposure, criticality)
* Transform findings into root-cause fix actions
* Generate prioritized remediation reports and send them to owners via email

---

## Work Flow

1. Execute or retrieve Nessus scan results
2. Normalize findings (remove noise, extract CVEs correctly)
3. Enrich CVEs with NVD metadata
4. Correlate CVEs with CISA KEV (exploitation signal)
5. Attach asset context from CMDB (owner, exposure, role)
6. Apply transformation process to cluster CVEs into remediation action items
8. Generate prioritized action report
9. Send reports to asset owners

---

## Transformation (Core Output Processing)

This system converts raw scan output into remediation actions through a structured pipeline:

1. **Normalization**

   * Extract vulnerabilities per host from Nessus
   * Fetch plugin-level details to accurately retrieve CVEs
   * Remove informational findings and duplicate noise
   * Build structured dataset: `host → vulnerabilities → CVEs`

2. **Enrichment**

   * Add NVD data (CVSS score, severity, description, publish date)
   * Tag CVEs present in CISA KEV (actively exploited)
   * Attach CMDB context (team, asset role, exposure, criticality)

3. **Scoring**

   * Compute priority score using:

     * CVSS (non-linear buckets)
     * KEV presence (highest weight)
     * Exposure (external vs internal)
     * Asset criticality
     * Blast radius (number of affected hosts)
     * Vulnerability age
   * Assign SLA: **IMMEDIATE / URGENT / SCHEDULED / BACKLOG**

4. **Root Cause Clustering**

   * Group findings by:

     * Software family (Apache, MySQL, Redis, etc.)
     * Affected host set
   * Collapse multiple CVEs and plugins into single fix actions
   * Enforce rule: one cluster = one remediation task

5. **Action Generation**

   * Convert clusters into fix-oriented tasks:

     * Example: multiple Apache CVEs → “Upgrade Apache HTTP Server”
   * Each action includes:

     * Affected hosts (explicit list)
     * Priority score and SLA
     * Minimal steps: contain → fix → verify
     * Deduplication of overlapping fixes

6. **Rendering**

   * Structured JSON is passed to LLM
   * LLM generates:

     * Ranked action queue
     * Human-readable summaries
     * Email-ready reports

Final Output:
A short list of high-impact fixes replacing hundreds of individual CVEs

---

## Architecture

```id="arch01"
cmdb-nvd-nessus-mcp/
├── mcp_server.py       # MCP server (tool orchestration + scoring + clustering)
├── nessus_scan.py      # Nessus API client (scan + plugin-level CVE extraction)
├── nvd_client.py       # NVD API client (CVSS + metadata enrichment)
├── kev_client.py       # CISA KEV client (exploitation intelligence)
├── cmdb_client.py      # SQLite CMDB (asset context)
├── email_client.py     # SMTP email delivery
├── .env                # Environment variables (API keys, config)
└── README.md
```

---

## Available MCP Tools

| Tool                       | Description                            | Example Prompt              |
| -------------------------- | -------------------------------------- | --------------------------- |
| `nessus_launch_scan`       | Launch predefined Nessus scan          | "Start vulnerability scan"  |
| `nessus_scan_status`       | Check current scan status              | "Is the scan complete?"     |
| `nessus_get_results`       | Fetch scan results with CVE extraction | "Get scan results"          |
| `nessus_test_connection`   | Validate Nessus API connectivity       | "Test Nessus connection"    |
| `nvd_enrich_cves`          | Enrich CVEs with CVSS + metadata       | "Enrich CVEs with details"  |
| `nvd_get_cve`              | Retrieve detailed CVE info             | "Explain CVE-2021-41773"    |
| `kev_check`                | Identify actively exploited CVEs       | "Which CVEs are in KEV?"    |
| `kev_catalog_summary`      | KEV dataset summary                    | "Show KEV summary"          |
| `cmdb_get_assets`          | Fetch asset inventory                  | "List all assets"           |
| `generate_summary`         | Generate prioritized fix actions       | "Summarize vulnerabilities" |
| `email_send_owner_reports` | Send reports to asset owners           | "Send reports to owners"    |
| `email_test_connection`    | Validate SMTP configuration            | "Test email setup"          |

---

## Guardrails

### Security Guardrails

* API keys stored securely in `.env`
* Only trusted sources used (NVD, KEV, Nessus)
* No arbitrary command execution via MCP tools
* Strict API-based authentication for Nessus

---

### Operational Guardrails

* NVD rate limiting handled with adaptive delays
* KEV data cached to reduce repeated requests
* Informational findings filtered out early
* CVE enrichment capped to avoid API overload
* Consistent structured JSON outputs
* CMDB auto-initialized for guaranteed asset context

---

## Limitations

### ❗ Nessus Dependency

* Requires local or accessible Nessus instance
* Scan must be preconfigured (SCAN_ID)

---

### ❗ API Rate Limits

* NVD API can slow enrichment for large scans
* High-volume environments require batching

---

### ❗ KEV Data Freshness

* KEV feed is cached (not strictly real-time)
* Newly exploited CVEs may have slight delay

---

### ❗ No Async Processing

* Entire pipeline runs synchronously
* No background workers or job queue

---

### ❗ LLM Dependency

* Final report clarity depends on LLM output quality
* Strict prompting required to avoid hallucinations

---

### ❗ Limited Scalability

* CVE enrichment capped (~50 per batch)
* Large-scale deployments need optimization
