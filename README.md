
# NESSUS MCP Server

A **Model Context Protocol (MCP) server** for vulnerability management automation. This system integrates Tenable Nessus scanning with CVE enrichment from NIST NVD, threat intelligence from CISA KEV, asset context from a CMDB, and **LLM-driven reasoning** to prioritize and report vulnerabilities.

---

## Overview

This MCP server enables an AI agent (e.g., Claude Desktop) to:

* Launch and monitor **Nessus vulnerability scans**
* Fetch and process scan results across multiple assets
* Enrich vulnerabilities using **NVD (CVSS, severity, CWE, references)**
* Identify actively exploited vulnerabilities via **CISA KEV**
* Map vulnerabilities to assets using a **CMDB (ownership, criticality, team)**
* Perform **LLM-driven analysis and prioritization**
* Generate and send **structured vulnerability reports** via email

---

## Work Flow

1. Launch Nessus scan
2. Process scan results (hosts + vulnerabilities + CVEs)
3. Enrich CVEs using NVD API
4. Check CVEs against CISA KEV catalog
5. Generate structured report with vulnerability insights, misconfigurations, recommendations, etc.
6. Send reports to respective asset owners via email

---

## Architecture

```

cmdb-nvd-nessus-mcp/
├── mcp_server.py       # MCP server (tool definitions + orchestration)
├── nessus_scan.py      # Nessus API client (scan + results)
├── nvd_client.py       # NVD API client (CVEs enrichment)
├── kev_client.py       # CISA KEV client (threat Intel)
├── cmdb_client.py      # SQLite CMDB (asset inventory)
├── email_client.py     # SMTP email client
├── .env                # Environment variables (API keys, config)
└── README.md

```

---

## Available MCP Tools

| Tool                          | Description                                                   | Example Prompt                                  |
| ----------------------------- | ------------------------------------------------------------- | ----------------------------------------------- |
| `nessus_launch_scan`          | Launch predefined Nessus scan                                 | "Start vulnerability scan"                      |
| `nessus_scan_status`          | Check current scan status                                     | "Is the scan complete?"                         |
| `nessus_get_results`          | Fetch scan results and CVEs                                   | "Get scan results"                              |
| `nessus_test_connection`      | Validate Nessus API connectivity                              | "Test Nessus connection"                        |
| `nvd_enrich_cves`             | Enrich CVEs with NVD data                                     | "Enrich CVEs with CVSS details"                 |
| `nvd_get_cve`                 | Get full details for a CVE                                    | "Explain CVE-2021-41773"                        |
| `kev_check`                   | Check CVEs against KEV (actively exploited)                   | "Which CVEs are exploited?"                     |
| `kev_catalog_summary`         | Get KEV dataset metadata                                      | "Show KEV summary"                              |
| `cmdb_get_assets`             | Retrieve all CMDB assets                                      | "List all assets"                               |
| `generate_summary`            | Generate structured vulnerability report input                | "Summarize findings"                            |
| `email_send_owner_reports`    | Send per-asset vulnerability reports                          | "Send reports to owners"                        |
| `email_test_connection`       | Validate SMTP configuration                                   | "Test email setup"                              |

---

## Guardrails

### Security Guardrails

* **Environment-based secrets** – API keys (Nessus, NVD, SMTP) stored securely in `.env`
* **Trusted data sources** – CVEs from NVD, KEV from official CISA feed
* **No arbitrary execution** – MCP tools restrict operations to predefined logic
* **API-based authentication** – Nessus accessed via API keys (no session handling)

---

### Operational Guardrails

* **NVD rate limiting** – adaptive delay based on API key usage
* **KEV caching** – reduces repeated external requests
* **Filtered scan results** – informational findings excluded
* **Bounded enrichment** – CVE processing capped per request
* **Structured outputs** – consistent JSON responses for AI consumption
* **Auto-initialized CMDB** – ensures asset inventory is always available

---

## Limitations

### ❗ Nessus Dependency

* Requires Nessus running locally (`https://localhost:8834`)
* Scan must be preconfigured (SCAN_ID)

---

### ❗ API Rate Limits

* NVD API limits can slow CVE enrichment
* Large scans may introduce latency

---

### ❗ KEV Data Freshness

* KEV data is cached and not strictly real-time
* May miss newly added exploited vulnerabilities temporarily

---

### ❗ No Async Processing

* No job queue or background workers
* Entire workflow runs synchronously

---

### ❗ LLM Dependency

* Accuracy of prioritization depends on LLM reasoning
* Potential for hallucinations if prompts are weak

---

### ❗ Limited Scalability

* CVE enrichment capped per request (max ~50 CVEs)
* Large environments require batching or optimization

---




