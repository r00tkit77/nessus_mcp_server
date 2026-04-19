import os
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "cmdb.db")

# Seed data: the 4 Docker target containers used in the lab environment
_SEED_ASSETS = [
    (1, "172.17.0.2", "target-apache", "Linux", "Web Server",   "dev", "high",   "Arnav",  "arnav@example.com",  "WebOps"),
    (2, "172.17.0.3", "target-mysql",  "Linux", "Database",     "dev", "high",   "Arnav",   "arnav@example.com",    "DataOps"),
    (3, "172.17.0.4", "target-php",    "Linux", "App Server",   "dev", "medium", "Dhivyan",  "dhivyan@example.com",  "AppDev"),
    (4, "172.17.0.5", "target-redis",  "Linux", "Cache Server", "dev", "medium", "Dhivyan", "dhivyan@example.com",   "AppDev"),
]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Initialisation ────────────────────────────────────────────────────────────

def init_cmdb() -> dict:
    """
    Create the assets table if it doesn't exist and seed with default lab targets.
    Safe to call multiple times — uses INSERT OR IGNORE for seed rows.
    """
    try:
        conn = _connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                id          INTEGER PRIMARY KEY,
                ip_address  TEXT UNIQUE,
                hostname    TEXT,
                os          TEXT,
                role        TEXT,
                environment TEXT,
                criticality TEXT,
                owner_name  TEXT,
                owner_email TEXT,
                team        TEXT
            )
        """)
        conn.executemany(
            "INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?,?,?,?,?,?)",
            _SEED_ASSETS
        )
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        conn.close()
        return {"success": True, "db_path": DB_PATH, "total_assets": count}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Read operations ───────────────────────────────────────────────────────────

def get_all_assets() -> dict:
    """Return all assets in the CMDB."""
    try:
        conn   = _connect()
        rows   = conn.execute("SELECT * FROM assets ORDER BY id").fetchall()
        conn.close()
        assets = [dict(r) for r in rows]
        return {"success": True, "assets": assets, "total": len(assets)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_asset_by_ip(ip: str) -> dict:
    """Look up a single asset by IP address."""
    try:
        conn = _connect()
        row  = conn.execute(
            "SELECT * FROM assets WHERE ip_address = ?", (ip,)
        ).fetchone()
        conn.close()
        if row:
            return {"success": True, "found": True, "asset": dict(row)}
        return {"success": True, "found": False, "ip": ip}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_asset_by_hostname(hostname: str) -> dict:
    """Look up a single asset by hostname (case-insensitive)."""
    try:
        conn = _connect()
        row  = conn.execute(
            "SELECT * FROM assets WHERE LOWER(hostname) = LOWER(?)", (hostname,)
        ).fetchone()
        conn.close()
        if row:
            return {"success": True, "found": True, "asset": dict(row)}
        return {"success": True, "found": False, "hostname": hostname}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_assets_by_owner(owner_email: str) -> dict:
    """Return all assets belonging to a specific owner email."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM assets WHERE LOWER(owner_email) = LOWER(?)", (owner_email,)
        ).fetchall()
        conn.close()
        assets = [dict(r) for r in rows]
        return {"success": True, "assets": assets, "total": len(assets), "owner_email": owner_email}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_assets_by_team(team: str) -> dict:
    """Return all assets belonging to a specific team."""
    try:
        conn = _connect()
        rows = conn.execute(
            "SELECT * FROM assets WHERE LOWER(team) = LOWER(?)", (team,)
        ).fetchall()
        conn.close()
        assets = [dict(r) for r in rows]
        return {"success": True, "assets": assets, "total": len(assets), "team": team}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Write operations ──────────────────────────────────────────────────────────

def upsert_asset(
    ip_address:  str,
    hostname:    str,
    os:          str       = None,
    role:        str       = None,
    environment: str       = None,
    criticality: str       = None,
    owner_name:  str       = None,
    owner_email: str       = None,
    team:        str       = None,
) -> dict:
    """
    Insert a new asset or update an existing one (matched by ip_address).
    Returns the full saved asset record.
    """
    try:
        conn = _connect()
        conn.execute("""
            INSERT INTO assets (ip_address, hostname, os, role, environment,
                                criticality, owner_name, owner_email, team)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                hostname    = excluded.hostname,
                os          = excluded.os,
                role        = excluded.role,
                environment = excluded.environment,
                criticality = excluded.criticality,
                owner_name  = excluded.owner_name,
                owner_email = excluded.owner_email,
                team        = excluded.team
        """, (ip_address, hostname, os, role, environment,
              criticality, owner_name, owner_email, team))
        conn.commit()
        row = conn.execute(
            "SELECT * FROM assets WHERE ip_address = ?", (ip_address,)
        ).fetchone()
        conn.close()
        return {"success": True, "asset": dict(row)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def delete_asset(ip_address: str) -> dict:
    """Remove an asset from the CMDB by IP address."""
    try:
        conn    = _connect()
        changes = conn.execute(
            "DELETE FROM assets WHERE ip_address = ?", (ip_address,)
        ).rowcount
        conn.commit()
        conn.close()
        if changes:
            return {"success": True, "deleted": True, "ip_address": ip_address}
        return {"success": True, "deleted": False, "ip_address": ip_address,
                "message": "No asset found with that IP"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Diagnostics ───────────────────────────────────────────────────────────────

def get_stats() -> dict:
    """Return a summary of CMDB contents: counts by team, criticality, environment."""
    try:
        conn = _connect()

        total = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]

        by_team = {
            row["team"]: row["cnt"]
            for row in conn.execute(
                "SELECT team, COUNT(*) AS cnt FROM assets GROUP BY team"
            ).fetchall()
        }
        by_criticality = {
            row["criticality"]: row["cnt"]
            for row in conn.execute(
                "SELECT criticality, COUNT(*) AS cnt FROM assets GROUP BY criticality"
            ).fetchall()
        }
        by_env = {
            row["environment"]: row["cnt"]
            for row in conn.execute(
                "SELECT environment, COUNT(*) AS cnt FROM assets GROUP BY environment"
            ).fetchall()
        }

        conn.close()
        return {
            "success":        True,
            "total_assets":   total,
            "by_team":        by_team,
            "by_criticality": by_criticality,
            "by_environment": by_env,
            "db_path":        DB_PATH,
            "generated_at":   datetime.now().isoformat(),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def test_connection() -> dict:
    """Verify the SQLite DB is reachable and the assets table exists."""
    try:
        conn   = _connect()
        tables = [
            r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        count  = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] \
                 if "assets" in tables else None
        conn.close()
        return {
            "success":       True,
            "db_path":       DB_PATH,
            "tables":        tables,
            "asset_count":   count,
            "table_exists":  "assets" in tables,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "db_path": DB_PATH}


if __name__ == "__main__":
    print("Initialising CMDB...")
    r = init_cmdb()
    if r["success"]:
        print(f"✅ DB ready at {r['db_path']} — {r['total_assets']} assets loaded")
        stats = get_stats()
        print(f"   Teams        : {stats['by_team']}")
        print(f"   Criticality  : {stats['by_criticality']}")
    else:
        print(f"❌ {r['error']}")
