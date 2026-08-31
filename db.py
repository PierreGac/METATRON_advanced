#!/usr/bin/env python3
"""
METATRON - db.py
MariaDB connection + all read/write/edit/delete operations
Database: metatron
"""

import mysql.connector
from datetime import datetime


# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

_attacks_table_ready = False

ATTACKS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS attacks (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sl_no       INT,
  attack_name TEXT,
  severity    VARCHAR(50),
  target      TEXT,
  danger      TEXT,
  vulns_used  TEXT,
  fix_text    TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
)
"""


def _ensure_attacks_table(conn):
    """Create attacks table on existing installs that predate this schema."""
    global _attacks_table_ready
    if _attacks_table_ready:
        return
    try:
        c = conn.cursor()
        c.execute(ATTACKS_TABLE_SQL)
        conn.commit()
        c.close()
        _attacks_table_ready = True
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass


def get_connection():
    """Returns a MariaDB connection. No password (local setup)."""
    conn = mysql.connector.connect(
        host="localhost",
        user="metatron",
        password="123",
        database="metatron"
    )
    _ensure_attacks_table(conn)
    return conn


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
        (target, now, "active")
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str) -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (sl_no, vuln_name, severity, port, service, description))
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (%s, %s, %s, %s)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted 
        (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        sl_no,
        str(exploit_name or "")[:1000],
        str(tool_used  or "")[:500],
        str(payload    or ""),
        str(result     or "")[:2000],
        str(notes      or "")
    ))
    conn.commit()
    conn.close()


def save_attack(sl_no, attack_name, severity, target, danger, vulns_used, fix_text):
    """Insert a possible-attack row derived from the final LLM pass."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO attacks
        (sl_no, attack_name, severity, target, danger, vulns_used, fix_text)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        sl_no,
        str(attack_name or "")[:1000],
        str(severity or "medium")[:50],
        str(target or ""),
        str(danger or ""),
        str(vulns_used or ""),
        str(fix_text or ""),
    ))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (%s, %s, %s, %s, %s)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM attacks WHERE sl_no = %s", (sl_no,))
    attacks = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()

    conn.close()

    return {
        "history":   history,
        "vulns":     vulns,
        "fixes":     fixes,
        "exploits":  exploits,
        "attacks":   attacks,
        "summary":   summary
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_attacks(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM attacks WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s",
        (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE exploits_attempted SET {field} = %s WHERE id = %s",
        (value, exploit_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_attack(attack_id: int, field: str, value: str):
    """Edit a single field in attacks by id."""
    allowed = {"attack_name", "severity", "target", "danger", "vulns_used", "fix_text"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE attacks SET {field} = %s WHERE id = %s",
        (value, attack_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] attacks.{field} updated for id={attack_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = %s", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_attack(attack_id: int):
    """Delete a single possible-attack row."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM attacks WHERE id = %s", (attack_id,))
    conn.commit()
    conn.close()
    print(f"[+] Attack id={attack_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all 6 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM attacks           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ POSSIBLE ATTACKS ]")
    if data.get("attacks"):
        for a in data["attacks"]:
            print(f"  id={a[0]} | {a[2]} | Severity: {a[3]}")
            print(f"           Target : {a[4]}")
            print(f"           Danger : {a[5]}")
            print(f"           Vulns  : {a[6]}")
            print(f"           Fix    : {a[7]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: metatron")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
