#!/usr/bin/env python3
"""
METATRON - metatron.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python metatron.py
"""
from export import export_menu
import os
import sys
from contextlib import contextmanager
from pathlib import Path
from db import (
    get_connection,
    create_session,
    save_vulnerability,
    save_fix,
    save_exploit,
    save_summary,
    get_all_history,
    get_session,
    get_vulnerabilities,
    get_fixes,
    get_exploits,
    edit_vulnerability,
    edit_fix,
    edit_exploit,
    edit_summary_risk,
    delete_vulnerability,
    delete_exploit,
    delete_fix,
    delete_full_session,
    print_history,
    print_session
)
from tools import collect_install_status, interactive_tool_run, format_recon_for_llm, run_default_recon
from llm import analyse_target, MODEL_NAME, OLLAMA_URL

LAST_RUN_LOG = Path(__file__).resolve().parent / "last_run.log"


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    os.system("clear")
    print("""
\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mAI Penetration Testing Assistant  |  Advanced Edition  |  Model: metatron-qwen  |  Parrot OS\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


class _TeeStream:
    """Write to the live console and a log file at the same time."""

    def __init__(self, primary, log_file):
        self.primary = primary
        self.log_file = log_file

    def write(self, data):
        self.primary.write(data)
        self.primary.flush()
        try:
            self.log_file.write(data)
            self.log_file.flush()
        except OSError:
            pass
        return len(data) if isinstance(data, str) else 0

    def flush(self):
        self.primary.flush()
        try:
            self.log_file.flush()
        except OSError:
            pass

    def isatty(self):
        return bool(getattr(self.primary, "isatty", lambda: False)())

    def fileno(self):
        return self.primary.fileno()

    def __getattr__(self, name):
        return getattr(self.primary, name)


@contextmanager
def scan_console_log():
    """Copy recon + AI console output to last_run.log (overwrite each scan)."""
    orig_out, orig_err = sys.stdout, sys.stderr
    fh = None
    try:
        fh = open(LAST_RUN_LOG, "w", encoding="utf-8", errors="replace")
        sys.stdout = _TeeStream(orig_out, fh)
        sys.stderr = _TeeStream(orig_err, fh)
        yield LAST_RUN_LOG
    finally:
        sys.stdout = orig_out
        sys.stderr = orig_err
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def new_scan():
    divider("NEW SCAN")
    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    # create session in history table first
    sl_no = create_session(target)
    success(f"Session created — SL# {sl_no}")

    with scan_console_log():
        divider("RECON")
        info("Choose recon tools to run:")
        raw_scan = interactive_tool_run(target)

        if not raw_scan.strip():
            warn("No scan data collected. Aborting.")
            delete_full_session(sl_no)
            return

        divider("AI ANALYSIS")
        result = analyse_target(target, raw_scan)

    # ── save everything to DB ──────────────────
    divider("SAVING TO DATABASE")

    # save vulnerabilities and their fixes
    for vuln in result["vulnerabilities"]:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"]
        )
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="ai")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}]")

    # save exploits
    for exp in result["exploits"]:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"]
        )
        success(f"Saved exploit: {exp['exploit_name']}")

    # save summary
    save_summary(
        sl_no,
        result["raw_scan"],
        result["full_response"],
        result["risk_level"]
    )

    success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    # show results and offer edit/delete
    data = get_session(sl_no)
    print_session(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)

    sl_no_str = prompt("Enter SL# to view details (or press Enter to go back): ")
    if not sl_no_str:
        return

    try:
        sl_no = int(sl_no_str)
    except ValueError:
        error("Invalid SL#.")
        return

    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return

    print_session(data)

    if confirm("Export this session?"):
        export_menu(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1] Edit a vulnerability")
        print("  [2] Edit a fix")
        print("  [3] Edit an exploit")
        print("  [4] Edit risk level")
        print("  [5] Delete a vulnerability")
        print("  [6] Delete a fix")
        print("  [7] Delete an exploit")
        print("  [8] Delete FULL session (all tables)")
        print("  [9] Back")
        divider()

        choice = prompt("Choice: ")

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")

            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))

        # ── DELETE FULL SESSION ───────────────
        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "9":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────

def check_db():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        error(f"MariaDB connection failed: {e}")
        error("Make sure MariaDB is running: sudo systemctl start mariadb")
        return False


PYTHON_MODULES = (
    ("mysql.connector", "mysql-connector-python"),
    ("requests", "requests"),
    ("bs4", "beautifulsoup4"),
    ("ddgs", "ddgs"),
    ("playwright", "playwright"),
    ("reportlab", "reportlab"),
    ("rich", "rich"),
    ("lxml", "lxml"),
    ("PIL", "pillow"),
)


def _print_check_row(ok: bool, name: str, detail: str, hint: str = "") -> None:
    if ok:
        extra = f"  \033[90m{detail}\033[0m" if detail else ""
        print(f"  \033[92m[✓]\033[0m {name}{extra}")
    else:
        print(f"  \033[91m[✗]\033[0m {name}  \033[90m{detail}\033[0m")
        if hint:
            print(f"      \033[93m→ {hint}\033[0m")


def _check_python_packages() -> tuple:
    ok_n = miss_n = 0
    print("\n  Python packages")
    for module, pip_name in PYTHON_MODULES:
        try:
            __import__(module)
            _print_check_row(True, pip_name, module)
            ok_n += 1
        except Exception as exc:
            _print_check_row(False, pip_name, str(exc), f"pip install {pip_name}")
            miss_n += 1
    return ok_n, miss_n


def _check_ollama() -> tuple:
    print("\n  Ollama")
    ok_n = miss_n = 0
    try:
        import requests
        base = OLLAMA_URL.rsplit("/api/", 1)[0]
        resp = requests.get(base, timeout=3)
        alive = resp.status_code < 500
    except Exception as exc:
        _print_check_row(False, "ollama API", str(exc), "ollama serve")
        _print_check_row(False, f"model {MODEL_NAME}", "API unreachable", f"ollama create {MODEL_NAME} -f Modelfile")
        return 0, 2
    _print_check_row(alive, "ollama API", base)
    if alive:
        ok_n += 1
    else:
        miss_n += 1
    model_ok = False
    detail = "not listed"
    try:
        import requests
        tags = requests.get(f"{base}/api/tags", timeout=5).json()
        names = [m.get("name", "") for m in tags.get("models", [])]
        model_ok = any(MODEL_NAME in n for n in names)
        if model_ok:
            detail = next(n for n in names if MODEL_NAME in n)
        elif names:
            detail = "installed: " + ", ".join(names[:6])
    except Exception as exc:
        detail = str(exc)
    _print_check_row(
        model_ok,
        f"model {MODEL_NAME}",
        detail,
        f"ollama create {MODEL_NAME} -f Modelfile && ollama run {MODEL_NAME}",
    )
    if model_ok:
        ok_n += 1
    else:
        miss_n += 1
    return ok_n, miss_n


def _check_mariadb() -> tuple:
    print("\n  Database")
    try:
        conn = get_connection()
        conn.close()
        _print_check_row(True, "MariaDB", "metatron@localhost")
        return 1, 0
    except Exception as exc:
        _print_check_row(
            False,
            "MariaDB",
            str(exc),
            "sudo systemctl start mariadb  (user metatron / db metatron)",
        )
        return 0, 1


def check_install():
    """Verify Python deps, scanners, wordlist, MariaDB, Ollama, Playwright."""
    divider("INSTALLATION CHECK")
    info("Checking requirements, tools, and services...")
    ok_n = miss_n = 0

    p_ok, p_miss = _check_python_packages()
    ok_n += p_ok
    miss_n += p_miss

    print("\n  Scan tools")
    rows = collect_install_status()
    for row in rows:
        if row["group"] == "tools":
            _print_check_row(row["ok"], row["name"], row["detail"], row["hint"])
            if row["ok"]:
                ok_n += 1
            else:
                miss_n += 1

    print("\n  Wordlists & runtime")
    for row in rows:
        if row["group"] in ("wordlist", "runtime"):
            _print_check_row(row["ok"], row["name"], row["detail"], row["hint"])
            if row["ok"]:
                ok_n += 1
            else:
                miss_n += 1

    d_ok, d_miss = _check_mariadb()
    ok_n += d_ok
    miss_n += d_miss

    o_ok, o_miss = _check_ollama()
    ok_n += o_ok
    miss_n += o_miss

    divider()
    if miss_n == 0:
        success(f"All {ok_n} checks passed.")
    else:
        warn(f"{ok_n} ok, {miss_n} missing. Install hints are listed above.")
        info("On Debian/Ubuntu, sudo ./install.sh covers most of these.")


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Check installation")
        print("  \033[92m[4]\033[0m  Exit")
        divider()

        choice = prompt("metatron> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "3":
            check_install()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "4":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if not check_db():
        sys.exit(1)
    main_menu()
