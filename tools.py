#!/usr/bin/env python3
"""
METATRON - tools.py
Recon and web-testing tool runners — output is streamed live, saved to disk,
and returned as strings to feed into the LLM.
OS: Parrot OS (tools pre-installed or easily available)
"""

import copy
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "tools_config.json"

TOOL_INSTALL_HINTS = {
    "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
    "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "sudo apt install httpx-toolkit  # or: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && export PATH=\"$(go env GOPATH)/bin:$PATH\"",
    "httpx-toolkit": "sudo apt install httpx-toolkit",
    "dalfox": "go install -v github.com/hahwul/dalfox/v2@latest  # then: export PATH=\"$(go env GOPATH)/bin:$PATH\"",
    "ffuf": "sudo apt install ffuf || go install github.com/ffuf/ffuf/v2@latest",
    "sqlmap": "git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap  # apt 1.9.x is flagged outdated",
    "wapiti": "pip install -U wapiti3  # apt 3.0.x has a broken wapp database",
    "commix": "git clone https://github.com/commixproject/commix.git /opt/commix  # apt is often stale",
    "wpscan": "sudo apt install wpscan || sudo gem install wpscan",
    "playwright": "pip install playwright && playwright install chromium",
    "testssl.sh": "sudo apt install testssl.sh",
    "zaproxy": "sudo apt install zaproxy  # binary may be zap.sh",
    "arp-scan": "sudo apt install arp-scan",
}

DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
WORDLIST_CANDIDATES = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)

DEFAULT_CONFIG = {
    "_global": {
        "max_log_lines": 2000,
        "timeout_retry_multiplier": 2,
        "results_dir": "scan_results",
    },
    "nmap": {"timeout": 180, "args": ["-sV", "-sC", "-T4", "--open", "{target}"], "extra_args": []},
    "whois": {"timeout": 30, "args": ["{target}"], "extra_args": []},
    "whatweb": {"timeout": 60, "args": ["-a", "3", "{target}"], "extra_args": []},
    "curl": {"timeout": 20, "args": ["-I", "--max-time", "10"], "extra_args": []},
    "dig": {"timeout": 15, "args": ["+short"], "extra_args": []},
    "nikto": {"timeout": 300, "args": ["-h", "{url}", "-ssl", "-nointeractive"], "extra_args": []},
    "gobuster": {
        "timeout": 300,
        "wordlist": DEFAULT_WORDLIST,
        "args": ["dir", "-u", "{url}", "-w", "{wordlist}", "-r", "-e"],
        "extra_args": [],
    },
    "arp-scan": {"timeout": 60, "args": ["--ignoredups", "{target}"], "extra_args": []},
    "sslscan": {"timeout": 240, "args": ["--no-colour", "{target}"], "extra_args": []},
    "testssl.sh": {"timeout": 300, "args": ["{target}"], "extra_args": []},
    "katana": {"timeout": 180, "depth": 2, "args": ["-u", "{url}", "-d", "{depth}", "-jc"], "extra_args": []},
    "nuclei": {"timeout": 300, "args": ["-u", "{url}"], "extra_args": []},
    "httpx": {
        "timeout": 60,
        "args": ["-u", "{url}", "-title", "-tech-detect", "-status-code"],
        "extra_args": [],
    },
    "ffuf": {
        "timeout": 300,
        "wordlist": DEFAULT_WORDLIST,
        "args": ["-u", "{url}/FUZZ", "-w", "{wordlist}"],
        "extra_args": [],
    },
    "sqlmap": {
        "timeout": 420,
        "crawl": 1,
        "args": ["-u", "{url}", "--batch", "--crawl={crawl}"],
        "extra_args": [],
    },
    "wapiti": {
        "timeout": 120,
        "idle_reset": True,
        "max_timeout": 3600,
        "args": ["-u", "{url}", "-v", "2"],
        "extra_args": [],
    },
    "dalfox": {"timeout": 300, "args": ["url", "{url}"], "extra_args": []},
    "commix": {
        "timeout": 600,
        "crawl": 2,
        "args": ["--url", "{url}", "--batch", "--crawl={crawl}"],
        "extra_args": [],
    },
    "wpscan": {"timeout": 300, "args": ["--url", "{url}"], "extra_args": []},
    "zaproxy": {
        "timeout": 120,
        "idle_reset": True,
        "max_timeout": 3600,
        "args": [
            "-cmd", "-quickurl", "{url}", "-quickprogress",
            "-config", "spider.maxChildren=10",
            "-config", "spider.maxDepth=2",
            "-config", "spider.maxDuration=5",
            "-config", "scanner.threadPerHost=2",
        ],
        "extra_args": [],
    },
    "playwright": {
        "timeout": 180,
        "max_clicks": 15,
        "click_timeout_ms": 5000,
        "headless": True,
        "allowed_hosts": [],
        "allow_subdomains": False,
    },
}

_config = None
_version_cache = {}
_current_results_dir = None
_log_lock = threading.Lock()


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────

def _http_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _scheme_urls(target: str) -> tuple:
    """Return (http_url, https_url) so curl can probe both schemes."""
    raw = (target or "").strip()
    if raw.startswith("https://"):
        https_url = raw
        http_url = "http://" + raw[len("https://"):]
    elif raw.startswith("http://"):
        http_url = raw
        https_url = "https://" + raw[len("http://"):]
    else:
        http_url = f"http://{raw}"
        https_url = f"https://{raw}"
    return http_url, https_url


def load_tools_config(force: bool = False) -> dict:
    """Load tools_config.json, merged over in-code defaults."""
    global _config
    if _config is not None and not force:
        return _config

    merged = copy.deepcopy(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            print(f"[!] {CONFIG_PATH.name} is not a JSON object — using defaults.")
            _config = merged
            return _config
        for key, value in data.items():
            if key == "_global" and isinstance(value, dict):
                merged["_global"].update(value)
            elif isinstance(value, dict):
                merged.setdefault(key, {}).update(value)
            else:
                merged[key] = value
        _config = merged
    except FileNotFoundError:
        print(f"[!] Config not found: {CONFIG_PATH} — using built-in defaults.")
        _config = merged
    except json.JSONDecodeError as exc:
        print(f"[!] Invalid JSON in {CONFIG_PATH}: {exc} — using built-in defaults.")
        _config = merged
    return _config


def get_tool_config(name: str) -> dict:
    cfg = load_tools_config()
    tool_cfg = cfg.get(name, {})
    if not isinstance(tool_cfg, dict):
        return {}
    return tool_cfg


def get_global_config() -> dict:
    cfg = load_tools_config()
    global_cfg = cfg.get("_global", {})
    return global_cfg if isinstance(global_cfg, dict) else {}


def resolve_wordlist(cfg: dict) -> str:
    configured = str(cfg.get("wordlist") or DEFAULT_WORDLIST)
    if configured and Path(configured).is_file():
        return configured
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).is_file():
            if configured and candidate != configured:
                print(f"  [*] wordlist {configured} missing — using {candidate}")
            return candidate
    return configured


def substitute_args(args: list, target: str, cfg: dict, wordlist: str = None) -> list:
    url = _http_url(target)
    if wordlist is None:
        wordlist = resolve_wordlist(cfg)
    try:
        crawl_n = int(cfg.get("crawl", 1) or 1)
    except (TypeError, ValueError):
        crawl_n = 1
    crawl = str(max(1, min(3, crawl_n)))
    depth = str(cfg.get("depth", 2))
    mapping = {
        "{target}": target,
        "{url}": url,
        "{wordlist}": wordlist,
        "{crawl}": crawl,
        "{depth}": depth,
    }
    out = []
    for arg in args:
        arg = str(arg)
        for placeholder, value in mapping.items():
            arg = arg.replace(placeholder, value)
        out.append(arg)
    return out


def build_command(binary: str, target: str, cfg: dict) -> list:
    """Build argv. Binary (argv[0]) is never taken from JSON args/extra_args."""
    wordlist = resolve_wordlist(cfg)
    args = substitute_args(list(cfg.get("args") or []), target, cfg, wordlist=wordlist)
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    prefix = [sys.executable, binary] if str(binary).endswith(".py") else [binary]
    return prefix + args + extra


def _help_blob(binary: str) -> str:
    try:
        result = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=8,
            encoding="utf-8",
            errors="replace",
        )
        return ((result.stdout or "") + (result.stderr or "")).lower()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _is_projectdiscovery_httpx(binary: str) -> bool:
    blob = _help_blob(binary)
    if not blob:
        return False
    if "projectdiscovery" in blob or "-tech-detect" in blob or "-status-code" in blob:
        return True
    if "-u string" in blob or "-u, -list" in blob:
        return True
    return "-title" in blob and " -u" in blob


def _go_bin(name: str) -> str:
    gopath = os.environ.get("GOPATH") or str(Path.home() / "go")
    path = Path(gopath) / "bin" / name
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return ""


def _project_venv_bin(name: str) -> str:
    path = Path(__file__).parent / "venv" / "bin" / name
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return ""


def resolve_tool_binary(logical_name: str) -> str:
    """
    Map a config/allowlist name to an executable on PATH.
    httpx: prefer httpx-toolkit / Go install over the Python httpx CLI.
    sqlmap: prefer GitHub /opt/sqlmap or venv over outdated apt.
    commix: prefer GitHub /opt/commix over outdated apt.
    wapiti: prefer venv wapiti3 over apt 3.0.x.
    zaproxy: also try zap.sh / owasp-zap.
    Optional tools_config.json field "binary" overrides.
    """
    cfg = get_tool_config(logical_name)
    override = str(cfg.get("binary") or "").strip()
    if override:
        return override

    if logical_name in ("httpx", "httpx-toolkit"):
        found = shutil.which("httpx-toolkit")
        if found:
            return found
        go_httpx = _go_bin("httpx")
        if go_httpx and _is_projectdiscovery_httpx(go_httpx):
            return go_httpx
        path_httpx = shutil.which("httpx")
        if path_httpx and _is_projectdiscovery_httpx(path_httpx):
            return path_httpx
        if go_httpx:
            return go_httpx
        return path_httpx or "httpx-toolkit"

    if logical_name == "sqlmap":
        for candidate in (Path("/usr/local/bin/sqlmap"), Path("/opt/sqlmap/sqlmap.py")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        venv_sqlmap = _project_venv_bin("sqlmap")
        if venv_sqlmap:
            return venv_sqlmap
        return shutil.which("sqlmap") or "sqlmap"

    if logical_name == "commix":
        for candidate in (Path("/usr/local/bin/commix"), Path("/opt/commix/commix.py")):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        opt_py = Path("/opt/commix/commix.py")
        if opt_py.is_file():
            return str(opt_py)
        return shutil.which("commix") or "commix"

    if logical_name == "wapiti":
        venv_wapiti = _project_venv_bin("wapiti")
        if venv_wapiti:
            return venv_wapiti
        local = Path("/usr/local/bin/wapiti")
        if local.is_file() and os.access(local, os.X_OK):
            return str(local)
        return shutil.which("wapiti") or "wapiti"

    if logical_name == "zaproxy":
        for candidate in ("zaproxy", "owasp-zap", "zap.sh"):
            found = shutil.which(candidate)
            if found:
                return found
        zap_sh = Path("/usr/share/zaproxy/zap.sh")
        if zap_sh.is_file():
            return str(zap_sh)
        return "zaproxy"

    return logical_name


def _editor_cmd() -> str:
    if os.environ.get("EDITOR"):
        return os.environ["EDITOR"]
    if os.name == "nt":
        return "notepad"
    return "nano"


def open_config_editor() -> None:
    cmd = _editor_cmd()
    print(f"[*] Opening {CONFIG_PATH} with {cmd}...")
    try:
        subprocess.call([cmd, str(CONFIG_PATH)])
    except FileNotFoundError:
        print(f"[!] Editor '{cmd}' not found. Set $EDITOR or edit {CONFIG_PATH} manually.")
        input("Press Enter when done editing...")


def print_config_preview(selected_names: list) -> None:
    cfg = load_tools_config()
    print("\n[ TOOL CONFIGURATION ]")
    global_cfg = cfg.get("_global", {})
    print("=== _global ===")
    print(json.dumps(global_cfg, indent=2))
    print()
    for name in selected_names:
        tool_cfg = cfg.get(name, {})
        print(f"=== {name} ===")
        print(json.dumps(tool_cfg, indent=2))
        print()


def prompt_edit_config(selected_names: list) -> None:
    """Show per-tool JSON and optionally open the editor before running."""
    while True:
        load_tools_config(force=True)
        print_config_preview(selected_names)
        choice = input("[Enter] Run with this configuration  [e] Edit tools_config.json: ").strip().lower()
        if choice != "e":
            return
        open_config_editor()
        try:
            with open(CONFIG_PATH, encoding="utf-8") as fh:
                json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[!] Config is invalid after edit: {exc}")
            print("    Enter uses built-in defaults if the file still fails to load.")
            continue
        load_tools_config(force=True)


# ─────────────────────────────────────────────
# RESULTS DIR / LOG HELPERS
# ─────────────────────────────────────────────

def sanitize_target(target: str) -> str:
    text = target.strip()
    text = re.sub(r"^https?://", "", text, flags=re.IGNORECASE)
    text = re.sub(r"[^\w.\-]+", "_", text)
    return (text[:80] or "target").strip("._") or "target"


def resolve_results_root() -> Path:
    """Resolve scan_results against the project directory, not process CWD."""
    root = str(get_global_config().get("results_dir", "scan_results") or "scan_results")
    path = Path(root).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path


def reports_dir() -> Path:
    path = PROJECT_ROOT / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def start_results_dir(target: str) -> Path:
    global _current_results_dir
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = resolve_results_root() / sanitize_target(target) / stamp
    path.mkdir(parents=True, exist_ok=True)
    _current_results_dir = path
    print(f"[+] Saving full tool logs to: {path}")
    return path


def _truncate_log(text: str, max_lines: int) -> str:
    if max_lines <= 0:
        return text
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return text
    head = max(1, int(max_lines * 0.2))
    tail = max(max_lines - head, 1)
    omitted = len(lines) - head - tail
    if omitted <= 0:
        return text
    return "\n".join(lines[:head] + [f"--- truncated {omitted} lines ---"] + lines[-tail:])


def _probe_version(binary: str) -> str:
    if binary in _version_cache:
        return _version_cache[binary]
    if binary in (sys.executable, "python", "python3"):
        _version_cache[binary] = ""
        return ""
    attempts = (("version",), ("--version",), ("-V",))
    for argv in attempts:
        try:
            result = subprocess.run(
                [binary, *argv],
                capture_output=True,
                text=True,
                timeout=10,
                encoding="utf-8",
                errors="replace",
            )
            if result.returncode != 0:
                continue
            blob = (result.stdout or "") + (result.stderr or "")
            lower = blob.lower()
            if "unknown flag" in lower or "unknown option" in lower:
                continue
            summary = _version_summary(blob)
            if summary:
                _version_cache[binary] = summary
                print(f"  [version] {binary}: {summary}")
                return summary
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    _version_cache[binary] = ""
    return ""


def _version_summary(blob: str) -> str:
    """Pick a short version line; skip ASCII-art banners."""
    art = re.compile(r"[█░▓▒▄▀━_/\\\\|`]{8,}")
    candidates = []
    for ln in (blob or "").splitlines():
        text = ln.strip()
        if not text or len(text) > 160:
            continue
        if text.lower().startswith("error:"):
            continue
        if art.search(text) or text.count("_") > 12:
            continue
        if re.search(r"\d+\.\d+", text):
            candidates.append(text)
    if candidates:
        return " | ".join(candidates[:2])
    return ""


def _append_log_file(tool_name: str, text: str) -> None:
    if not _current_results_dir or not tool_name:
        return
    log_path = _current_results_dir / f"{tool_name}.log"
    with _log_lock:
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")


ZAP_PROGRESS_RE = re.compile(r"^\s*\[[=\s]*\]\s*\d+%")


def _zap_alert_summary(text: str) -> str:
    if "<alertitem>" not in (text or "").lower() and "<OWASPZAPReport" not in (text or ""):
        return ""
    lines = []
    for block in re.findall(r"<alertitem>(.*?)</alertitem>", text or "", re.S | re.I):
        alert = ""
        risk = ""
        uri = ""
        am = re.search(r"<alert>([^<]*)</alert>", block, re.I)
        nm = re.search(r"<name>([^<]*)</name>", block, re.I)
        rm = re.search(r"<riskdesc>([^<]*)</riskdesc>", block, re.I)
        um = re.search(r"<uri>([^<]+)</uri>", block, re.I)
        if am:
            alert = am.group(1).strip()
        elif nm:
            alert = nm.group(1).strip()
        if rm:
            risk = rm.group(1).strip()
        if um:
            uri = um.group(1).strip()
        if alert:
            lines.append(f"ZAP: {alert} | {risk} | {uri}")
        if len(lines) >= 30:
            break
    if not lines:
        return ""
    return "ZAP ALERTS:\n" + "\n".join(lines)


def _filter_live_output(tool_name: str, text: str, state: dict) -> str:
    """Collapse CR progress updates; hide ZAP XML and percentage bars from the console."""
    text = (text or "").replace("\r", "\n")
    if tool_name != "zaproxy":
        return text
    if state.get("xml"):
        return ""
    out = []
    for line in text.splitlines(keepends=True):
        if "<?xml" in line or "<OWASPZAPReport" in line:
            state["xml"] = True
            continue
        if state.get("xml"):
            continue
        if ZAP_PROGRESS_RE.search(line):
            continue
        out.append(line)
    return "".join(out)

def _wait_process(proc, timeout: int, idle_reset: bool, max_timeout: int, activity: dict) -> bool:
    """
    Wait until the process exits. Return True if we killed it for timeout.
    Wall-clock timeout unless idle_reset: then `timeout` is silence, max_timeout is the hard cap.
    """
    start = time.monotonic()
    if not idle_reset:
        try:
            proc.wait(timeout=timeout)
            return False
        except subprocess.TimeoutExpired:
            return True

    idle_limit = max(int(timeout or 0), 1)
    hard_limit = int(max_timeout or 0)
    while proc.poll() is None:
        now = time.monotonic()
        elapsed = now - start
        if hard_limit and elapsed >= hard_limit:
            return True
        idle = now - activity["t"]
        if idle >= idle_limit:
            return True
        slice_t = min(0.5, idle_limit - idle)
        if hard_limit:
            slice_t = min(slice_t, hard_limit - elapsed)
        if slice_t <= 0:
            return True
        try:
            proc.wait(timeout=slice_t)
        except subprocess.TimeoutExpired:
            continue
    return False


def run_tool(
    command: list,
    timeout: int = 120,
    tool_name: str = "",
    allow_retry: bool = False,
    _retried: bool = False,
    idle_reset: bool = False,
    max_timeout: int = 0,
) -> str:
    """
    Execute a command, stream stdout+stderr live, save full log to disk,
    return a (possibly truncated) string for the LLM.
    timeout is wall-clock seconds, or silence seconds when idle_reset is True.
    """
    if not command:
        return "[!] Empty command."

    binary = str(command[0])
    display = " ".join(str(c) for c in command)
    name = tool_name or Path(binary).name
    global_cfg = get_global_config()
    max_lines = int(global_cfg.get("max_log_lines", 2000) or 2000)

    version = _probe_version(binary)
    if version:
        _append_log_file(name, f"[version] {binary}: {version}\n")

    captured = []
    timed_out = False
    proc = None
    activity = {"t": time.monotonic()}
    started = time.monotonic()
    live_state = {"xml": False}

    try:
        proc = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )

        def _reader():
            raw = proc.stdout
            if raw is None:
                return
            while True:
                chunk = raw.read(4096)
                if not chunk:
                    break
                activity["t"] = time.monotonic()
                text = chunk.decode("utf-8", errors="replace")
                console_text = _filter_live_output(name, text, live_state)
                if console_text:
                    print(console_text, end="", flush=True)
                captured.append(text)
                _append_log_file(name, text)

        reader = threading.Thread(target=_reader, daemon=True)
        reader.start()
        timed_out = _wait_process(proc, timeout, idle_reset, max_timeout, activity)
        if timed_out:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
        reader.join(timeout=5)

    except FileNotFoundError:
        hint_key = name or Path(binary).name
        hint = TOOL_INSTALL_HINTS.get(hint_key) or TOOL_INSTALL_HINTS.get(
            Path(binary).name, f"sudo apt install {Path(binary).name}"
        )
        msg = f"[!] Tool not found: {binary} — install it with: {hint}"
        print(msg)
        _append_log_file(name, msg + "\n")
        return msg
    except Exception as exc:
        msg = f"[!] Unexpected error running {binary}: {exc}"
        print(msg)
        _append_log_file(name, msg + "\n")
        return msg
    finally:
        if proc is not None and proc.stdout:
            try:
                proc.stdout.close()
            except OSError:
                pass

    body = "".join(captured).rstrip()
    if timed_out:
        elapsed = int(time.monotonic() - started)
        if idle_reset:
            notice = (
                f"[!] Idle timeout after {timeout}s with no output "
                f"(ran {elapsed}s): {display}"
            )
        else:
            notice = f"[!] Timed out after {timeout}s: {display}"
        print(notice)
        _append_log_file(name, notice + "\n")
        partial = body + ("\n" if body else "") + notice

        if allow_retry and not _retried:
            multiplier = float(global_cfg.get("timeout_retry_multiplier", 2) or 2)
            bumped = max(int(timeout * multiplier), timeout + 1)
            bumped_max = int(max_timeout * multiplier) if max_timeout else 0
            choice = input(
                f"Timed out after {timeout}s. Retry with timeout={bumped}? [y/N/e]: "
            ).strip().lower()
            if choice == "y":
                print(f"[*] Retrying with timeout={bumped}s...")
                return run_tool(
                    command,
                    timeout=bumped,
                    tool_name=name,
                    allow_retry=False,
                    _retried=True,
                    idle_reset=idle_reset,
                    max_timeout=bumped_max or max_timeout,
                )
            if choice == "e":
                prompt_edit_config([name])
                new_cfg = get_tool_config(name)
                new_timeout = int(new_cfg.get("timeout", bumped) or bumped)
                new_idle = bool(new_cfg.get("idle_reset", idle_reset))
                new_max = int(new_cfg.get("max_timeout", max_timeout) or 0)
                print(f"[*] Retrying with timeout={new_timeout}s from config...")
                return run_tool(
                    command,
                    timeout=new_timeout,
                    tool_name=name,
                    allow_retry=False,
                    _retried=True,
                    idle_reset=new_idle,
                    max_timeout=new_max,
                )
        return _truncate_log(partial, max_lines)

    if not body:
        body = "[!] Tool returned no output."
    if name == "zaproxy":
        summary = _zap_alert_summary(body)
        if summary:
            print(summary)
            body = summary
    return _truncate_log(body, max_lines)


GOBUSTER_WILDCARD_RE = re.compile(
    r"exclude the status code or the length",
    re.IGNORECASE,
)
GOBUSTER_LENGTH_RE = re.compile(r"\(Length:\s*(\d+)\)", re.IGNORECASE)
RESPONSE_SIZE_RE = re.compile(r"\[Size:\s*(\d+)\]", re.IGNORECASE)


def _dominant_response_size(output: str, min_hits: int = 8) -> str:
    sizes = RESPONSE_SIZE_RE.findall(output or "")
    if len(sizes) < min_hits:
        return ""
    counts = {}
    for size in sizes:
        counts[size] = counts.get(size, 0) + 1
    size, n = max(counts.items(), key=lambda kv: kv[1])
    if n >= min_hits and n / len(sizes) >= 0.5:
        return size
    return ""


def _retry_gobuster_wildcard(output: str, command: list, timeout: int) -> str:
    if "--exclude-length" in command:
        return output
    length = ""
    if GOBUSTER_WILDCARD_RE.search(output or ""):
        match = GOBUSTER_LENGTH_RE.search(output or "")
        if match:
            length = match.group(1)
    if not length:
        length = _dominant_response_size(output)
    if not length:
        return output
    retry_cmd = list(command) + ["--exclude-length", length]
    print(f"  [*] gobuster catch-all size {length} — retrying with --exclude-length {length}")
    print(f"  [*] {' '.join(str(c) for c in retry_cmd)}")
    retry_out = run_tool(retry_cmd, timeout=timeout, tool_name="gobuster", allow_retry=False)
    return (output or "") + f"\n\n[retry --exclude-length {length}]\n" + retry_out


def _retry_ffuf_filter(output: str, command: list, timeout: int) -> str:
    if "-fs" in command:
        return output
    size = _dominant_response_size(output)
    if not size:
        return output
    retry_cmd = list(command) + ["-fs", size]
    print(f"  [*] ffuf catch-all size {size} — retrying with -fs {size}")
    print(f"  [*] {' '.join(str(c) for c in retry_cmd)}")
    retry_out = run_tool(retry_cmd, timeout=timeout, tool_name="ffuf", allow_retry=False)
    return (output or "") + f"\n\n[retry -fs {size}]\n" + retry_out


def _finalize_command(logical_name: str, command: list, target: str) -> list:
    command = list(command)
    if logical_name == "nikto":
        url = _http_url(target)
        if url.startswith("https://") and "-ssl" not in command:
            command.append("-ssl")
    if logical_name == "zaproxy" and _current_results_dir is not None:
        out = str(_current_results_dir / "zaproxy_report.xml")
        if "-quickout" not in command:
            command.extend(["-quickout", out])
    if logical_name == "commix":
        url = _http_url(target)
        if url.startswith("https://") and "--force-ssl" not in command:
            command.append("--force-ssl")
        raw = target if target.startswith(("http://", "https://")) else url
        parsed = urlparse(raw)
        has_query = bool(parse_qsl(parsed.query, keep_blank_values=True))
        if not has_query and not any(str(a).startswith("--crawl") for a in command):
            command.append("--crawl=2")
    if logical_name == "sqlmap":
        raw = target if target.startswith(("http://", "https://")) else _http_url(target)
        parsed = urlparse(raw)
        weak = {
            "unique", "v", "ver", "version", "cb", "cache", "nocache", "_",
        }
        keys = []
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
            if not key or key.lower() in weak or key.lower().startswith("utm_"):
                continue
            if key not in keys:
                keys.append(key)
        if keys:
            if "-p" not in command:
                command.extend(["-p", ",".join(keys)])
        elif "--forms" not in command:
            command.append("--forms")
    return command


def _run_configured(binary: str, target: str, allow_retry: bool = True) -> str:
    cfg = get_tool_config(binary)
    timeout = int(cfg.get("timeout", 120) or 120)
    argv0 = resolve_tool_binary(binary)
    command = _finalize_command(binary, build_command(argv0, target, cfg), target)
    print(f"  [*] {' '.join(str(c) for c in command)}")
    output = run_tool(
        command,
        timeout=timeout,
        tool_name=binary,
        allow_retry=allow_retry,
        idle_reset=bool(cfg.get("idle_reset")),
        max_timeout=int(cfg.get("max_timeout") or 0),
    )
    if binary == "gobuster":
        output = _retry_gobuster_wildcard(output, command, timeout)
    if binary == "ffuf":
        output = _retry_ffuf_filter(output, command, timeout)
    return output


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    return _run_configured("nmap", target)


def run_whois(target: str) -> str:
    return _run_configured("whois", target)


def run_whatweb(target: str) -> str:
    return _run_configured("whatweb", target)


def run_curl_headers(target: str) -> str:
    """Fetch HTTP and HTTPS headers using configured curl flags."""
    cfg = get_tool_config("curl")
    timeout = int(cfg.get("timeout", 20) or 20)
    wordlist = resolve_wordlist(cfg)
    base_args = substitute_args(
        list(cfg.get("args") or ["-I", "--max-time", "10"]),
        target,
        cfg,
        wordlist=wordlist,
    )
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    http_url, https_url = _scheme_urls(target)

    print(f"  [*] curl {' '.join(base_args + extra)} {http_url}")
    http_out = run_tool(
        ["curl"] + base_args + extra + [http_url],
        timeout=timeout,
        tool_name="curl",
        allow_retry=True,
    )

    https_cmd = ["curl"] + base_args + extra
    if "-k" not in https_cmd:
        https_cmd.append("-k")
    https_cmd.append(https_url)
    print(f"  [*] curl {' '.join(base_args + extra)} -k {https_url}")
    https_out = run_tool(https_cmd, timeout=timeout, tool_name="curl", allow_retry=True)

    return f"[HTTP Headers]\n{http_out}\n\n[HTTPS Headers]\n{https_out}"


def run_dig(target: str) -> str:
    cfg = get_tool_config("dig")
    timeout = int(cfg.get("timeout", 15) or 15)
    wordlist = resolve_wordlist(cfg)
    extra = substitute_args(list(cfg.get("extra_args") or []), target, cfg, wordlist=wordlist)
    prefix = substitute_args(list(cfg.get("args") or ["+short"]), target, cfg, wordlist=wordlist)
    print(f"  [*] dig {target} A/MX/NS/TXT")
    records = {}
    for rtype in ("A", "MX", "NS", "TXT"):
        records[rtype] = run_tool(
            ["dig"] + prefix + extra + [rtype, target],
            timeout=timeout,
            tool_name="dig",
            allow_retry=True,
        )
    return (
        f"[A Records]\n{records['A']}\n\n"
        f"[MX Records]\n{records['MX']}\n\n"
        f"[NS Records]\n{records['NS']}\n\n"
        f"[TXT Records]\n{records['TXT']}"
    )


def run_nikto(target: str) -> str:
    return _run_configured("nikto", target)


def run_gobuster(target: str) -> str:
    return _run_configured("gobuster", target)


def run_arp_scan(target: str) -> str:
    output = _run_configured("arp-scan", target)
    if "Operation not permitted" in output or "You don't have permission" in output:
        notice = "[!] arp-scan needs CAP_NET_RAW/root — treating as non-fatal."
        print(notice)
        return output + "\n" + notice
    return output


def run_sslscan(target: str) -> str:
    return _run_configured("sslscan", target)


def run_testssl(target: str) -> str:
    return _run_configured("testssl.sh", target)


def run_katana(target: str) -> str:
    return _run_configured("katana", target)


def run_nuclei(target: str) -> str:
    return _run_configured("nuclei", target)


def run_httpx_probe(target: str) -> str:
    return _run_configured("httpx", target)


def run_ffuf(target: str) -> str:
    return _run_configured("ffuf", target)


def run_sqlmap(target: str) -> str:
    return _run_configured("sqlmap", target)


def run_wapiti(target: str) -> str:
    return _run_configured("wapiti", target)


def run_dalfox(target: str) -> str:
    return _run_configured("dalfox", target)


def run_commix(target: str) -> str:
    return _run_configured("commix", target)


def run_wpscan(target: str) -> str:
    return _run_configured("wpscan", target)


def run_zap(target: str) -> str:
    return _run_configured("zaproxy", target)


def run_playwright(target: str, allow_retry: bool = True) -> str:
    """Origin-locked browser click probe (virtual tool)."""
    cfg = get_tool_config("playwright")
    timeout = int(cfg.get("timeout", 180) or 180)
    script = Path(__file__).parent / "browser_probe.py"
    url = _http_url(target)
    cmd = [
        sys.executable,
        str(script),
        "--url", url,
        "--max-clicks", str(cfg.get("max_clicks", 15)),
        "--click-timeout-ms", str(cfg.get("click_timeout_ms", 5000)),
    ]
    if cfg.get("headless", True):
        cmd.append("--headless")
    else:
        cmd.append("--headed")
    hosts = cfg.get("allowed_hosts") or []
    if hosts:
        cmd.extend(["--allowed-hosts", ",".join(str(h) for h in hosts)])
    if cfg.get("allow_subdomains"):
        cmd.append("--allow-subdomains")
    print(f"  [*] playwright probe {url}")
    return run_tool(cmd, timeout=timeout, tool_name="playwright", allow_retry=allow_retry)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1":  ("nmap",          run_nmap),
    "2":  ("whois",         run_whois),
    "3":  ("whatweb",       run_whatweb),
    "4":  ("curl headers",  run_curl_headers),
    "5":  ("dig DNS",       run_dig),
    "6":  ("nikto",         run_nikto),
    "7":  ("gobuster",      run_gobuster),
    "8":  ("arp-scan",      run_arp_scan),
    "9":  ("sslscan",       run_sslscan),
    "10": ("testssl.sh",    run_testssl),
    "11": ("katana",        run_katana),
    "12": ("nuclei",        run_nuclei),
    "13": ("httpx",         run_httpx_probe),
    "14": ("ffuf",          run_ffuf),
    "15": ("sqlmap",        run_sqlmap),
    "16": ("wapiti",        run_wapiti),
    "17": ("dalfox",        run_dalfox),
    "18": ("commix",        run_commix),
    "19": ("wpscan",        run_wpscan),
    "20": ("zaproxy",       run_zap),
    "21": ("playwright",    run_playwright),
}

# Config / log file keys for menu entries (curl headers → curl, dig DNS → dig)
MENU_CONFIG_KEYS = {
    "1": "nmap",
    "2": "whois",
    "3": "whatweb",
    "4": "curl",
    "5": "dig",
    "6": "nikto",
    "7": "gobuster",
    "8": "arp-scan",
    "9": "sslscan",
    "10": "testssl.sh",
    "11": "katana",
    "12": "nuclei",
    "13": "httpx",
    "14": "ffuf",
    "15": "sqlmap",
    "16": "wapiti",
    "17": "dalfox",
    "18": "commix",
    "19": "wpscan",
    "20": "zaproxy",
    "21": "playwright",
}

DEFAULT_RECON_KEYS = ["1", "2", "3", "4", "5"]
ALL_TOOL_KEYS = list(TOOLS_MENU.keys())


def run_default_recon(target: str) -> dict:
    """
    Run the standard recon pipeline (everything except nikto).
    Returns a dict of {tool_name: output_string}.
    Nikto is excluded by default — too slow/noisy for auto-run.
    """
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    results = {}
    results["nmap"] = run_nmap(target)
    results["whois"] = run_whois(target)
    results["whatweb"] = run_whatweb(target)
    results["curl_headers"] = run_curl_headers(target)
    results["dig"] = run_dig(target)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


INSTALL_CHECK_TOOLS = (
    "nmap", "whois", "whatweb", "curl", "dig", "nikto", "gobuster",
    "arp-scan", "sslscan", "testssl.sh", "katana", "nuclei", "httpx",
    "ffuf", "sqlmap", "wapiti", "dalfox", "commix", "wpscan", "zaproxy",
)


def _binary_available(path_or_name: str) -> str:
    if not path_or_name:
        return ""
    path = Path(path_or_name)
    if path.is_file() and os.access(path_or_name, os.X_OK):
        return str(path)
    found = shutil.which(path_or_name)
    return found or ""


def tool_binary_status(logical_name: str) -> tuple:
    """Return (ok, resolved_path_or_name)."""
    if logical_name in ("curl", "whois", "dig"):
        aliases = {
            "curl": ("curl",),
            "whois": ("whois",),
            "dig": ("dig",),
        }
        for name in aliases[logical_name]:
            found = shutil.which(name)
            if found:
                return True, found
        return False, logical_name

    if logical_name in ("httpx", "httpx-toolkit"):
        resolved = resolve_tool_binary(logical_name)
        found = _binary_available(resolved)
        if found and (
            Path(found).name in ("httpx-toolkit", "httpx-pd")
            or _is_projectdiscovery_httpx(found)
        ):
            return True, found
        return False, "ProjectDiscovery httpx not found (not the Python httpx CLI)"

    resolved = resolve_tool_binary(logical_name)
    found = _binary_available(resolved)
    if found:
        return True, found
    fallback = _binary_available(logical_name)
    if fallback:
        return True, fallback
    return False, resolved or logical_name


def playwright_status() -> tuple:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "python package missing (pip install playwright && playwright install chromium)"
    try:
        with sync_playwright() as p:
            exe = p.chromium.executable_path
        if exe and Path(exe).is_file():
            return True, exe
        return False, "Chromium missing (playwright install chromium)"
    except Exception as exc:
        return False, str(exc)


def wordlist_status() -> tuple:
    path = resolve_wordlist({})
    if path and Path(path).is_file():
        return True, path
    return False, path or DEFAULT_WORDLIST


def collect_install_status() -> list:
    """
    Presence checks for scanners, Playwright, and the dirb wordlist.
    Each item: {group, name, ok, detail, hint}
    """
    rows = []
    for name in INSTALL_CHECK_TOOLS:
        ok, detail = tool_binary_status(name)
        rows.append({
            "group": "tools",
            "name": name,
            "ok": ok,
            "detail": detail,
            "hint": TOOL_INSTALL_HINTS.get(name, f"sudo apt install {name}"),
        })
    ok, detail = playwright_status()
    rows.append({
        "group": "tools",
        "name": "playwright",
        "ok": ok,
        "detail": detail,
        "hint": TOOL_INSTALL_HINTS["playwright"],
    })
    ok, detail = wordlist_status()
    rows.append({
        "group": "wordlist",
        "name": "dirb common.txt",
        "ok": ok,
        "detail": detail,
        "hint": "sudo apt install dirb",
    })
    java = shutil.which("java")
    rows.append({
        "group": "runtime",
        "name": "java (ZAP)",
        "ok": bool(java),
        "detail": java or "not on PATH",
        "hint": "sudo apt install default-jre",
    })
    go = shutil.which("go")
    rows.append({
        "group": "runtime",
        "name": "go",
        "ok": bool(go),
        "detail": go or "not on PATH (needed to install nuclei/katana/httpx/dalfox/ffuf)",
        "hint": "sudo apt install golang-go",
    })
    return rows


ALLOWED_TOOLS = {
    "nmap", "whois", "whatweb", "curl", "dig", "nikto",
    "gobuster", "arp-scan", "sslscan", "testssl.sh",
    "katana", "nuclei", "httpx", "httpx-toolkit", "ffuf", "sqlmap", "wapiti",
    "dalfox", "commix", "wpscan", "zaproxy",
    "playwright",
}


def _extract_dispatch_target(parts: list) -> str:
    """Last non-flag token after the binary — host or URL."""
    for token in reversed(parts[1:]):
        if not token.startswith("-"):
            return token
    return ""


_JUNK_PATH_SEGMENTS = {
    "fullpath", "fuzz", "fu", "path", "url", "target", "endpoint", "endpoints",
}


def _sanitize_dispatch_target(target: str) -> str:
    """Drop invented path tokens like /fullpath so ffuf/gobuster stay on origin."""
    raw = (target or "").strip()
    if not raw:
        return raw
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    last = (parsed.path or "").rstrip("/").split("/")[-1].lower()
    if last in _JUNK_PATH_SEGMENTS:
        host = parsed.netloc or parsed.path.split("/")[0]
        if parsed.scheme and host:
            return f"{parsed.scheme}://{host}"
        return host
    return raw


def run_tool_by_command(command_str: str) -> str:
    """
    AI dispatch: binary name is allowlisted; flags always come from
    tools_config.json. Extra flags the model invents are ignored.
    """
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    tool = parts[0].lower().split("/")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    target = _extract_dispatch_target(parts)
    if not target:
        return f"[!] No target in command. Use: [TOOL: {tool} TARGET]"
    cleaned = _sanitize_dispatch_target(target)
    if cleaned != target:
        print(f"  [!] Stripped junk path from TARGET: {target} → {cleaned}")
        target = cleaned

    extra_from_model = len(parts) > 2
    if extra_from_model:
        print(f"  [*] Ignoring model flags; using {CONFIG_PATH.name} for {tool}")

    if tool == "playwright":
        return run_playwright(target, allow_retry=False)
    if tool == "curl":
        return run_curl_headers(target)
    if tool == "dig":
        return run_dig(target)

    config_key = "httpx" if tool == "httpx-toolkit" else tool
    cfg = get_tool_config(config_key)
    timeout = int(cfg.get("timeout", 120) or 120)
    argv0 = resolve_tool_binary(config_key)
    command = _finalize_command(config_key, build_command(argv0, target, cfg), target)
    joined = " ".join(str(c) for c in command)
    if target not in joined and _http_url(target) not in joined:
        command.append(target)
    print(f"  [*] {' '.join(str(c) for c in command)}")
    output = run_tool(
        command,
        timeout=timeout,
        tool_name=config_key,
        allow_retry=False,
        idle_reset=bool(cfg.get("idle_reset")),
        max_timeout=int(cfg.get("max_timeout") or 0),
    )
    if config_key == "gobuster":
        output = _retry_gobuster_wildcard(output, command, timeout)
    if config_key == "ffuf":
        output = _retry_ffuf_filter(output, command, timeout)
    return output


# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def _run_selected(target: str, keys: list) -> dict:
    combined = {}
    for key in keys:
        if key not in TOOLS_MENU:
            print(f"[!] Unknown option: {key}")
            continue
        name, func = TOOLS_MENU[key]
        print(f"\n[*] Running {name}...")
        combined[name] = func(target)
    return combined


def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run, optionally edit JSON config,
    then execute. Returns combined output string.
    """
    load_tools_config(force=True)

    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Legacy: nmap, whois, whatweb, curl, dig")
    print("  [n] Legacy: same as [a] plus nikto")
    print("  [m] Run all tools")

    choice = input("\nChoice(s) e.g. 1 2 4 or m: ").strip().lower()

    if choice == "a":
        keys = list(DEFAULT_RECON_KEYS)
    elif choice == "n":
        keys = list(DEFAULT_RECON_KEYS) + ["6"]
    elif choice == "m":
        keys = list(ALL_TOOL_KEYS)
    else:
        keys = choice.split()

    selected_config_names = []
    for key in keys:
        if key in MENU_CONFIG_KEYS:
            selected_config_names.append(MENU_CONFIG_KEYS[key])
        elif key not in ("a", "n", "m") and key not in TOOLS_MENU:
            print(f"[!] Unknown option: {key}")

    if not selected_config_names:
        return ""

    prompt_edit_config(selected_config_names)
    start_results_dir(target)

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = _run_selected(target, keys)
    return format_recon_for_llm(combined)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    start_results_dir(target)
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
