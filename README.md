# METATRON
AI-powered penetration testing assistant using local LLM on linux (Parrot OS)
# 🔱 METATRON
### AI-Powered Penetration Testing Assistant

<p align="center">
  <img src="screenshots/banner.png" alt="Metatron Banner" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/OS-Parrot%20Linux-green?style=for-the-badge&logo=linux"/>
  <img src="https://img.shields.io/badge/AI-metatron--qwen-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/DB-MariaDB-orange?style=for-the-badge&logo=mariadb"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

---

## 📌 What is Metatron?

**Metatron** is a CLI-based AI penetration testing assistant that runs entirely on your local machine — no cloud, no API keys, no subscriptions.

You give it a target IP or domain. It runs recon and web-testing tools (nmap, whois, whatweb, curl, dig, nikto, gobuster, sslscan, nuclei, sqlmap, searchsploit, gau, subfinder, masscan, and more), feeds results to a locally running AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history. Full tool logs are also written under `scan_results/`.

---

## ✨ Features

- 🤖 **Local AI Analysis** — powered by `metatron-qwen` via Ollama, runs 100% offline
- 🔍 **Automated Recon** — nmap, whois, whatweb, curl headers, dig DNS, plus optional web testers
- 🛠️ **Configurable tools** — `tools_config.json` for timeouts, flags, wordlists, crawl depth, ZAP limits, Playwright clicks
- 📁 **Scan logs** — full live output saved under `scan_results/<target>/<timestamp>/`
- 🌐 **Web Search** — DuckDuckGo search + CVE lookup (no API key needed)
- 🗄️ **MariaDB Backend** — full scan history with 5 linked tables
- ✏️ **Edit / Delete** — modify any saved result directly from the CLI
- 🔁 **Agentic Loop** — AI can request more tool runs mid-analysis
- 🚫 **No API Keys** — everything is free and local
-📤 Export Reports

Metatron allows you to export scan results into clean, shareable report formats by selecting '2.view history'->select slno and export

📄 PDF — professional vulnerability reports
🌐 HTML — browser-viewable reports
---

## 🖥️ Screenshots

<p align="center">
  <img src="screenshots/main_menu.png" alt="Main Menu" width="700"/>
  <br><i>Main Menu</i>
</p>

<p align="center">
  <img src="screenshots/scan_running.png" alt="Scan Running" width="700"/>
  <br><i>Recon tools running on target</i>
</p>

<p align="center">
  <img src="screenshots/ai_analysis.png" alt="AI Analysis" width="700"/>
  <br><i>metatron-qwen analyzing scan results</i>
</p>

<p align="center">
  <img src="screenshots/results.png" alt="Results" width="700"/>
  <br><i>Vulnerabilities saved to database</i>
</p>
<p align="center"> <img src="screenshots/export_menu.png" alt="Export Menu" width="700"/> <br><i>Export scan results as PDF and or HTML</i> </p>
---

## 🧱 Tech Stack

| Component  | Technology                          |
|------------|-------------------------------------|
| Language   | Python 3                            |
| AI Model   | metatron-qwen (fine-tuned Qwen 3.5) |
| Base Model | huihui_ai/qwen3.5-abliterated:9b    |
| LLM Runner | Ollama                              |
| Database   | MariaDB                             |
| OS         | Parrot OS (Debian-based)            |
| Search     | DuckDuckGo (free, no key)           |

---

## ⚙️ Installation

### Quick install (recommended)

On Parrot, Kali, or Debian, from the repo root:

```bash
chmod +x install.sh
sudo ./install.sh
```

The script installs apt packages as root, then Python venv, Playwright Chromium, Go scanners, Ollama, and (optional) the MariaDB schema as your normal user. Missing apt names are skipped and filled with Go/pip/gem fallbacks.

Manual steps below are only needed if you prefer not to use `install.sh`.

---

### 1. Clone the repository

```bash
git clone https://github.com/sooryathejas/METATRON.git
cd METATRON
```

### 2. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

`pip` installs the Playwright **Python package only**. It does not download Chromium. Do the next step or menu `[21] playwright` will fail with `Executable doesn't exist` / `ms-playwright/chromium_headless_shell-...`.

### 4. Install Playwright browsers (required for `[21] playwright`)

Stay inside the same venv as step 2, then download Chromium (and OS libraries on Linux):

```bash
playwright install chromium
sudo playwright install-deps chromium
```

If Playwright was just upgraded and asks you to download browsers, run:

```bash
playwright install
```

That installs every bundled browser. `playwright install chromium` is enough for Metatron.

Confirm the binary exists:

```bash
python3 -c "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(headless=True); print(b.version); b.close(); p.stop()"
```

Notes:

- Use the **venv** `playwright` command (`which playwright` should point at `venv/bin/playwright`). A system-wide install puts browsers in a different cache than the venv package.
- Browsers land under `~/.cache/ms-playwright/`. If that path is missing after install, the venv and the `playwright` CLI are not the same install.
- On Parrot/Debian, `install-deps` pulls libraries Chromium needs (missing libs look like a launch failure even after `playwright install chromium`).

### 5. Install system tools

Metatron calls host binaries by name. Packages below are typical on **Kali**; **Parrot** may omit some — install the fallback if `apt` says “Unable to locate package”.

**Core recon**

```bash
sudo apt update
sudo apt install nmap whois whatweb curl dnsutils nikto gobuster arp-scan sslscan masscan
```

**Web testers (apt — skip any name your distro does not ship)**

```bash
sudo apt install sqlmap wapiti ffuf commix wpscan testssl.sh
sudo apt install zaproxy
sudo apt install httpx-toolkit
```

Debian/Ubuntu `sqlmap` and `wapiti` apt packages are often stale (sqlmap "version is outdated", Wapiti 3.0.x "Problem with local wapp database"). Prefer the GitHub sqlmap clone and `pip install -U wapiti3` from the table below; `install.sh` does that automatically.

`httpx-toolkit` is ProjectDiscovery **httpx**. Do not use the Python `httpx` CLI from `requirements.txt` (`httpx [OPTIONS] URL` / no `-u`). Metatron prefers `httpx-toolkit`, then `$GOPATH/bin/httpx`, and ignores a Python `httpx` on PATH.

**Go tools** (put Go’s bin directory first, then install):

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
# persist that line in ~/.bashrc or ~/.zshrc

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install github.com/ffuf/ffuf/v2@latest
```

**If apt cannot find a package**

| Tool | Fallback |
|------|----------|
| sqlmap | Debian/Ubuntu apt (e.g. 1.9.6) is flagged outdated. `git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap` and wrap `/usr/local/bin/sqlmap` (install.sh does this) |
| wapiti | apt 3.0.x prints `Problem with local wapp database`. `pip install -U wapiti3` in the venv (CLI is still `wapiti`) |
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` |
| dalfox | Go install above |
| commix | `git clone https://github.com/commixproject/commix.git` then `sudo ln -s "$PWD/commix/commix.py" /usr/local/bin/commix` |
| wpscan | `sudo gem install wpscan` (needs Ruby) |
| zaproxy | `sudo apt install zaproxy` or install OWASP ZAP; binary may be `zap.sh` under `/usr/share/zaproxy/` (Metatron also looks for `zap.sh` / `owasp-zap`) |
| nuclei / katana / httpx / subfinder | Go install + PATH as above |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| searchsploit | `sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb` then `sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit`. Papers: `sudo git clone https://github.com/offensive-security/exploitdb-papers.git /opt/exploitdb-papers` (install.sh does this) |
| masscan | `sudo apt install masscan` (LAN hosts only — Metatron refuses public IPs/domains) |
| testssl.sh | `sudo apt install testssl.sh` or clone https://github.com/drwetter/testssl.sh |

Wordlists for gobuster/ffuf come from **SecLists** (~2 GB). `install.sh` tries the `seclists` apt package first. On Parrot/Debian that package is often missing, so the fallback is a shallow clone with the repo root at `/usr/share/wordlists` (so `Discovery/` sits next to any existing lists):

```bash
sudo apt install seclists   # Kali/Parrot if the package exists
# if apt has no seclists package:
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists
```

If `/usr/share/wordlists` already exists and is not empty, `install.sh` still clones, then copies SecLists trees (`Discovery`, `Fuzzing`, …) into that directory without overwriting files already there.

Metatron auto-detects the root in this order: `_global.wordlists_root` in `tools_config.json`, then `/usr/share/wordlists` (if `Discovery/` is there), `/usr/share/seclists`, and `/usr/share/wordlists/seclists`. Dirb `common.txt` is a last-resort fallback only.

The AI can switch lists with an allowlisted scenario (never a raw filesystem path):

```
[TOOL: gobuster https://host SCENARIO:wordpress]
[TOOL: ffuf https://host/api/v1 SCENARIO:api]
[TOOL: ffuf https://host/page?id=1 SCENARIO:sqli]
```

| Scenario | Typical use | Wordlist (under the SecLists root) |
|----------|-------------|-------------------------------------|
| *(default gobuster)* | directory busting | `Discovery/Web-Content/big.txt` |
| *(default ffuf)* | directory busting | `Discovery/Web-Content/directory-list-2.3-big.txt` |
| `wordpress` | WordPress paths | `Discovery/Web-Content/CMS/wordpress.fuzz.txt` |
| `api` | API endpoints | `Discovery/Web-Content/api/api-endpoints.txt` |
| `backups` | leftover/backup files | `Discovery/Web-Content/Common-DB-Backups.txt` |
| `sqli` | SQLi payloads (ffuf) | `Fuzzing/Databases/SQLi/Generic-SQLi.txt` |
| `xss` | XSS payloads (ffuf) | `Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt` |
| `parameters` | parameter names (ffuf) | `Discovery/Web-Content/burp-parameter-names.txt` |

Edit named lists under the `wordlists` key in [`tools_config.json`](tools_config.json). JSON cannot change `argv[0]`. Extra flags the model writes are still ignored.

Check what is actually on PATH:

```bash
command -v nmap gobuster sqlmap ffuf dalfox nuclei katana httpx-toolkit wapiti commix wpscan zaproxy searchsploit gau subfinder masscan
```

If you already ran `pip install -r requirements.txt` but skipped browsers, run step 4 now — you do not need to reinstall Python packages.

---

## 🤖 AI Model Setup

### Step 1 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 2 — Download the base model

```bash
ollama pull huihui_ai/qwen3.5-abliterated:9b
```

> ⚠️ This model requires at least 8.4 GB of RAM. If your system has less, use the 4b variant:
> ```bash
> ollama pull huihui_ai/qwen3.5-abliterated:4b
> ```
> Then edit `Modelfile` and change the FROM line to the 4b model.

### Step 3 — Build the custom metatron-qwen model

The repo includes a `Modelfile` that fine-tunes the base model with pentest-specific parameters:

```bash
ollama create metatron-qwen -f Modelfile
```

This creates your local `metatron-qwen` model with:
- 16,384 token context window
- Temperature: 0.7
- Top-k: 10
- Top-p: 0.9

### Step 4 — Verify the model exists

```bash
ollama list
```

You should see `metatron-qwen` in the list.

---

## 🗄️ Database Setup

### Step 1 — Make sure MariaDB is running

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### Step 2 — Create the database and user

```bash
mysql -u root
```

```sql
CREATE DATABASE metatron;
CREATE USER 'metatron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON metatron.* TO 'metatron'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 3 — Create the tables

```bash
mysql -u metatron -p123 metatron
```

```sql
CREATE TABLE history (
  sl_no     INT AUTO_INCREMENT PRIMARY KEY,
  target    VARCHAR(255) NOT NULL,
                      scan_date DATETIME NOT NULL,
                      status    VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE vulnerabilities (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sl_no       INT,
  vuln_name   TEXT,
  severity    VARCHAR(50),
                              port        VARCHAR(20),
                              service     VARCHAR(100),
                              description TEXT,
                              FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE fixes (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  sl_no    INT,
  vuln_id  INT,
  fix_text TEXT,
  source   VARCHAR(50),
                    FOREIGN KEY (sl_no) REFERENCES history(sl_no),
                    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE exploits_attempted (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  exploit_name TEXT,
  tool_used    TEXT,
  payload      LONGTEXT,
  result       TEXT,
  notes        TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE summary (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  raw_scan     LONGTEXT,
  ai_analysis  LONGTEXT,
  risk_level   VARCHAR(50),
                      generated_at DATETIME,
                      FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
```

---

## 🚀 Usage

Metatron needs **two terminal tabs** to run.

### Terminal 1 — Load the AI model

```bash
ollama run metatron-qwen
```

Wait until you see the `>>>` prompt. This means the model is loaded into memory and ready. You can leave this terminal running in the background.

### Terminal 2 — Launch Metatron

```bash
cd ~/METATRON
source venv/bin/activate
python metatron.py
```

---

### Walkthrough

**1. Main menu appears:**
```
  [1]  New Scan
  [2]  View History
  [3]  Check installation
  [4]  Exit
```

**2. Select [1] New Scan → enter your target:**
```
[?] Enter target IP or domain: 192.168.1.1
```
or
```
[?] Enter target IP or domain: example.com
```

**3. Select recon tools to run:**
```
  [1] nmap
  [2] whois
  [3] whatweb
  [4] curl headers
  [5] dig DNS
  [6] nikto
  [7] gobuster
  [8] arp-scan
  [9] sslscan
  [10] testssl.sh
  [11] katana
  [12] nuclei
  [13] httpx
  [14] ffuf
  [15] sqlmap
  [16] wapiti
  [17] dalfox
  [18] commix
  [19] wpscan
  [20] zaproxy
  [21] playwright
  [22] searchsploit
  [23] gau
  [24] subfinder
  [25] masscan
  [a] Legacy: nmap, whois, whatweb, curl, dig
  [n] Legacy: same as [a] plus nikto
  [m] Run all tools
```

`masscan` only runs when the target resolves entirely to RFC1918, loopback, or link-local addresses. Public hosts are skipped with a notice. `gau` and `subfinder` skip IP targets. `searchsploit` takes a product/version query (not a URL).

**4. Review or edit configuration** for the selected tools (`tools_config.json`). Each tool is shown in its own `=== name ===` block. Press Enter to run, or `e` to edit the JSON in `$EDITOR` (nano by default).

**5. Metatron runs selected tools in JSON-defined waves** (independent tools in parallel). Progress bars (`\r`, ZAP percent) are stripped from logs. Parallel waves show a heartbeat line instead of interleaving stdout. Timeouts in parallel do not prompt; the wave continues.

**6. Results are fed to the AI.** The model writes a `PLAN:` then `[TOOL: name TARGET:... PROFILE:... SCENARIO:...]` tags. Flags always come from JSON **profiles** (`default` / `aggressive` / `exploit`). Duplicate (tool, endpoint, profile) runs are skipped. Auto-dispatch only fills CVE `[SEARCH:]` and evidence `curl`. A finalize pass writes `VULN:` / `RISK_LEVEL:` for MariaDB. A markdown report is written to `scan_results/<target>/<stamp>/report.md` and `reports/metatron_last.md`.

**7. Everything is saved to MariaDB automatically.**

**8. After the scan you can edit, delete, or export PDF/HTML/Markdown.**

---

## ⚙️ Tool configuration

[`tools_config.json`](tools_config.json) controls timeouts, flags, wordlists, crawl depth, ZAP spider limits, Playwright clicks, **named profiles**, and the **wave scheduler**. JSON cannot change the binary name (`argv[0]`). AI tags:

```
[TOOL: sqlmap TARGET:https://host/search?q=test PROFILE:aggressive]
[TOOL: gobuster TARGET:https://host PROFILE:default SCENARIO:api]
[TOOL: searchsploit TARGET:CVE-2024-1234 PROFILE:default]
```

**PROFILE** selects argv (`default` → `aggressive` → `exploit` via `extends`). **SCENARIO** selects an allowlisted wordlist. Invented `-flags` are ignored. `PROFILE:exploit` (`--os-shell` / `--os-cmd`) is not used unless a prior default/aggressive run exists on that endpoint (`exploit_requires_detect`).

The first user-selected pass uses each tool’s **default** profile in waves. Follow-up is AI-planned; only unverified CVEs and curl evidence are auto-filled.

Placeholders in `args`: `{target}`, `{url}`, `{host}`, `{wordlist}`, `{crawl}`, `{depth}`.

Set `METATRON_DRY_RUN=1` to print argv without executing (useful for tests). Optional `psutil` enables RAM/load throttling (`ram_percent_limit`, `load_per_cpu_limit`).

Global keys:

```json
"_global": {
  "max_log_lines": 2000,
  "timeout_retry_multiplier": 2,
  "results_dir": "scan_results",
  "wordlists_root": "",
  "max_workers": 4,
  "max_injection_endpoints": 3,
  "max_exploit_runs": 1,
  "exploit_requires_detect": true,
  "idle_reset": true
}
```

**Timeouts** are idle by default: `timeout` is seconds of silence, and any stdout/stderr from the tool resets the timer (gobuster progress, ZAP crawls, etc. keep running). Optional `max_timeout` is a hard wall-clock cap from process start (`0` = none). Set `"idle_reset": false` on a tool (or `_global`) to restore old wall-clock timeout from start.

Edit the `waves` array to change parallelism and dependencies. Tools not listed fall into a serial `other` wave.

Leave `wordlists_root` empty to auto-detect. Named scenarios live in the top-level `wordlists` object. ZAP defaults omit `-quickprogress`; alerts come from the XML summary. Playwright stays on the start host unless you set `allowed_hosts` or `allow_subdomains`.

---

## 📁 Project Structure

```
METATRON/
├── install.sh          ← sudo full install (apt, venv, Playwright, Go tools, Ollama)
├── metatron.py         ← main CLI entry point
├── db.py               ← MariaDB connection and all CRUD operations
├── dispatch.py         ← tag parse, dedup, sanitizer, safety gates
├── report_md.py        ← markdown report renderer
├── tools.py            ← recon / web-test runners, live logs, config, waves
├── tools_config.json   ← profiles, waves, timeouts, wordlists
├── browser_probe.py    ← origin-locked Playwright click probe
├── llm.py              ← Ollama interface and AI tool dispatch loop
├── search.py           ← DuckDuckGo web search and CVE lookup
├── Modelfile           ← custom model config for metatron-qwen
├── requirements.txt    ← Python dependencies
├── .gitignore          ← excludes venv, pycache, scan_results, db files
├── LICENSE           ← MIT License
├── README.md         ← this file
└── screenshots/      ← terminal screenshots for documentation
```

---

## 🗃️ Database Schema

All 5 tables are linked by `sl_no` (session number) from the `history` table:

```
history              ← one row per scan session (sl_no is the spine)
    │
    ├── vulnerabilities   ← vulns found, linked by sl_no
    │       │
    │       └── fixes     ← fixes per vuln, linked by vuln_id + sl_no
    │
    ├── exploits_attempted ← exploits tried, linked by sl_no
    │
    └── summary           ← full AI analysis dump, linked by sl_no
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.

- Only use Metatron on systems you own or have **explicit written permission** to test.
- Unauthorized scanning or exploitation of systems is **illegal**.
- The author is not responsible for any misuse of this tool.

---

## 👤 Author

**Soorya Thejas**
- GitHub: [@sooryathejas](https://github.com/sooryathejas)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
