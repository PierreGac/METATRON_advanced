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

You give it a target IP or domain. It runs recon and web-testing tools (nmap, whois, whatweb, curl, dig, nikto, gobuster, sslscan, nuclei, sqlmap, and more), feeds results to a locally running AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history. Full tool logs are also written under `scan_results/`.

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
sudo apt install nmap whois whatweb curl dnsutils nikto gobuster arp-scan sslscan
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
| nuclei / katana / httpx | Go install + PATH as above |
| testssl.sh | `sudo apt install testssl.sh` or clone https://github.com/drwetter/testssl.sh |

Wordlists for gobuster/ffuf:

```bash
sudo apt install dirb
# expects /usr/share/wordlists/dirb/common.txt on Kali; Ubuntu dirb uses
# /usr/share/dirb/wordlists/common.txt (Metatron falls back automatically)
```

Check what is actually on PATH:

```bash
command -v nmap gobuster sqlmap ffuf dalfox nuclei katana httpx-toolkit wapiti commix wpscan zaproxy
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
  [a] Legacy: nmap, whois, whatweb, curl, dig
  [n] Legacy: same as [a] plus nikto
  [m] Run all tools
```

**4. Review or edit configuration** for the selected tools (`tools_config.json`). Each tool is shown in its own `=== name ===` block. Press Enter to run, or `e` to edit the JSON in `$EDITOR` (nano by default).

**5. Metatron streams tool output live.** If a tool times out you can retry with a higher timeout (`y`), edit config (`e`), or keep the partial log (`N`). Full logs (not truncated) go to `scan_results/<target>/<timestamp>/<tool>.log`. The copy sent to the AI is capped by `_global.max_log_lines` (default 2000).

**6. Results are fed to the AI.** The model emits `[TOOL:]` / `[SEARCH:]` tags (TARGET only; flags come from JSON). Missing scanners and unverified CVEs are auto-dispatched. A final schema-only pass writes `VULN:` / `RISK_LEVEL:` for the database.

**7. Everything is saved to MariaDB automatically.**

**8. After the scan you can edit or delete any result.**

---

## ⚙️ Tool configuration

[`tools_config.json`](tools_config.json) controls timeouts, flags, wordlists, crawl depth, ZAP spider limits, and Playwright click settings. JSON cannot change the binary name (`argv[0]`). AI `[TOOL: name TARGET]` tags use the same JSON flags — extra flags the model writes are ignored. The AI may only change **TARGET** (origin or a discovered same-host URL). The analysis loop auto-runs missing web scanners if the model forgets tags, searches unverified CVEs, then does a schema-only finalize pass; **that** finalize output is what is parsed into MariaDB.

Placeholders in `args`: `{target}`, `{url}`, `{wordlist}`, `{crawl}`, `{depth}`. Gobuster/ffuf fall back to `/usr/share/dirb/wordlists/common.txt` when the Kali wordlist path is missing. Katana includes `-jc` (JS crawl) for SPAs. Playwright dismisses cookie/consent dialogs before other clicks.

Append extra flags with `extra_args`. Global keys:

```json
"_global": {
  "max_log_lines": 2000,
  "timeout_retry_multiplier": 2,
  "results_dir": "scan_results"
}
```

ZAP defaults cap spider children/depth/duration so `-quickurl` does not run unbounded. Playwright stays on the start host unless you set `allowed_hosts` or `allow_subdomains`.

---

## 📁 Project Structure

```
METATRON/
├── install.sh          ← sudo full install (apt, venv, Playwright, Go tools, Ollama)
├── metatron.py         ← main CLI entry point
├── db.py               ← MariaDB connection and all CRUD operations
├── tools.py            ← recon / web-test runners, live logs, config
├── tools_config.json   ← per-tool timeouts, args, wordlists, ZAP/Playwright settings
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
