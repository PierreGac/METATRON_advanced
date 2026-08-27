#!/usr/bin/env bash
#
# METATRON installer — Parrot/Debian/Kali
# Run:  sudo ./install.sh
# Apt packages need root. venv, Go tools, Playwright browsers, and Ollama
# models are installed as the invoking user (SUDO_USER).
#
# Inspired by:
# https://github.com/drgreenthumb93/METATRON_optimized/blob/main/install.sh
#

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[!] Re-running with sudo (package installs need root)...${NC}"
    exec sudo -E "$0" "$@"
fi

REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(eval echo "~$REAL_USER")"
VENV="$SCRIPT_DIR/venv"
GO_BIN=""

run_user() {
    if [[ "$REAL_USER" == "root" ]]; then
        bash -lc "$*"
    else
        sudo -u "$REAL_USER" -H bash -lc "$*"
    fi
}

apt_try() {
    local pkg="$1"
    if DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1; then
        echo -e "  [${GREEN}+${NC}] $pkg"
        return 0
    fi
    echo -e "  [${YELLOW}skip${NC}] $pkg (not in apt or failed)"
    return 1
}

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              METATRON INSTALLER                              ║"
echo "║   Recon + web-testing assistant (Parrot / Debian / Kali)     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "Installing as user: $REAL_USER  (home: $REAL_HOME)"
echo "Repo: $SCRIPT_DIR"
echo ""

# =============================================================================
# STEP 1: Apt packages
# =============================================================================

echo -e "\n${GREEN}[1/7] Installing apt packages...${NC}"

if ! command -v apt-get &>/dev/null; then
    echo -e "${RED}[!] apt-get not found. This installer targets Debian-based distros.${NC}"
    exit 1
fi

apt-get update -y

CORE_PKGS=(
    python3 python3-pip python3-venv python3-dev
    git curl wget
    golang-go
    nmap whois whatweb dnsutils nikto gobuster arp-scan sslscan
    dirb
    mariadb-server
)

WEB_PKGS=(
    sqlmap wapiti ffuf commix wpscan testssl.sh
    zaproxy httpx-toolkit
    ruby ruby-dev
    pipx
)

echo "  Core:"
for pkg in "${CORE_PKGS[@]}"; do
    apt_try "$pkg"
done

echo "  Web testers (optional if missing on Parrot):"
for pkg in "${WEB_PKGS[@]}"; do
    apt_try "$pkg"
done

# =============================================================================
# STEP 2: Python venv + Playwright
# =============================================================================

echo -e "\n${GREEN}[2/7] Python venv and Playwright...${NC}"

if [[ ! -f "$SCRIPT_DIR/requirements.txt" ]]; then
    echo -e "${RED}[!] requirements.txt missing in $SCRIPT_DIR${NC}"
    exit 1
fi

if [[ ! -d "$VENV" ]]; then
    run_user "python3 -m venv '$VENV'"
fi
run_user "'$VENV/bin/pip' install --upgrade pip"
run_user "'$VENV/bin/pip' install -r '$SCRIPT_DIR/requirements.txt'"
run_user "'$VENV/bin/playwright' install chromium"

echo "[*] Playwright OS libraries (root)..."
"$VENV/bin/playwright" install-deps chromium || \
    echo -e "${YELLOW}[!] playwright install-deps failed; Chromium may still need extra libs.${NC}"

# =============================================================================
# STEP 3: Go PATH + ProjectDiscovery / ffuf / dalfox
# =============================================================================

echo -e "\n${GREEN}[3/7] Go tools (nuclei, katana, httpx, dalfox, ffuf)...${NC}"

if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}[!] go not on PATH; skip Go installs.${NC}"
else
    GOPATH_VAL="$(run_user 'go env GOPATH' | tr -d '\r')"
    [[ -z "$GOPATH_VAL" ]] && GOPATH_VAL="$REAL_HOME/go"
    GO_BIN="$GOPATH_VAL/bin"
    mkdir -p "$GO_BIN"
    chown -R "$REAL_USER:" "$GOPATH_VAL" 2>/dev/null || true

    BASHRC="$REAL_HOME/.bashrc"
    PATH_LINE='export PATH="$(go env GOPATH)/bin:$PATH"'
    if [[ -f "$BASHRC" ]] && ! grep -q 'go env GOPATH' "$BASHRC" 2>/dev/null; then
        echo "$PATH_LINE" >> "$BASHRC"
        chown "$REAL_USER:" "$BASHRC" 2>/dev/null || true
        echo "[+] Appended GOPATH/bin to $BASHRC"
    fi

    run_user "export PATH=\"$GO_BIN:\$PATH\"; go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    run_user "export PATH=\"$GO_BIN:\$PATH\"; go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    run_user "export PATH=\"$GO_BIN:\$PATH\"; go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    run_user "export PATH=\"$GO_BIN:\$PATH\"; go install -v github.com/hahwul/dalfox/v2@latest"
    run_user "export PATH=\"$GO_BIN:\$PATH\"; go install github.com/ffuf/ffuf/v2@latest"
fi

# =============================================================================
# STEP 4: Fallbacks when apt skipped a tool / stale distro packages
# =============================================================================

echo -e "\n${GREEN}[4/7] Fallbacks for missing CLIs...${NC}"

echo "[*] sqlmap from GitHub (Debian/Ubuntu apt is often flagged outdated)..."
if [[ -d /opt/sqlmap/.git ]]; then
    git -C /opt/sqlmap pull --ff-only || true
elif [[ ! -d /opt/sqlmap ]]; then
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap || true
fi
if [[ -f /opt/sqlmap/sqlmap.py ]]; then
    cat >/usr/local/bin/sqlmap <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/sqlmap/sqlmap.py "$@"
EOF
    chmod +x /usr/local/bin/sqlmap /opt/sqlmap/sqlmap.py
    echo "[+] sqlmap -> /usr/local/bin/sqlmap (GitHub /opt/sqlmap)"
elif ! command -v sqlmap &>/dev/null && ! run_user 'command -v sqlmap' &>/dev/null; then
    echo "[*] sqlmap via pipx..."
    run_user "pipx install sqlmap" || \
        run_user "'$VENV/bin/pip' install -U sqlmap" || true
fi

echo "[*] wapiti3 in venv (apt 3.0.x has a broken wapp database)..."
run_user "'$VENV/bin/pip' install -U wapiti3" || true
if [[ -x "$VENV/bin/wapiti" ]]; then
    ln -sf "$VENV/bin/wapiti" /usr/local/bin/wapiti
    echo "[+] wapiti -> /usr/local/bin/wapiti (venv wapiti3)"
    run_user "'$VENV/bin/wapiti' --update" || true
fi

if ! command -v ffuf &>/dev/null && [[ -n "${GO_BIN:-}" && -x "$GO_BIN/ffuf" ]]; then
    ln -sf "$GO_BIN/ffuf" /usr/local/bin/ffuf
    echo "[+] Linked $GO_BIN/ffuf -> /usr/local/bin/ffuf"
fi

if ! command -v dalfox &>/dev/null && [[ -n "${GO_BIN:-}" && -x "$GO_BIN/dalfox" ]]; then
    ln -sf "$GO_BIN/dalfox" /usr/local/bin/dalfox
    echo "[+] Linked dalfox -> /usr/local/bin/dalfox"
fi

if ! command -v nuclei &>/dev/null && [[ -n "${GO_BIN:-}" && -x "$GO_BIN/nuclei" ]]; then
    ln -sf "$GO_BIN/nuclei" /usr/local/bin/nuclei
fi
if ! command -v katana &>/dev/null && [[ -n "${GO_BIN:-}" && -x "$GO_BIN/katana" ]]; then
    ln -sf "$GO_BIN/katana" /usr/local/bin/katana
fi
if ! command -v httpx-toolkit &>/dev/null && [[ -n "${GO_BIN:-}" && -x "$GO_BIN/httpx" ]]; then
    ln -sf "$GO_BIN/httpx" /usr/local/bin/httpx-pd
    echo "[+] Linked ProjectDiscovery httpx -> /usr/local/bin/httpx-pd"
    echo "    (Metatron uses httpx-toolkit or GOPATH/bin/httpx, not Python httpx)"
fi

echo "[*] commix from GitHub (Debian/Ubuntu apt is often stale)..."
if [[ -d /opt/commix/.git ]]; then
    git -C /opt/commix pull --ff-only || true
elif [[ ! -d /opt/commix ]]; then
    git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix || true
fi
if [[ -f /opt/commix/commix.py ]]; then
    cat >/usr/local/bin/commix <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/commix/commix.py "$@"
EOF
    chmod +x /usr/local/bin/commix /opt/commix/commix.py
    echo "[+] commix -> /usr/local/bin/commix (GitHub /opt/commix)"
fi

if ! command -v wpscan &>/dev/null; then
    echo "[*] wpscan via gem..."
    gem install wpscan || true
fi

if ! command -v testssl.sh &>/dev/null && [[ ! -x /usr/bin/testssl.sh ]]; then
    if [[ ! -d /opt/testssl.sh ]]; then
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh || true
    fi
    if [[ -f /opt/testssl.sh/testssl.sh ]]; then
        ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
        chmod +x /opt/testssl.sh/testssl.sh
        echo "[+] Linked testssl.sh"
    fi
fi

# =============================================================================
# STEP 5: Ollama + metatron-qwen
# =============================================================================

echo -e "\n${GREEN}[5/7] Ollama and metatron-qwen model...${NC}"

if ! command -v ollama &>/dev/null; then
    echo "[*] Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "[+] Ollama already installed"
fi

systemctl enable ollama 2>/dev/null || true
systemctl start ollama 2>/dev/null || true
sleep 2

echo ""
echo "Select base model (needs RAM; 9b is the repo default):"
echo "  1) huihui_ai/qwen3.5-abliterated:9b   (default, ~8.4 GB RAM)"
echo "  2) huihui_ai/qwen3.5-abliterated:4b   (smaller)"
echo ""
read -r -p "Choice [1-2, default=1]: " model_choice || true
case "${model_choice:-1}" in
    2) BASE_MODEL="huihui_ai/qwen3.5-abliterated:4b" ;;
    *) BASE_MODEL="huihui_ai/qwen3.5-abliterated:9b" ;;
esac

MODELFILE="$SCRIPT_DIR/Modelfile"
if [[ ! -f "$MODELFILE" ]]; then
    echo -e "${RED}[!] Modelfile missing.${NC}"
else
    TMP_MF="$(mktemp)"
    sed "s|^FROM .*|FROM ${BASE_MODEL}|" "$MODELFILE" > "$TMP_MF"
    chown "$REAL_USER:" "$TMP_MF" 2>/dev/null || true
    echo "[*] Pulling ${BASE_MODEL} (this can take a while)..."
    run_user "ollama pull ${BASE_MODEL}"
    echo "[*] Creating metatron-qwen..."
    run_user "ollama create metatron-qwen -f '$TMP_MF'"
    rm -f "$TMP_MF"
    echo "[+] Model metatron-qwen created"
fi

# =============================================================================
# STEP 6: MariaDB (optional, matches README credentials)
# =============================================================================

echo -e "\n${GREEN}[6/7] MariaDB...${NC}"

systemctl enable mariadb 2>/dev/null || true
systemctl start mariadb 2>/dev/null || true

echo ""
read -r -p "Create metatron database/user (password 123 as in README)? [y/N]: " db_choice || true
if [[ "${db_choice,,}" == "y" ]]; then
    mysql -u root <<'SQL' || true
CREATE DATABASE IF NOT EXISTS metatron;
CREATE USER IF NOT EXISTS 'metatron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON metatron.* TO 'metatron'@'localhost';
FLUSH PRIVILEGES;
SQL
    mysql -u metatron -p123 metatron <<'SQL' || true
CREATE TABLE IF NOT EXISTS history (
  sl_no     INT AUTO_INCREMENT PRIMARY KEY,
  target    VARCHAR(255) NOT NULL,
  scan_date DATETIME NOT NULL,
  status    VARCHAR(50) DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sl_no       INT,
  vuln_name   TEXT,
  severity    VARCHAR(50),
  port        VARCHAR(20),
  service     VARCHAR(100),
  description TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
CREATE TABLE IF NOT EXISTS fixes (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  sl_no    INT,
  vuln_id  INT,
  fix_text TEXT,
  source   VARCHAR(50),
  FOREIGN KEY (sl_no) REFERENCES history(sl_no),
  FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);
CREATE TABLE IF NOT EXISTS exploits_attempted (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  exploit_name TEXT,
  tool_used    TEXT,
  payload      LONGTEXT,
  result       TEXT,
  notes        TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
CREATE TABLE IF NOT EXISTS summary (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  raw_scan     LONGTEXT,
  ai_analysis  LONGTEXT,
  risk_level   VARCHAR(50),
  generated_at DATETIME,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
SQL
    echo "[+] MariaDB schema applied (user metatron / password 123)"
else
    echo "[*] Skipped DB schema. See README Database Setup."
fi

# =============================================================================
# STEP 7: Verify
# =============================================================================

echo -e "\n${GREEN}[7/7] Verifying installation...${NC}"

PATH_CHECK="$PATH"
[[ -n "${GO_BIN:-}" ]] && PATH_CHECK="$GO_BIN:$PATH_CHECK"

check_cmd() {
    local name="$1"
    if command -v "$name" &>/dev/null || [[ -n "$GO_BIN" && -x "$GO_BIN/$name" ]] || [[ -x "$VENV/bin/$name" ]]; then
        echo -e "  [${GREEN}✓${NC}] $name"
    else
        echo -e "  [${RED}✗${NC}] $name (missing)"
    fi
}

echo ""
echo "Checking tools:"
for tool in nmap nikto whatweb gobuster arp-scan sslscan sqlmap wapiti ffuf \
            dalfox commix wpscan nuclei katana ollama; do
    check_cmd "$tool"
done

    if command -v httpx-toolkit &>/dev/null || [[ -n "$GO_BIN" && -x "$GO_BIN/httpx" ]]; then
    echo -e "  [${GREEN}✓${NC}] ProjectDiscovery httpx (httpx-toolkit or GOPATH/bin/httpx)"
else
    echo -e "  [${RED}✗${NC}] ProjectDiscovery httpx"
fi

if command -v zaproxy &>/dev/null || command -v zap.sh &>/dev/null || [[ -x /usr/share/zaproxy/zap.sh ]]; then
    echo -e "  [${GREEN}✓${NC}] ZAP"
else
    echo -e "  [${RED}✗${NC}] ZAP"
fi

if [[ -x "$VENV/bin/python" ]]; then
    echo -e "  [${GREEN}✓${NC}] venv python"
else
    echo -e "  [${RED}✗${NC}] venv python"
fi

if run_user "ollama list 2>/dev/null | grep -q metatron-qwen"; then
    echo -e "  [${GREEN}✓${NC}] ollama model metatron-qwen"
else
    echo -e "  [${YELLOW}~${NC}] ollama model metatron-qwen (not listed yet)"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              INSTALLATION COMPLETE                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Usage:"
echo ""
echo "  1. Open a new shell (so GOPATH/bin is on PATH), then:"
echo "       cd $SCRIPT_DIR"
echo "       source venv/bin/activate"
echo ""
echo "  2. Load the model (leave this tab running):"
echo "       ollama run metatron-qwen"
echo ""
echo "  3. In another tab:"
echo "       source venv/bin/activate"
echo "       python metatron.py"
echo ""
echo -e "${YELLOW}[!] Only scan systems you own or have permission to test.${NC}"
echo ""
