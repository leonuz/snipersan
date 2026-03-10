#!/usr/bin/env bash
# SniperSan — automated setup for Debian/Ubuntu Linux
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[-]${NC} $*"; exit 1; }

echo -e "${RED}"
cat << 'EOF'
███████╗███╗   ██╗██╗██████╗ ███████╗██████╗ ███████╗ █████╗ ███╗   ██╗
██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗████╗  ██║
███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝███████╗███████║██╔██╗ ██║
╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗╚════██║██╔══██║██║╚██╗██║
███████║██║ ╚████║██║██║     ███████╗██║  ██║███████║██║  ██║██║ ╚████║
╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
echo -e "${NC}         AI-Powered Web Penetration Testing Agent — Installer"
echo ""

# ─── OS check ────────────────────────────────────────────────────────────────
if [[ ! -f /etc/debian_version ]]; then
    warn "This installer targets Debian/Ubuntu. Other distros may need manual adjustments."
fi

# ─── Python ──────────────────────────────────────────────────────────────────
info "Checking Python 3.10+..."
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install Python 3.10+ and re-run."
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ $PY_MAJOR -lt 3 || ($PY_MAJOR -eq 3 && $PY_MINOR -lt 10) ]]; then
    error "Python 3.10+ required (found $PY_VER)."
fi
success "Python $PY_VER found."

# ─── pip ─────────────────────────────────────────────────────────────────────
info "Installing Python dependencies..."
if ! command -v pip3 &>/dev/null && ! python3 -m pip --version &>/dev/null 2>&1; then
    warn "pip not found, attempting to install..."
    sudo apt-get install -y python3-pip
fi

# WeasyPrint needs system libs
info "Installing WeasyPrint system dependencies..."
sudo apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    2>/dev/null || warn "Some WeasyPrint libs may be missing — PDF export might fail."

python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --quiet
success "Python dependencies installed."

# ─── nmap ────────────────────────────────────────────────────────────────────
info "Checking nmap..."
if command -v nmap &>/dev/null; then
    success "nmap already installed: $(nmap --version | head -1)"
else
    info "Installing nmap..."
    sudo apt-get install -y nmap
    success "nmap installed."
fi

# ─── WPScan ──────────────────────────────────────────────────────────────────
info "Checking WPScan..."
if command -v wpscan &>/dev/null; then
    success "WPScan already installed: $(wpscan --version 2>/dev/null | head -1)"
else
    info "Installing Ruby + WPScan..."
    sudo apt-get install -y ruby ruby-dev build-essential libcurl4-openssl-dev libxml2 libxml2-dev zlib1g-dev
    sudo gem install wpscan --quiet
    success "WPScan installed."
fi

# ─── Nuclei ──────────────────────────────────────────────────────────────────
info "Checking Nuclei..."
if command -v nuclei &>/dev/null; then
    success "Nuclei already installed: $(nuclei -version 2>&1 | head -1)"
else
    info "Installing Nuclei..."
    NUCLEI_TAG=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    NUCLEI_VER="${NUCLEI_TAG#v}"
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_TAG}/nuclei_${NUCLEI_VER}_linux_amd64.zip"
    info "Downloading nuclei $NUCLEI_VER..."
    curl -sL "$NUCLEI_URL" -o /tmp/nuclei.zip
    unzip -q /tmp/nuclei.zip -d /tmp/nuclei_bin
    sudo mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei
    sudo chmod +x /usr/local/bin/nuclei
    rm -rf /tmp/nuclei.zip /tmp/nuclei_bin
    success "Nuclei $NUCLEI_VER installed."
fi

# ─── .env setup ──────────────────────────────────────────────────────────────
echo ""
if [[ -f .env ]]; then
    warn ".env already exists — skipping."
else
    info "Setting up .env..."
    cp .env.example .env

    read -rp "$(echo -e "${CYAN}[?]${NC} Enter your ANTHROPIC_API_KEY (sk-ant-...): ")" ANTHROPIC_KEY
    if [[ -n "$ANTHROPIC_KEY" ]]; then
        sed -i "s|ANTHROPIC_API_KEY=.*|ANTHROPIC_API_KEY=${ANTHROPIC_KEY}|" .env
        success "ANTHROPIC_API_KEY set."
    else
        warn "No key entered — edit .env manually before running."
    fi

    read -rp "$(echo -e "${CYAN}[?]${NC} Enter your WPSCAN_API_TOKEN (optional, press Enter to skip): ")" WPSCAN_KEY
    if [[ -n "$WPSCAN_KEY" ]]; then
        sed -i "s|WPSCAN_API_TOKEN=.*|WPSCAN_API_TOKEN=${WPSCAN_KEY}|" .env
        success "WPSCAN_API_TOKEN set."
    fi
fi

# ─── reports dir ─────────────────────────────────────────────────────────────
mkdir -p reports

# ─── done ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Run:  python3 main.py"
echo "  Auto: python3 main.py -t https://target.com -m auto"
echo "  Help: python3 main.py --help"
echo ""
