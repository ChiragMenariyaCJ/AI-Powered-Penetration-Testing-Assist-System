#!/bin/bash

set -euo pipefail

# This script sets up PTAS on Kali Linux.

echo "=========================================="
echo "PTAS - Kali Linux Setup"
echo "=========================================="

# These colours make the setup output easier to read.
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
OLLAMA_SETUP_MODEL="${PTAS_SETUP_OLLAMA_MODEL:-qwen2.5:3b-instruct}"
if [[ ! "$OLLAMA_SETUP_MODEL" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
    echo "PTAS_SETUP_OLLAMA_MODEL contains unsupported characters." >&2
    exit 1
fi
if [ "${EUID}" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Update one .env value without changing the other settings.
set_env_value() {
    local key="$1"
    local value="$2"
    if grep -q "^${key}=" .env; then
        sed -i "s|^${key}=.*|${key}=${value}|" .env
    else
        printf '\n%s=%s\n' "$key" "$value" >> .env
    fi
}

# Update the installed system packages.
echo -e "${BLUE}[1/9] Updating system packages...${NC}"
$SUDO apt update

# Install Python and the download tools used by setup.
echo -e "${BLUE}[2/9] Installing Python 3, pip, and download tools...${NC}"
$SUDO apt install -y python3 python3-pip python3-venv curl ca-certificates

# Install MariaDB.
echo -e "${BLUE}[3/9] Installing MariaDB (MySQL alternative)...${NC}"
$SUDO apt install -y mariadb-server mariadb-client

# Install Nmap and Terminator.
echo -e "${BLUE}[4/9] Installing Nmap and Terminator...${NC}"
$SUDO apt install -y nmap terminator

# Start MariaDB and enable it at boot.
echo -e "${BLUE}[5/9] Starting MariaDB service...${NC}"
$SUDO systemctl start mariadb
$SUDO systemctl enable mariadb

# Create the Python virtual environment.
echo -e "${BLUE}[6/9] Creating Python virtual environment...${NC}"
cd "$PROJECT_DIR"
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
PYTHON="$PROJECT_DIR/.venv/bin/python"

# Install the Python packages used by PTAS.
echo -e "${BLUE}[7/9] Installing Python dependencies...${NC}"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r Backend/requirements-kali.txt

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}Created .env from .env.example; change SECRET_KEY before non-local use.${NC}"
fi

# Install Ollama safely unless PTAS_SKIP_OLLAMA is enabled.
echo -e "${BLUE}[8/9] Installing the local Ollama recommendation model...${NC}"
if [ "${PTAS_SKIP_OLLAMA:-0}" = "1" ]; then
    echo -e "${YELLOW}Skipping Ollama because PTAS_SKIP_OLLAMA=1.${NC}"
else
    if ! command -v ollama >/dev/null 2>&1; then
        OLLAMA_INSTALLER="$(mktemp)"
        if ! curl -fsSL https://ollama.com/install.sh -o "$OLLAMA_INSTALLER"; then
            rm -f "$OLLAMA_INSTALLER"
            echo "Could not download the official Ollama installer." >&2
            exit 1
        fi
        if ! $SUDO sh "$OLLAMA_INSTALLER"; then
            rm -f "$OLLAMA_INSTALLER"
            echo "The official Ollama installer did not complete successfully." >&2
            exit 1
        fi
        rm -f "$OLLAMA_INSTALLER"
    fi

    $SUDO systemctl enable --now ollama
    OLLAMA_READY=0
    for _attempt in {1..30}; do
        if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
            OLLAMA_READY=1
            break
        fi
        sleep 1
    done
    if [ "$OLLAMA_READY" -ne 1 ]; then
        echo "Ollama did not become ready at http://127.0.0.1:11434." >&2
        echo "Check it with: sudo systemctl status ollama" >&2
        exit 1
    fi

    # Reuse model files that Ollama has already downloaded.
    ollama pull "$OLLAMA_SETUP_MODEL"
    set_env_value "PTAS_LLM_PROVIDER" "ollama"
    set_env_value "OLLAMA_BASE_URL" "http://127.0.0.1:11434"
    set_env_value "OLLAMA_MODEL" "$OLLAMA_SETUP_MODEL"
fi

# Install the short ptas command for every terminal.
echo -e "${BLUE}[9/9] Installing the global ptas command...${NC}"
$SUDO ln -sfn "$PROJECT_DIR/ptas.sh" /usr/local/bin/ptas

# Create the local database and application user.
echo -e "${BLUE}Configuring PTAS database...${NC}"
$SUDO mariadb <<'SQL'
CREATE DATABASE IF NOT EXISTS ptas_db;
CREATE USER IF NOT EXISTS 'ptas_user'@'localhost' IDENTIFIED BY 'ptas_password';
GRANT ALL PRIVILEGES ON ptas_db.* TO 'ptas_user'@'localhost';
FLUSH PRIVILEGES;
SQL

# Register Metasploitable now when its IP was supplied.
METASPLOITABLE_SETUP_IP="${PTAS_METASPLOITABLE_IP:-}"
METASPLOITABLE_SETUP_LAB="${PTAS_METASPLOITABLE_LAB:-msf2-local}"
if [ -n "$METASPLOITABLE_SETUP_IP" ]; then
    echo -e "${BLUE}Configuring Metasploitable 2 network registration...${NC}"
    if ! "$PROJECT_DIR/metasploitable-setup.sh" \
        --target "$METASPLOITABLE_SETUP_IP" \
        --name "$METASPLOITABLE_SETUP_LAB"; then
        echo -e "${YELLOW}PTAS installed, but Metasploitable registration failed.${NC}"
        echo "Start the VM, confirm its host-only IP, and rerun metasploitable-setup.sh."
    fi
fi

echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review DATABASE_URL and SECRET_KEY in .env"
echo ""
echo "2. Start the backend in the VS Code terminal and leave it running:"
echo "   ./start.sh"
echo ""
echo "3. Open a separate Linux terminal and start the student interface:"
echo "   ptas"
echo ""
echo "4. Activate the virtual environment only for manual development commands:"
echo "   source .venv/bin/activate"
echo ""
if [ -z "$METASPLOITABLE_SETUP_IP" ]; then
    echo "5. Optional: register a VMware Metasploitable guest by its current IP:"
    echo "   ./metasploitable-setup.sh --target 192.168.121.130"
    echo ""
fi
if [ "${PTAS_SKIP_OLLAMA:-0}" != "1" ]; then
    echo "Local recommendation model: $OLLAMA_SETUP_MODEL"
    echo "Ollama API: http://127.0.0.1:11434"
    echo ""
fi
echo "Application will be available at: http://localhost:8000"
