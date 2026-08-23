#!/bin/bash

set -euo pipefail

# AI-Powered Penetration Testing Assist System - Kali Linux Setup Script
# This script sets up the complete environment on Kali Linux

echo "=========================================="
echo "PTAS - Kali Linux Setup"
echo "=========================================="

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
if [ "${EUID}" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

# Step 1: Update system
echo -e "${BLUE}[1/8] Updating system packages...${NC}"
$SUDO apt update

# Step 2: Install Python and pip
echo -e "${BLUE}[2/8] Installing Python 3 and pip...${NC}"
$SUDO apt install -y python3 python3-pip python3-venv

# Step 3: Install MySQL/MariaDB
echo -e "${BLUE}[3/8] Installing MariaDB (MySQL alternative)...${NC}"
$SUDO apt install -y mariadb-server mariadb-client

# Step 4: Install Nmap and the native split-terminal window
echo -e "${BLUE}[4/8] Installing Nmap and Terminator...${NC}"
$SUDO apt install -y nmap terminator

# Step 5: Start and enable MariaDB
echo -e "${BLUE}[5/8] Starting MariaDB service...${NC}"
$SUDO systemctl start mariadb
$SUDO systemctl enable mariadb

# Step 6: Create Python virtual environment
echo -e "${BLUE}[6/8] Creating Python virtual environment...${NC}"
cd "$PROJECT_DIR"
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
PYTHON="$PROJECT_DIR/.venv/bin/python"

# Step 7: Install Python dependencies
echo -e "${BLUE}[7/8] Installing Python dependencies...${NC}"
"$PYTHON" -m pip install --upgrade pip
"$PYTHON" -m pip install -r Backend/requirements-kali.txt

# Install the short command students use from any terminal. The launcher
# resolves this symlink back to the repository and its virtual environment.
echo -e "${BLUE}[8/8] Installing the global ptas command...${NC}"
$SUDO ln -sfn "$PROJECT_DIR/ptas.sh" /usr/local/bin/ptas

# Create a local development database and least-privilege application user.
echo -e "${BLUE}Configuring PTAS database...${NC}"
$SUDO mariadb <<'SQL'
CREATE DATABASE IF NOT EXISTS ptas_db;
CREATE USER IF NOT EXISTS 'ptas_user'@'localhost' IDENTIFIED BY 'ptas_password';
GRANT ALL PRIVILEGES ON ptas_db.* TO 'ptas_user'@'localhost';
FLUSH PRIVILEGES;
SQL

if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${YELLOW}Created .env from .env.example; change SECRET_KEY before non-local use.${NC}"
fi

echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review DATABASE_URL and SECRET_KEY in .env"
echo ""
echo "2. Activate virtual environment:"
echo "   source .venv/bin/activate"
echo ""
echo "3. Open a normal Linux terminal and start the student interface:"
echo "   ptas"
echo ""
echo "4. To start only the backend API, use:"
echo "   uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Application will be available at: http://localhost:8000"
