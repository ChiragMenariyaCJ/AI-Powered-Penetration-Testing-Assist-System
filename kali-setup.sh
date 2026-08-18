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
echo -e "${BLUE}[1/7] Updating system packages...${NC}"
$SUDO apt update

# Step 2: Install Python and pip
echo -e "${BLUE}[2/7] Installing Python 3 and pip...${NC}"
$SUDO apt install -y python3 python3-pip python3-venv

# Step 3: Install MySQL/MariaDB
echo -e "${BLUE}[3/7] Installing MariaDB (MySQL alternative)...${NC}"
$SUDO apt install -y mariadb-server mariadb-client

# Step 4: Install Nmap (Kali usually has this, but ensure it's installed)
echo -e "${BLUE}[4/7] Installing Nmap...${NC}"
$SUDO apt install -y nmap tmux

# Step 5: Start and enable MariaDB
echo -e "${BLUE}[5/7] Starting MariaDB service...${NC}"
$SUDO systemctl start mariadb
$SUDO systemctl enable mariadb

# Step 6: Create Python virtual environment
echo -e "${BLUE}[6/7] Creating Python virtual environment...${NC}"
cd "$PROJECT_DIR"
if [ ! -d venv ]; then
    python3 -m venv venv
fi
source venv/bin/activate

# Step 7: Install Python dependencies
echo -e "${BLUE}[7/7] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r Backend/requirements-kali.txt

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
echo "   source venv/bin/activate"
echo ""
echo "3. Run the application from the repository root:"
echo "   ./start.sh"
echo ""
echo "4. Or start with Uvicorn directly:"
echo "   uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Application will be available at: http://localhost:8000"
