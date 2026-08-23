#!/bin/bash

set -euo pipefail

# Quick start script for PTAS on Kali Linux
# Run this to start the application with one command

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
BACKEND_DIR="$PROJECT_DIR/Backend"
VENV_DIR="$PROJECT_DIR/.venv"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   PTAS - Quick Start (Kali Linux)      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    echo "Install with: sudo apt install -y python3 python3-pip"
    exit 1
fi

# Check if Nmap is installed
if ! command -v nmap &> /dev/null; then
    echo -e "${RED}❌ Nmap is not installed${NC}"
    echo "Install with: sudo apt install -y nmap"
    exit 1
fi

# Check if MariaDB/MySQL is installed
if ! command -v mysql &> /dev/null && ! command -v mariadb &> /dev/null; then
    echo -e "${RED}❌ MySQL/MariaDB is not installed${NC}"
    echo "Install with: sudo apt install -y mariadb-server"
    exit 1
fi

# Check if MariaDB/MySQL is running
if ! sudo systemctl is-active --quiet mariadb 2>/dev/null && ! sudo systemctl is-active --quiet mysql 2>/dev/null; then
    echo -e "${YELLOW}⚠️  MariaDB/MySQL is not running. Attempting to start...${NC}"
    sudo systemctl start mariadb 2>/dev/null || sudo systemctl start mysql 2>/dev/null
    sleep 2
fi

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${BLUE}📦 Creating Python virtual environment...${NC}"
    python3 -m venv "$VENV_DIR"
fi

# Use the project interpreter explicitly. This avoids accidentally installing
# dependencies with, or launching Uvicorn from, the system Python.
PYTHON="$VENV_DIR/bin/python"

# Install/upgrade dependencies
echo -e "${BLUE}📚 Installing Python dependencies...${NC}"
"$PYTHON" -m pip install --quiet --upgrade pip
"$PYTHON" -m pip install --quiet -r "$BACKEND_DIR/requirements-kali.txt"

# Check the configured application connection rather than assuming a root login.
echo -e "${BLUE}🗄️  Checking database connection...${NC}"
cd "$PROJECT_DIR"
if ! "$PYTHON" -c "from Backend.database import engine; c = engine.connect(); c.close()"; then
    echo -e "${RED}❌ Could not connect using DATABASE_URL${NC}"
    echo -e "${YELLOW}Run ./kali-setup.sh, or update DATABASE_URL in .env.${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Database connection succeeded${NC}"
PTAS_API_HOST="$("$PYTHON" -c 'from Backend.config import settings; print(settings.api_host)')"
PTAS_API_PORT="$("$PYTHON" -c 'from Backend.config import settings; print(settings.api_port)')"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ All checks passed! Starting API  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📍 API Information:${NC}"
echo -e "   Base URL:      ${YELLOW}http://${PTAS_API_HOST}:${PTAS_API_PORT}${NC}"
echo -e "   Swagger Docs:  ${YELLOW}http://${PTAS_API_HOST}:${PTAS_API_PORT}/docs${NC}"
echo -e "   ReDoc:         ${YELLOW}http://${PTAS_API_HOST}:${PTAS_API_PORT}/redoc${NC}"
echo ""
echo -e "${BLUE}⏹️  Press Ctrl+C to stop the server${NC}"
echo -e "${BLUE}🧭 Layer tracing:${NC} route → controller → usecase → repository"
echo ""

# Start from the repository root so Backend.* imports resolve correctly.
cd "$PROJECT_DIR"
exec "$PYTHON" -m uvicorn Backend.main:app --reload \
    --host "$PTAS_API_HOST" \
    --port "$PTAS_API_PORT" \
    --log-level info
