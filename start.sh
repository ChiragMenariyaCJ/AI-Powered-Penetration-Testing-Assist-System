#!/bin/bash

# Quick start script for PTAS on Kali Linux
# Run this to start the application with one command

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"; pwd)"
BACKEND_DIR="$PROJECT_DIR/Backend"
VENV_DIR="$PROJECT_DIR/venv"

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

# Activate virtual environment
echo -e "${BLUE}🔧 Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Install/upgrade dependencies
echo -e "${BLUE}📚 Installing Python dependencies...${NC}"
pip install --quiet --upgrade pip
pip install --quiet -r "$BACKEND_DIR/requirements.txt"

# Check database
echo -e "${BLUE}🗄️  Checking database...${NC}"
DB_EXISTS=$(mysql -u root -e "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='ptas_db'" 2>/dev/null | grep ptas_db)

if [ -z "$DB_EXISTS" ]; then
    echo -e "${YELLOW}⚠️  Database 'ptas_db' not found. Creating...${NC}"
    sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS ptas_db;" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Database created successfully${NC}"
    else
        echo -e "${RED}⚠️  Could not create database with sudo${NC}"
        echo -e "${YELLOW}   Try running as root or check MySQL permissions${NC}"
    fi
else
    echo -e "${GREEN}✅ Database 'ptas_db' exists${NC}"
fi

echo ""
echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ All checks passed! Starting API  ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}📍 API Information:${NC}"
echo -e "   Base URL:      ${YELLOW}http://localhost:8000${NC}"
echo -e "   Swagger Docs:  ${YELLOW}http://localhost:8000/docs${NC}"
echo -e "   ReDoc:         ${YELLOW}http://localhost:8000/redoc${NC}"
echo ""
echo -e "${BLUE}⏹️  Press Ctrl+C to stop the server${NC}"
echo ""

# Start the application
cd "$BACKEND_DIR"
uvicorn main:app --reload --host 0.0.0.0 --port 8000
