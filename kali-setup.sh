#!/bin/bash

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

# Step 1: Update system
echo -e "${BLUE}[1/7] Updating system packages...${NC}"
sudo apt update && sudo apt upgrade -y

# Step 2: Install Python and pip
echo -e "${BLUE}[2/7] Installing Python 3 and pip...${NC}"
sudo apt install -y python3 python3-pip python3-venv

# Step 3: Install MySQL/MariaDB
echo -e "${BLUE}[3/7] Installing MariaDB (MySQL alternative)...${NC}"
sudo apt install -y mariadb-server mariadb-client

# Step 4: Install Nmap (Kali usually has this, but ensure it's installed)
echo -e "${BLUE}[4/7] Installing Nmap...${NC}"
sudo apt install -y nmap

# Step 5: Start and enable MariaDB
echo -e "${BLUE}[5/7] Starting MariaDB service...${NC}"
sudo systemctl start mariadb
sudo systemctl enable mariadb

# Step 6: Create Python virtual environment
echo -e "${BLUE}[6/7] Creating Python virtual environment...${NC}"
cd "$(dirname "$0")"
python3 -m venv venv
source venv/bin/activate

# Step 7: Install Python dependencies
echo -e "${BLUE}[7/7] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r Backend/requirements.txt

echo -e "${GREEN}=========================================="
echo "Setup Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Create MySQL database:"
echo "   sudo mysql -u root"
echo "   MariaDB [(none)]> CREATE DATABASE ptas_db;"
echo "   MariaDB [(none)]> EXIT;"
echo ""
echo "2. Update Backend/database.py with your MySQL credentials (if needed)"
echo ""
echo "3. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "4. Run the application:"
echo "   cd Backend"
echo "   python3 main.py"
echo ""
echo "5. Or start with Uvicorn directly:"
echo "   uvicorn Backend.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo "Application will be available at: http://localhost:8000"
