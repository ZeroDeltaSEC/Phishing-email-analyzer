#!/bin/bash
# Installation and Setup Script for Advanced Phishing Email Analyzer v2.0

echo "=========================================="
echo " Phishing Email Analyzer v2.0 Setup"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root for some installations
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Note: Some dependencies may require sudo/root access${NC}"
    echo ""
fi

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
    fi
}

echo "=== Checking System Dependencies ==="
echo ""

# Check Python
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    print_status 0 "Python 3 installed (version $PYTHON_VERSION)"
else
    print_status 1 "Python 3 not found - REQUIRED"
    echo "  Install: sudo apt install python3 python3-pip"
fi

# Check pip
if command_exists pip3; then
    print_status 0 "pip3 installed"
else
    print_status 1 "pip3 not found - REQUIRED"
    echo "  Install: sudo apt install python3-pip"
fi

# Check system tools
echo ""
echo "=== Checking Analysis Tools ==="
echo ""

# Essential tools
command_exists curl && print_status 0 "curl installed" || print_status 1 "curl not found"
command_exists file && print_status 0 "file command installed" || print_status 1 "file not found"
command_exists strings && print_status 0 "strings installed" || print_status 1 "strings not found"

# Network analysis tools
command_exists tcpdump && print_status 0 "tcpdump installed" || print_status 1 "tcpdump not found (optional, but recommended)"
command_exists tshark && print_status 0 "tshark installed" || print_status 1 "tshark not found (optional)"

# File analysis tools
command_exists exiftool && print_status 0 "exiftool installed" || print_status 1 "exiftool not found (recommended)"
command_exists binwalk && print_status 0 "binwalk installed" || print_status 1 "binwalk not found (recommended)"
command_exists yara && print_status 0 "YARA installed" || print_status 1 "YARA not found (recommended)"

# Office document analysis
command_exists olevba && print_status 0 "oletools installed" || print_status 1 "oletools not found (recommended for Office docs)"

# Browser automation
command_exists firefox && print_status 0 "Firefox installed" || print_status 1 "Firefox not found (required for URL detonation)"
command_exists geckodriver && print_status 0 "geckodriver installed" || print_status 1 "geckodriver not found (required for Selenium)"

# AI
command_exists ollama && print_status 0 "Ollama installed" || print_status 1 "Ollama not found (required for AI analysis)"

echo ""
echo "=== Python Dependencies Check ==="
echo ""

# Check Python packages
python3 -c "import selenium" 2>/dev/null && print_status 0 "selenium installed" || print_status 1 "selenium not found"
python3 -c "import magic" 2>/dev/null && print_status 0 "python-magic installed" || print_status 1 "python-magic not found"

echo ""
echo "=== Installation Recommendations ==="
echo ""

cat << 'EOF'
To install missing dependencies on Kali Linux / Debian / Ubuntu:

# System packages
sudo apt update
sudo apt install -y \
    python3 python3-pip \
    curl file binutils \
    tcpdump tshark wireshark-common \
    exiftool libimage-exiftool-perl \
    binwalk yara \
    firefox-esr geckodriver

# Python packages
pip3 install -r requirements.txt
pip3 install selenium python-magic yara-python oletools

# Ollama (AI Analysis)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2:3b

EOF

echo ""
echo "=== Quick Start ==="
echo ""
echo "1. Install missing dependencies (see above)"
echo "2. Make script executable: chmod +x analyze_phishing_v2.py"
echo "3. Run analysis: python3 analyze_phishing_v2.py suspicious.eml"
echo ""

# Offer to install Python dependencies
echo -e "${YELLOW}Do you want to install Python dependencies now? (y/n)${NC}"
read -r response

if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    echo ""
    echo "Installing Python dependencies..."
    pip3 install -r requirements.txt
    pip3 install selenium python-magic yara-python oletools
    echo ""
    echo -e "${GREEN}Python dependencies installed!${NC}"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Check README.md for full documentation"
echo ""
