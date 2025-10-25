#!/bin/bash
#
# Aegis Cloud Security Scanner - Production Launcher (Linux/macOS)
# ================================================================
#
# This script launches Aegis Cloud Scanner with Waitress production server
# for Linux and macOS systems.
#
# Usage:
#   ./start_aegis.sh          # Start in production mode
#   ./start_aegis.sh dev      # Start in development mode
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Virtual environment directory
VENV_DIR="$SCRIPT_DIR/venv"

# Check mode
MODE="${1:-production}"

# Function to open browser
open_browser() {
    sleep 5
    local url="http://localhost:5000"

    # Detect OS and use appropriate command
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open "$url" 2>/dev/null &
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command -v xdg-open &> /dev/null; then
            xdg-open "$url" 2>/dev/null &
        elif command -v gnome-open &> /dev/null; then
            gnome-open "$url" 2>/dev/null &
        fi
    fi
}

# Banner
echo ""
echo "========================================"
echo "  🛡️  AEGIS CLOUD SECURITY SCANNER"
if [ "$MODE" == "dev" ]; then
    echo "  Version 0.9.1 - DEVELOPMENT MODE"
else
    echo "  Version 0.9.1 - PRODUCTION MODE"
fi
echo "========================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR]${NC} Python 3 is not installed!"
    echo ""
    echo "Please install Python 3.8 or higher:"
    echo "  - Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
    echo "  - macOS: brew install python@3.11"
    echo ""
    exit 1
fi

echo -e "${CYAN}[1/4]${NC} Checking Python installation..."
python3 --version

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo ""
    echo -e "${CYAN}[2/4]${NC} Creating virtual environment..."
    echo "Location: $VENV_DIR"

    python3 -m venv "$VENV_DIR"

    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Failed to create virtual environment!"
        echo ""
        echo "Try installing python3-venv:"
        echo "  sudo apt install python3-venv"
        exit 1
    fi

    echo -e "${GREEN}✅ Virtual environment created successfully!${NC}"
else
    echo -e "${CYAN}[2/4]${NC} Virtual environment already exists"
fi

# Activate virtual environment
echo -e "${CYAN}[3/4]${NC} Activating virtual environment..."
source "$VENV_DIR/bin/activate"

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed to activate virtual environment!"
    exit 1
fi

# Install/update requirements
echo -e "${CYAN}[4/4]${NC} Installing dependencies (this may take a few minutes on first run)..."
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet --upgrade

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[WARNING]${NC} Some dependencies failed to install. Trying without upgrade..."
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
fi

# Clear screen and show startup message
clear
echo ""
echo "========================================"
echo "  🛡️  AEGIS CLOUD SECURITY SCANNER"

if [ "$MODE" == "dev" ]; then
    echo "  Development Server (Flask Debug)"
    echo "========================================"
    echo ""
    echo "  Status: STARTING..."
    echo "  Access URL: http://localhost:5000"
    echo "  Debug Mode: ENABLED"
    echo ""
    echo "  Features:"
    echo "  - Auto-reload on code changes"
    echo "  - Detailed error messages"
    echo ""
    echo "  Opening browser in 5 seconds..."
    echo "  Press Ctrl+C to stop the server"
    echo "========================================"
    echo ""

    # Set Flask environment variables for development
    export FLASK_ENV=development
    export FLASK_DEBUG=1

    # Open browser in background
    open_browser &

    # Start Flask development server
    python3 "$SCRIPT_DIR/app.py"
else
    echo "  Production Server (Waitress)"
    echo "========================================"
    echo ""
    echo "  Status: STARTING..."
    echo "  Access URL: http://localhost:5000"
    echo ""
    echo "  Opening browser in 5 seconds..."
    echo "  Press Ctrl+C to stop the server"
    echo "========================================"
    echo ""

    # Open browser in background
    open_browser &

    # Start Waitress production server
    python3 "$SCRIPT_DIR/run_production.py"
fi

# Deactivate virtual environment on exit
deactivate
