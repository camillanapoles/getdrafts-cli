#!/bin/bash
#
# MobSF Local Installation Script for iOS-Pentesting-Skill
#
# Usage: ./scripts/install-mobsf-local.sh [--prefix PREFIX]
#

set -e

INSTALL_DIR="${INSTALL_DIR:-$HOME/MobSF}"
VENV_DIR="${VENV_DIR:-$INSTALL_DIR/venv}"

echo "🔧 Installing MobSF locally..."
echo "   Directory: $INSTALL_DIR"
echo "   Virtualenv: $VENV_DIR"
echo ""

check_prerequisites() {
    local missing=()

    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi

    if ! command -v git &> /dev/null; then
        missing+=("git")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo "❌ Missing prerequisites: ${missing[*]}"
        echo "   Install missing packages:"
        echo "   macOS: brew install python git"
        echo "   Ubuntu: sudo apt install python3 python3-pip git"
        exit 1
    fi
}

check_prerequisites

if [ -d "$INSTALL_DIR" ]; then
    echo "📁 MobSF directory exists, updating..."
    cd "$INSTALL_DIR"
    git fetch origin
    git pull origin master
else
    echo "📥 Cloning MobSF repository..."
    git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

if [ ! -d "$VENV_DIR" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "🔌 Activating virtual environment..."
# Resolved at runtime; shellcheck cannot follow it.
# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

echo "📦 Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🚀 Installing MobSF..."
python setup.py install

echo ""
echo "✅ MobSF installed successfully!"
echo ""
echo "   To run MobSF:"
echo "   1. Activate venv: source $VENV_DIR/bin/activate"
echo "   2. Run server: python manage.py runserver"
echo ""
echo "   Or use the wrapper script:"
echo "   ./scripts/run-mobsf-local.sh"
