#!/usr/bin/env bash

################################################################################
# iOS Pentesting Environment Setup Script
# Description: Automated installation of all required tools for iOS pentesting
# Author: iOS-Pentesting-Skill
# Version: 1.0.0
# Usage: ./scripts/setup-environment.sh [--dry-run] [--force]
#
# This script detects your OS and installs the required tools automatically.
# It supports macOS, Linux (Debian/Ubuntu, Arch, Fedora), and provides
# clear feedback throughout the installation process.
################################################################################

set -euo pipefail

# Color codes
RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
RED=$(tput setaf 1 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
BOLD=$(tput bold 2>/dev/null || echo "")

# Parse arguments
DRY_RUN=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--force]"
            exit 1
            ;;
    esac
done

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux) echo "linux" ;;
        *) echo "unknown" ;;
    esac
}

# Detect Linux distribution
detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # Resolved at runtime; shellcheck cannot follow it.
        # shellcheck source=/dev/null
        . /etc/os-release
        echo "$ID"
    elif command -v apt-get &>/dev/null; then
        echo "debian"
    elif command -v pacman &>/dev/null; then
        echo "arch"
    elif command -v dnf &>/dev/null || command -v yum &>/dev/null; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

# Install command wrapper
install_cmd() {
    local cmd="$1"
    if [[ "$DRY_RUN" == true ]]; then
        echo "${BLUE}[DRY RUN]${RESET} Would execute: $cmd"
        return 0
    fi

    if [[ "$FORCE" == true ]]; then
        eval "$cmd" </dev/tty
    else
        eval "$cmd"
    fi
}

# Print section header
print_header() {
    echo ""
    echo "${BLUE}${BOLD}========================================${RESET}"
    echo "${BLUE}${BOLD}  $1${RESET}"
    echo "${BLUE}${BOLD}========================================${RESET}"
    echo ""
}

# Print success
print_success() {
    echo "${GREEN}✅${RESET} $1"
}

# Print error
print_error() {
    echo "${RED}❌${RESET} $1"
}

# Print warning
print_warning() {
    echo "${YELLOW}⚠️  ${RESET} $1"
}

# Main setup
OS=$(detect_os)
DISTRO=""

if [[ "$OS" == "linux" ]]; then
    DISTRO=$(detect_distro)
fi

print_header "iOS Pentesting Environment Setup"
echo "${BOLD}Detected OS:${RESET} $OS"
if [[ "$OS" == "linux" ]]; then
    echo "${BOLD}Distribution:${RESET} $DISTRO"
fi
echo ""

if [[ "$DRY_RUN" == true ]]; then
    print_warning "DRY RUN MODE - No actual installations will be performed"
    echo ""
fi

# Track what was installed
INSTALLED_TOOLS=()

# macOS setup
if [[ "$OS" == "macos" ]]; then
    print_header "macOS Setup"

    # Check if Homebrew is installed
    if ! command -v brew &>/dev/null; then
        echo "Installing Homebrew..."
        if [[ "$DRY_RUN" == false ]]; then
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        else
            echo "[DRY RUN] Would install Homebrew"
        fi
        INSTALLED_TOOLS+=("homebrew")
    else
        print_success "Homebrew already installed"
    fi

    # Add Homebrew to PATH if needed (Apple Silicon)
    if [[ -d "/opt/homebrew/bin" ]] && [[ ":$PATH:" != *":/opt/homebrew/bin:"* ]]; then
        export PATH="/opt/homebrew/bin:$PATH"
    fi

    echo ""
    echo "Installing Python 3.11+..."
    if brew list python@3.11 &>/dev/null || brew list python@3.12 &>/dev/null || brew list python@3.13 &>/dev/null || brew list python@3.14 &>/dev/null; then
        print_success "Python 3 already installed"
    else
        install_cmd "brew install python@3.11"
        INSTALLED_TOOLS+=("python@3.11")
    fi

    echo ""
    echo "Installing Xcode Command Line Tools..."
    if xcode-select -p &>/dev/null; then
        print_success "Xcode CLI already installed"
    else
        install_cmd "xcode-select --install"
        INSTALLED_TOOLS+=("xcode-cli")
    fi

    echo ""
    echo "Installing core tools via Homebrew..."
    BREW_PACKAGES=(
        "git"
        "wget"
        "curl"
        "jq"
        "tree"
        "ripgrep"
        "ipatool"
        "libimobiledevice"
        "ideviceinstaller"
    )

    for pkg in "${BREW_PACKAGES[@]}"; do
        echo -n "  $pkg: "
        if brew list "$pkg" &>/dev/null; then
            print_success "already installed"
        else
            install_cmd "brew install $pkg"
            INSTALLED_TOOLS+=("$pkg")
            print_success "installed"
        fi
    done

    echo ""
    echo "Installing Python packages..."
    PYTHON_PACKAGES=(
        "frida-tools"
        "objection"
        "dsdump"
        "swift-demangle"
    )

    # Check if pip needs --break-system-packages (Python 3.14+)
    PIP_INSTALL="pip3 install"
    PIP_VERSION=$(python3 --version 2>/dev/null | awk '{print $2}' | cut -d. -f1-2)
    if [[ "$(echo "$PIP_VERSION >= 3.14" | bc -l 2>/dev/null || echo "0")" == "1" ]]; then
        PIP_INSTALL="pip3 install --break-system-packages"
    fi

    for pkg in "${PYTHON_PACKAGES[@]}"; do
        echo -n "  $pkg: "
        if pip3 show "$pkg" &>/dev/null; then
            print_success "already installed"
        else
            install_cmd "$PIP_INSTALL $pkg"
            INSTALLED_TOOLS+=("$pkg")
            print_success "installed"
        fi
    done

    echo ""
    echo "Installing optional tools..."
    echo "  class-dump (ObjC class dump):"
    if brew list class-dump &>/dev/null; then
        print_success "already installed"
    else
        echo "    To install manually: brew install class-dump"
    fi

    echo "  jtool2 (enhanced Mach-O analysis):"
    if command -v jtool2 &>/dev/null; then
        print_success "already installed"
    else
        echo "    To install manually, see tool-installation-ios.md"
    fi

# Linux setup
elif [[ "$OS" == "linux" ]]; then
    print_header "Linux Setup ($DISTRO)"

    case "$DISTRO" in
        debian|ubuntu)
            echo "Updating package list..."
            install_cmd "sudo apt update"

            echo ""
            echo "Installing system packages..."
            APT_PACKAGES=(
                "python3"
                "python3-pip"
                "python3-dev"
                "clang"
                "git"
                "wget"
                "curl"
                "jq"
                "tree"
                "ripgrep"
                "build-essential"
                "pkg-config"
                "libssl-dev"
                "libusb-1.0-0-dev"
                "libimobiledevice-utils"
                "ideviceinstaller"
            )

            for pkg in "${APT_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if dpkg -l "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "sudo apt install -y $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done

            echo ""
            echo "Installing Python packages..."
            PYTHON_PACKAGES=(
                "frida-tools"
                "objection"
                "dsdump"
                "swift-demangle"
            )

            for pkg in "${PYTHON_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if pip3 show "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "pip3 install $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done
            ;;

        arch|manjaro)
            echo "Installing system packages..."
            PACMAN_PACKAGES=(
                "python"
                "python-pip"
                "git"
                "wget"
                "curl"
                "jq"
                "tree"
                "ripgrep"
                "base-devel"
                "clang"
                "libusb"
                "libimobiledevice"
                "ideviceinstaller"
            )

            for pkg in "${PACMAN_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if pacman -Qi "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "sudo pacman -S --noconfirm $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done

            echo ""
            echo "Installing Python packages..."
            PYTHON_PACKAGES=(
                "frida-tools"
                "objection"
                "dsdump"
                "swift-demangle"
            )

            for pkg in "${PYTHON_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if pip3 show "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "pip3 install $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done
            ;;

        fedora|rhel)
            echo "Installing system packages..."
            DNF_PACKAGES=(
                "python3"
                "python3-pip"
                "python3-devel"
                "git"
                "wget"
                "curl"
                "jq"
                "tree"
                "ripgrep"
                "gcc"
                "clang"
                "libusb-devel"
                "libimobiledevice"
                "ideviceinstaller"
            )

            for pkg in "${DNF_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if rpm -q "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "sudo dnf install -y $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done

            echo ""
            echo "Installing Python packages..."
            PYTHON_PACKAGES=(
                "frida-tools"
                "objection"
                "dsdump"
                "swift-demangle"
            )

            for pkg in "${PYTHON_PACKAGES[@]}"; do
                echo -n "  $pkg: "
                if pip3 show "$pkg" &>/dev/null; then
                    print_success "already installed"
                else
                    install_cmd "pip3 install $pkg"
                    INSTALLED_TOOLS+=("$pkg")
                    print_success "installed"
                fi
            done
            ;;

        *)
            print_error "Unsupported distribution: $DISTRO"
            echo "Please refer to tool-installation-ios.md for manual setup"
            exit 1
            ;;
    esac

else
    print_error "Unsupported operating system: $OS"
    echo "iOS pentesting requires macOS or Linux"
    exit 1
fi

# Print Linux functionality warnings
print_functionality_warning() {
    if [[ "$OS" == "linux" ]]; then
        echo ""
        echo "${YELLOW}${BOLD}========================================${RESET}"
        echo "${YELLOW}${BOLD}  Linux Functionality Notes${RESET}"
        echo "${YELLOW}${BOLD}========================================${RESET}"
        echo ""
        echo "${BOLD}Some macOS-only tools have Linux alternatives:${RESET}"
        echo ""
        echo "  ${BOLD}macOS Tool${RESET} → ${GREEN}Linux Alternative${RESET}"
        echo "  ─────────────────────────────────────────────────────"
        echo "  plutil        → ${GREEN}plistutil${RESET}        (sudo apt install libplist-utils)"
        echo "  otool         → ${GREEN}llvm-objdump${RESET}      (sudo apt install llvm)"
        echo "  lipo          → ${GREEN}llvm-lipo${RESET}         (sudo apt install llvm)"
        echo "  codesign      → ${GREEN}ldid${RESET}              (sudo apt install ldid)"
        echo "  class-dump     → ${GREEN}Frida runtime${RESET}     (no direct equivalent)"
        echo "  jtool2        → ${GREEN}llvm-objdump${RESET}      (subset of features)"
        echo ""
        echo "${BOLD}Limitations:${RESET}"
        echo "  • ${YELLOW}codesign/ldid${RESET} works only for jailbroken devices"
        echo "  • ${YELLOW}security${RESET} keychain operations differ on Linux"
        echo "  • ${YELLOW}iOS Simulator${RESET} is not available on Linux"
        echo "  • Use Corellium or physical jailbroken devices for full dynamic analysis"
        echo ""
        echo "${BOLD}For detailed Linux workarounds:${RESET}"
        echo "  See ${GREEN}references/linux-ios-analysis-workarounds.md${RESET}"
        echo ""
    fi
}

# Final summary
print_header "Installation Summary"

echo "${BOLD}Tools installed/upgraded:${RESET}"
if [[ ${#INSTALLED_TOOLS[@]} -eq 0 ]]; then
    echo "  (none - all tools were already present)"
else
    for tool in "${INSTALLED_TOOLS[@]}"; do
        echo "  ✅ $tool"
    done
fi

echo ""
echo "${BOLD}Next steps:${RESET}"
echo "  1. Run preflight check to verify installation:"
echo "     ${GREEN}./scripts/preflight-check.sh${RESET}"
echo ""
echo "  2. Test Frida connection (if you have a device):"
echo "     ${GREEN}frida-ps -U${RESET}"
echo ""
echo "  3. Start auditing IPAs:"
echo "     See ${GREEN}references/getting-started-ios.md${RESET}"
echo ""

# Show Linux functionality warnings
print_functionality_warning

if [[ "$DRY_RUN" == true ]]; then
    print_warning "This was a DRY RUN. Re-run without --dry-run to actually install."
fi

exit 0
