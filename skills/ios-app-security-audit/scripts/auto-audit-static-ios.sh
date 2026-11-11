#!/usr/bin/env bash

################################################################################
# ios-app-security-audit: Automated Static Analysis Script
# Description: Automates Phase 0-3 of iOS app security audit workflow
# Author: ios-app-security-audit skill
# Version: 1.0.0
# Usage: ./auto-audit-static-ios.sh <ipa-file> [output-dir] [--quick|--full]
################################################################################

set -euo pipefail  # Exit on error, undefined variables, pipe failures

################################################################################
# Cross-platform realpath
################################################################################

_realpath() {
    if command -v realpath &>/dev/null; then
        realpath "$1"
    elif command -v python3 &>/dev/null; then
        python3 -c "import os, sys; print(os.path.realpath(sys.argv[1]))" -- "$1"
    elif command -v greadlink &>/dev/null; then
        greadlink -f "$1"
    else
        echo "$1"  # best effort fallback
    fi
}

################################################################################
# Color codes for terminal output
################################################################################

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
fi

################################################################################
# Utility functions
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*" >&2
}

log_section() {
    echo -e "\n${CYAN}${BOLD}=== $* ===${NC}\n"
}

show_help() {
    cat << EOF
${BOLD}ios-app-security-audit: Automated Static Analysis Script${NC}

${BOLD}USAGE:${NC}
    $0 <ipa-file> [output-dir] [--quick|--full] [--help|-h]

${BOLD}ARGUMENTS:${NC}
    ipa-file        Path to IPA file to analyze (required)
    output-dir      Directory for analysis results (optional)
                    Default: ./audit-<bundle-id>-<timestamp>/

${BOLD}OPTIONS:${NC}
    --quick         Quick mode: manifest + critical grep (~2 min)
    --full          Full mode: complete static analysis (~10 min) [default]
    --help, -h      Show this help message

${BOLD}EXAMPLES:${NC}
    $0 app.ipa
    $0 app.ipa ./my-audit
    $0 app.ipa --quick
    $0 app.ipa ./results --full

${BOLD}REQUIREMENTS:${NC}
    - plutil (macOS system tool)
    - otool (macOS system tool, requires Xcode CLI)
    - lipo (macOS system tool)
    - codesign (macOS system tool)
    - unzip (system tool)
    - ripgrep (optional but recommended, https://github.com/BurntSushi/ripgrep)

${BOLD}OUTPUT STRUCTURE:${NC}
    output-dir/
    ├── extracted/         # Unzipped IPA
    ├── Payload/*.app/    # App bundle
    ├── 00-extract-info.txt   # Phase 0 results
    ├── 01-info-plist.txt     # Phase 1 results
    ├── 02-triage.txt         # Phase 2 grep results
    ├── 03-findings-raw.txt   # All findings combined
    └── AUDIT-SUMMARY.md     # Summary report (ready for agent)

EOF
    exit 0
}

################################################################################
# OS Detection and Tool Availability
################################################################################

detect_os() {
    case "$(uname -s)" in
        Darwin)
            OS="macos"
            ;;
        Linux)
            OS="linux"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            OS="windows"
            ;;
        *)
            OS="unknown"
            ;;
    esac
    log_info "Detected OS: ${OS}"
}

check_command() {
    local cmd=$1
    if command -v "$cmd" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

check_grep_type() {
    if check_command "rg"; then
        GREP_CMD="rg"
        GREP_FLAGS="-n"
        log_info "Using ripgrep (fast)"
        return 0
    elif grep --version 2>/dev/null | grep -q "GNU"; then
        GREP_CMD="grep"
        GREP_FLAGS="-rnE"
        log_info "Using GNU grep"
        return 0
    else
        GREP_CMD="grep"
        GREP_FLAGS="-rnE"
        log_info "Using BSD grep (macOS)"
        return 0
    fi
}

check_requirements() {
    local missing=()
    local optional=()

    if ! check_command "plutil"; then
        missing+=("plutil")
    fi

    if ! check_command "otool"; then
        missing+=("otool")
    fi

    if ! check_command "lipo"; then
        missing+=("lipo")
    fi

    if ! check_command "unzip"; then
        missing+=("unzip")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Please install them first"
        exit 1
    fi

    if [ ${#optional[@]} -gt 0 ]; then
        log_warning "Optional tools not installed: ${optional[*]}"
        log_warning "Continuing without them..."
    fi
}

################################################################################
# Argument Parsing
################################################################################

parse_arguments() {
    IPA_FILE=""
    OUTPUT_DIR=""
    MODE="full"  # quick | full

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                ;;
            --quick)
                MODE="quick"
                shift
                ;;
            --full)
                MODE="full"
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                show_help
                ;;
            *)
                if [ -z "$IPA_FILE" ]; then
                    IPA_FILE="$1"
                elif [ -z "$OUTPUT_DIR" ]; then
                    OUTPUT_DIR="$1"
                else
                    log_error "Too many arguments"
                    show_help
                fi
                shift
                ;;
        esac
    done

    if [ -z "$IPA_FILE" ]; then
        log_error "IPA file is required"
        show_help
    fi

    if [ ! -f "$IPA_FILE" ]; then
        log_error "IPA file not found: $IPA_FILE"
        exit 1
    fi

    IPA_FILE=$(_realpath "$IPA_FILE")
    IPA_BASENAME=$(basename "$IPA_FILE")

    log_info "IPA File: $IPA_FILE"
    log_info "Mode: $MODE"
}

################################################################################
# Setup Output Directory
################################################################################

setup_output_dir() {
    timestamp=$(date +"%Y%m%d-%H%M%S")

    if [ -z "$OUTPUT_DIR" ]; then
        # Extract bundle name for directory name (will update after extraction)
        OUTPUT_DIR="./audit-${timestamp}"
    fi

    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_DIR=$(_realpath "$OUTPUT_DIR")

    # Create subdirectories
    mkdir -p "$OUTPUT_DIR/extracted"

    log_success "Output directory: $OUTPUT_DIR"
}

################################################################################
# Phase 0: Extract IPA & App Bundle Detection
################################################################################

phase0_extract() {
    log_section "Phase 0: Extract IPA & App Bundle Detection"

    local extract_file="$OUTPUT_DIR/00-extract-info.txt"

    {
        echo "=============================================="
        echo "PHASE 0: IPA EXTRACTION & APP BUNDLE DETECTION"
        echo "=============================================="
        echo ""
        echo "Timestamp: $(date)"
        echo "IPA File: $IPA_FILE"
        echo "IPA Size: $(du -h "$IPA_FILE" | awk '{print $1}')"
        echo ""
    } > "$extract_file"

    # Extract IPA
    log_info "Extracting IPA file..."
    if unzip -q "$IPA_FILE" -d "$OUTPUT_DIR/extracted" > "$OUTPUT_DIR/unzip.log" 2>&1; then
        log_success "IPA extracted successfully"
        echo "unzip: SUCCESS" >> "$extract_file"
    else
        log_error "unzip failed"
        echo "unzip: FAILED - see $OUTPUT_DIR/unzip.log" >> "$extract_file"
        return 1
    fi

    # Find app bundle
    APP_BUNDLE=$(find "$OUTPUT_DIR/extracted/Payload" -name "*.app" -type d | head -1)

    if [ -z "$APP_BUNDLE" ]; then
        log_error "No .app bundle found in Payload directory"
        echo "app_bundle: FAILED - No .app found" >> "$extract_file"
        return 1
    fi

    log_success "App bundle found: $APP_BUNDLE"
    echo "app_bundle: $APP_BUNDLE" >> "$extract_file"

    # Find executable binary
    BINARY_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP_BUNDLE/Info.plist" 2>/dev/null || echo "unknown")
    BINARY_PATH="$APP_BUNDLE/$BINARY_NAME"

    if [ ! -f "$BINARY_PATH" ]; then
        log_warning "Binary not found at expected path, searching the bundle..."
        BINARY_PATH=$(find "$APP_BUNDLE" -type f -executable -not -path "*/Frameworks/*" -not -path "*/PlugIns/*" | head -1)
    fi

    if [ -z "$BINARY_PATH" ]; then
        log_error "No executable binary found inside $APP_BUNDLE"
        return 1
    fi

    log_success "Binary found: $BINARY_PATH"
    echo "binary: $BINARY_PATH" >> "$extract_file"

    # Get bundle ID
    BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP_BUNDLE/Info.plist" 2>/dev/null || echo "unknown")

    if [ "$BUNDLE_ID" = "unknown" ]; then
        BUNDLE_ID=$(plutil -p "$APP_BUNDLE/Info.plist" 2>/dev/null | grep "CFBundleIdentifier" | awk -F'"' '{print $2}' || echo "unknown")
    fi

    log_success "Bundle ID: $BUNDLE_ID"
    echo "bundle_id: $BUNDLE_ID" >> "$extract_file"

    # Get architecture info with lipo
    log_info "Checking binary architecture..."
    local arch_info
    arch_info=$(lipo -info "$BINARY_PATH" 2>/dev/null || echo "unknown")
    echo "architecture: $arch_info" >> "$extract_file"
    echo "" >> "$extract_file"
    echo "--- Architecture Info ---" >> "$extract_file"
    echo "$arch_info" >> "$extract_file"

    # Get binary size
    local binary_size
    binary_size=$(du -h "$BINARY_PATH" 2>/dev/null | awk '{print $1}' || echo "unknown")
    echo "binary_size: $binary_size" >> "$extract_file"

    # Framework detection
    log_info "Detecting frameworks..."
    local frameworks=()

    # Check for React Native
    if [ -f "$APP_BUNDLE/main.jsbundle" ] || \
       [ -f "$APP_BUNDLE/index.jsbundle" ] || \
       strings "$BINARY_PATH" 2>/dev/null | grep -q "ReactNative"; then
        frameworks+=("React Native")
    fi

    # Check for Flutter
    if strings "$BINARY_PATH" 2>/dev/null | grep -q "FlutterEngine" || \
       [ -f "$APP_BUNDLE/Frameworks/Flutter.framework" ]; then
        frameworks+=("Flutter")
    fi

    # Check for Cordova/Capacitor
    if [ -f "$APP_BUNDLE/www/cordova.js" ] || \
       [ -f "$APP_BUNDLE/public/cordova.js" ] || \
       strings "$BINARY_PATH" 2>/dev/null | grep -q "cordova"; then
        frameworks+=("Cordova/Capacitor")
    fi

    # Check for Xamarin
    if strings "$BINARY_PATH" 2>/dev/null | grep -q "Xamarin" || \
       [ -d "$APP_BUNDLE/Mono" ]; then
        frameworks+=("Xamarin")
    fi

    # Check for Unity
    if strings "$BINARY_PATH" 2>/dev/null | grep -q "Unity" || \
       [ -d "$APP_BUNDLE/Data" ]; then
        frameworks+=("Unity")
    fi

    # Check for Swift
    if strings "$BINARY_PATH" 2>/dev/null | grep -q "_swift_allocating"; then
        frameworks+=("Swift (Native)")
    fi

    if [ ${#frameworks[@]} -eq 0 ]; then
        frameworks+=("Unknown/Native")
    fi

    echo "" >> "$extract_file"
    echo "--- Detected Frameworks ---" >> "$extract_file"
    for fw in "${frameworks[@]}"; do
        echo "- $fw" >> "$extract_file"
    done

    log_success "Detected frameworks: ${frameworks[*]}"

    # Rename output dir if still using default
    if [[ "$OUTPUT_DIR" == *"audit-"* ]]; then
        local new_dir="./audit-${BUNDLE_ID}-${timestamp}"
        mv "$OUTPUT_DIR" "$new_dir"
        OUTPUT_DIR="$new_dir"
        log_success "Updated output directory: $OUTPUT_DIR"
    fi

    echo "" >> "$extract_file"
    echo "Output Directory: $OUTPUT_DIR" >> "$extract_file"
}

################################################################################
# Phase 1: Info.plist Analysis
################################################################################

phase1_info_plist() {
    log_section "Phase 1: Info.plist Analysis"

    local info_plist="$APP_BUNDLE/Info.plist"
    local output="$OUTPUT_DIR/01-info-plist.txt"

    {
        echo "=============================================="
        echo "PHASE 1: INFO.PLIST ANALYSIS"
        echo "=============================================="
        echo ""
        echo "Timestamp: $(date)"
        echo "Info.plist: $info_plist"
        echo ""
    } > "$output"

    # Full Info.plist dump
    log_info "Dumping Info.plist..."
    {
        echo "--- Full Info.plist Content ---"
        plutil -p "$info_plist" 2>/dev/null || echo "Failed to read Info.plist"
        echo ""
    } >> "$output"

    # Extract URL schemes
    log_info "Analyzing URL schemes..."
    {
        echo "--- URL Schemes ---"
        /usr/libexec/PlistBuddy -c "Print :CFBundleURLTypes" "$info_plist" 2>/dev/null || echo "No URL schemes defined"
        echo ""
    } >> "$output"

    # Extract exported URL schemes
    {
        echo "--- Exported URL Schemes ---"
        plutil -p "$info_plist" 2>/dev/null | grep -A 2 "CFBundleURLSchemes" | grep -E '".*"' | tr -d ' ",:' | sort -u || echo "None"
        echo ""
    } >> "$output"

    # Check NSAppTransportSecurity
    log_info "Checking App Transport Security..."
    {
        echo "--- App Transport Security ---"
        if plutil -p "$info_plist" 2>/dev/null | grep -q "NSAllowsArbitraryLoads.*true"; then
            echo "⚠️  NSAllowsArbitraryLoads: true [HIGH RISK]"
        else
            echo "✓ NSAllowsArbitraryLoads: false"
        fi

        if plutil -p "$info_plist" 2>/dev/null | grep -q "NSAllowsArbitraryLoadsInWebContent.*true"; then
            echo "⚠️  NSAllowsArbitraryLoadsInWebContent: true [HIGH RISK]"
        else
            echo "✓ NSAllowsArbitraryLoadsInWebContent: false"
        fi
        echo ""
    } >> "$output"

    # Check background modes
    log_info "Checking background modes..."
    {
        echo "--- Background Modes ---"
        /usr/libexec/PlistBuddy -c "Print :UIBackgroundModes" "$info_plist" 2>/dev/null || echo "No background modes"
        echo ""
    } >> "$output"

    # Check privacy descriptions
    log_info "Checking privacy descriptions..."
    {
        echo "--- Privacy Descriptions ---"
        plutil -p "$info_plist" 2>/dev/null | grep -E "NS.*UsageDescription" | head -20 || echo "No privacy descriptions found"
        echo ""
    } >> "$output"

    # Get entitlements
    log_info "Extracting entitlements..."
    {
        echo "--- Entitlements ---"
        codesign -d --entitlements - "$BINARY_PATH" 2>/dev/null || echo "No entitlements found"
        echo ""
    } >> "$output"

    # Check app extensions
    log_info "Checking app extensions..."
    local extensions=()
    if [ -d "$APP_BUNDLE/PlugIns" ]; then
        while IFS= read -r -d '' ext; do
            ext_name=$(basename "$ext")
            extensions+=("$ext_name")
        done < <(find "$APP_BUNDLE/PlugIns" -name "*.appex" -type d -print0)
    fi

    {
        echo "--- App Extensions ---"
        if [ ${#extensions[@]} -gt 0 ]; then
            for ext in "${extensions[@]}"; do
                echo "- $ext"
            done
        else
            echo "No app extensions found"
        fi
        echo ""
    } >> "$output"

    log_success "Info.plist analysis completed"
}

################################################################################
# Phase 2: Targeted Triage (Grep Patterns)
################################################################################

phase2_triage() {
    log_section "Phase 2: Targeted Triage"

    local output="$OUTPUT_DIR/02-triage.txt"
    local scan_dir="$APP_BUNDLE"

    if [ ! -d "$scan_dir" ]; then
        log_warning "App bundle not found, skipping grep patterns"
        return 0
    fi

    {
        echo "=============================================="
        echo "PHASE 2: TARGETED TRIAGE (GREP PATTERNS)"
        echo "=============================================="
        echo ""
        echo "Timestamp: $(date)"
        echo "Scan Directory: $scan_dir"
        echo "Using: $GREP_CMD"
        echo ""
    } > "$output"

    # Define grep patterns
    get_pattern() {
        case "$1" in
            "webview_sinks") echo "loadRequest:|loadHTMLString:|evaluateJavaScript:|stringByEvaluatingJavaScriptFromString:" ;;
            "ipc_sources") echo "openURL:|handleOpenURL:|application:openURL:options:|continueUserActivity" ;;
            "secrets") echo "api_key|secret|token|password|private_key|access_token|auth_token" ;;
            "crypto") echo "kCCAlgorithm|CommonCrypto|CCCrypt|kCCOptionECBMode|kCCOptionPKCS7Padding" ;;
            "storage") echo "NSUserDefaults|SecItemAdd|SecItemCopyMatching|Keychain|kSecAttrAccessible" ;;
            "tls_ats") echo "NSAllowsArbitraryLoads|TLSMinimumVersion|NSExceptionDomains" ;;
            "logging") echo "NSLog|os_log|print\(|NSAssert|NSCAssert" ;;
            "biometric") echo "LAContext|evaluatePolicy:|TouchID|FaceID|kLAPolicyDeviceOwnerAuthentication" ;;
        esac
    }

    get_description() {
        case "$1" in
            "webview_sinks") echo "WebView Sinks (potential XSS)" ;;
            "ipc_sources") echo "IPC Sources (URL scheme handling)" ;;
            "secrets") echo "Hardcoded Secrets (API keys, tokens)" ;;
            "crypto") echo "Cryptographic Issues (weak algorithms)" ;;
            "storage") echo "Storage Patterns (Keychain, UserDefaults)" ;;
            "tls_ats") echo "TLS/ATS Issues (certificate validation)" ;;
            "logging") echo "Logging/Debugging Statements" ;;
            "biometric") echo "Biometric Authentication" ;;
        esac
    }

    log_info "Scanning with grep patterns..."

    for category in webview_sinks ipc_sources secrets crypto storage tls_ats logging biometric; do
        local pattern description
        pattern=$(get_pattern "$category")
        description=$(get_description "$category")

        echo "--- $description ---" >> "$output"

        local result
        if [ "$GREP_CMD" = "rg" ]; then
            # Exclude Frameworks directory for faster scanning
            result=$(cd "$scan_dir" && rg $GREP_FLAGS -g '!Frameworks/**' -g '!PlugIns/**' "$pattern" 2>/dev/null || true)
        else
            # Use grep with exclude directories
            result=$(cd "$scan_dir" && grep $GREP_FLAGS --exclude-dir=Frameworks --exclude-dir=PlugIns "$pattern" 2>/dev/null || true)
        fi

        if [ -n "$result" ]; then
            # Limit output to 50 matches per category
            echo "$result" | head -50 >> "$output"
        else
            echo "No matches found" >> "$output"
        fi

        echo "" >> "$output"
        log_info "Completed: $category"
    done

    log_success "Grep patterns completed"
}

################################################################################
# Phase 3: Generate Summary
################################################################################

phase3_summary() {
    log_section "Phase 3: Generate Summary"

    local summary_file="$OUTPUT_DIR/AUDIT-SUMMARY.md"
    local findings_file="$OUTPUT_DIR/03-findings-raw.txt"

    # Combine all findings
    cat "$OUTPUT_DIR/01-info-plist.txt" > "$findings_file"
    cat "$OUTPUT_DIR/02-triage.txt" >> "$findings_file"

    # Extract app info
    local bundle_id
    bundle_id=$(grep "bundle_id:" "$OUTPUT_DIR/00-extract-info.txt" 2>/dev/null | cut -d: -f2- | xargs)

    local frameworks
    frameworks=$(grep -A 10 "Detected Frameworks:" "$OUTPUT_DIR/00-extract-info.txt" 2>/dev/null | \
                  grep "^- " | cut -d' ' -f2- | tr '\n' ', ' | sed 's/,$//')

    local ipa_size
    ipa_size=$(grep "IPA Size:" "$OUTPUT_DIR/00-extract-info.txt" 2>/dev/null | cut -d: -f2- | xargs)

    # Count URL schemes
    local url_scheme_count
    url_scheme_count=$(plutil -p "$APP_BUNDLE/Info.plist" 2>/dev/null | grep -c "CFBundleURLSchemes" || echo "0")

    # Check ATS bypass
    local ats_bypass
    ats_bypass=$(plutil -p "$APP_BUNDLE/Info.plist" 2>/dev/null | grep -q "NSAllowsArbitraryLoads.*true" && echo "YES" || echo "NO")

    # Count grep findings by category
    local count_webview_sinks=0
    local count_ipc_sources=0
    local count_secrets=0
    local count_crypto=0
    local count_storage=0
    local count_tls_ats=0
    local count_logging=0
    local count_biometric=0

    local triage_file="$OUTPUT_DIR/02-triage.txt"
    if [ -f "$triage_file" ]; then
        count_webview_sinks=$(awk '/^--- WebView/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_ipc_sources=$(awk '/^--- IPC/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_secrets=$(awk '/^--- Hardcoded/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_crypto=$(awk '/^--- Cryptographic/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_storage=$(awk '/^--- Storage/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_tls_ats=$(awk '/^--- TLS\/ATS/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_logging=$(awk '/^--- Logging/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
        count_biometric=$(awk '/^--- Biometric/,/^--- [^-]|^$/ {if (!/No matches found/) count++} END {print count+0}' "$triage_file")
    fi

    # Generate Markdown summary
    # NOTE: ${MODE^} is a bash 4.0+ expansion. macOS ships bash 3.2, where it
    # is a "bad substitution" error that aborts the script under `set -e` and
    # leaves AUDIT-SUMMARY.md empty. Uppercase MODE portably instead.
    case "$MODE" in
        full)  MODE_LABEL="FULL" ;;
        quick) MODE_LABEL="QUICK" ;;
        *)     MODE_LABEL="$MODE" ;;
    esac

    cat > "$summary_file" << EOF
# iOS App Static Analysis Summary

**Generated:** $(date)
**Mode:** $MODE_LABEL
**IPA:** $IPA_BASENAME

---

## App Information

| Property | Value |
|----------|-------|
| **Bundle ID** | ${bundle_id:-Unknown} |
| **IPA Size** | ${ipa_size:-Unknown} |
| **Frameworks** | ${frameworks:-Unknown} |
| **Output Directory** | \`$OUTPUT_DIR\` |

---

## Attack Surface Summary

| Metric | Count |
|--------|-------|
| **URL Schemes** | $url_scheme_count |
| **App Extensions** | $(find "$APP_BUNDLE/PlugIns" -name "*.appex" 2>/dev/null | wc -l | xargs) |
| **Entitlements** | $(codesign -d --entitlements - "$BINARY_PATH" 2>/dev/null | wc -l | xargs || echo "0") |

---

## Security Flags

- **ATS Bypass (NSAllowsArbitraryLoads):** $( [ "$ats_bypass" = "YES" ] && echo "⚠️ **YES - HIGH RISK**" || echo "✅ NO" )
- **App Extensions:** $( [ -d "$APP_BUNDLE/PlugIns" ] && echo "✅ Present" || echo "⚠️ None" )
- **Executable Binary:** $(basename "$BINARY_PATH")

---

## Findings by Category

| Category | Matches | Priority |
|----------|---------|----------|
| WebView Sinks | ${count_webview_sinks} | Medium |
| IPC Sources | ${count_ipc_sources} | High |
| Hardcoded Secrets | ${count_secrets} | **CRITICAL** |
| Crypto Issues | ${count_crypto} | High |
| Storage Patterns | ${count_storage} | Medium |
| TLS/ATS Issues | ${count_tls_ats} | High |
| Logging Statements | ${count_logging} | Low |
| Biometric Usage | ${count_biometric} | Low |

---

## Next Steps

This summary provides a foundation for deeper analysis. Recommended actions:

1. **Review URL Schemes** - Check for hijacking vulnerabilities
2. **Analyze Hardcoded Secrets** - Replace with secure Keychain storage
3. **Audit WebView Usage** - Validate input sanitization
4. **Review Crypto Implementation** - Upgrade weak algorithms
5. **Check Entitlements** - Verify all are necessary
6. **Dynamic Testing** - Use Frida/Objection for runtime analysis

---

## Detailed Reports

For complete findings, review these files:

- \`00-extract-info.txt\` - IPA extraction and app bundle detection
- \`01-info-plist.txt\` - Info.plist analysis
- \`02-triage.txt\` - Grep pattern results
- \`03-findings-raw.txt\` - Combined findings

---

**Analysis completed. Ready for agent consumption.**
EOF

    log_success "Summary generated: $summary_file"
}

################################################################################
# Main Execution
################################################################################

main() {
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║  iOS App Security Audit: Automated Static Analysis Script   ║
║  Phase 0-3 Security Audit Workflow                      ║
╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"

    detect_os
    check_grep_type
    check_requirements

    # macOS requirement warning
    if [[ "$OSTYPE" != "darwin"* ]]; then
        log_warning "iOS analysis requires macOS. Linux/Windows support is limited."
        log_warning "Many tools (otool, codesign, plutil, security) are macOS-only."
    fi

    parse_arguments "$@"
    setup_output_dir

    log_info "Starting analysis in $MODE mode..."
    local start_time
    start_time=$(date +%s)

    phase0_extract
    phase1_info_plist

    if [ "$MODE" = "quick" ]; then
        log_warning "Quick mode: Skipping grep patterns"
    else
        phase2_triage
    fi

    phase3_summary

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    log_section "Analysis Complete"
    log_success "Total time: ${duration}s"
    log_success "Output directory: $OUTPUT_DIR"
    log_success "Summary report: $OUTPUT_DIR/AUDIT-SUMMARY.md"

    echo ""
    echo -e "${GREEN}${BOLD}✓ Static analysis completed successfully!${NC}"
    echo ""
}

# Run main function
main "$@"
