<#
.SYNOPSIS
    Preflight check wrapper script for ios-app-security-audit skill on Windows

.DESCRIPTION
    Wrapper for Python preflight check tool. If Python is not available,
    performs a minimal check and recommends installing Python 3.

.NOTES
    File:      preflight-check.ps1
    Author:    ios-app-security-audit skill
    Version:   1.0.0
    Requires:  Windows PowerShell 5.1 or later
#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string[]]$Args
)

# Set error action preference
$ErrorActionPreference = 'Stop'

# Color constants
$ColorFound = 'Green'
$ColorMissing = 'Red'
$ColorOptional = 'Yellow'
$ColorInfo = 'Cyan'

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check if python is available
$PythonCmd = $null
foreach $cmd in @('python', 'python3', 'py') {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $PythonCmd = $cmd
        break
    }
}

if ($PythonCmd) {
    # Delegate to Python core script
    $pythonScript = Join-Path $ScriptDir "preflight_check.py"
    & $PythonCmd $pythonScript @Args
    exit $LASTEXITCODE
}

# Fallback: Python not available
Write-Host ""
Write-Host "========================================" -ForegroundColor $ColorInfo
Write-Host "  iOS App Security Audit - Preflight Check" -ForegroundColor $ColorInfo
Write-Host "========================================" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "WARNING: Python 3 not found" -ForegroundColor $ColorOptional
Write-Host "  For full preflight check functionality, install Python 3:" -ForegroundColor $ColorOptional
Write-Host "  choco install python" -ForegroundColor $ColorInfo
Write-Host "  scoop install python" -ForegroundColor $ColorInfo
Write-Host ""
Write-Host "Performing minimal tool check..." -ForegroundColor $ColorInfo
Write-Host ""

# Minimal check
$missing = 0

function Check-Minimal {
    param(
        [string]$Tool,
        [bool]$Critical
    )

    if (Get-Command $Tool -ErrorAction SilentlyContinue) {
        Write-Host "✅ $Tool found" -ForegroundColor $ColorFound
    } else {
        Write-Host "❌ $Tool missing" -ForegroundColor $ColorMissing
        if ($Critical) {
            $script:missing++
        }
    }
}

Write-Host "Basic Tools:"
Check-Minimal "grep" $true
Check-Minimal "frida" $true
Check-Minimal "python" $false
Check-Minimal "python3" $false
Write-Host ""

# Same CRITICAL set as the Python core: without it the fallback reported
# "basic tools available" while the core failed on the same machine.
Write-Host "Device Toolchain (libimobiledevice):"
Check-Minimal "ideviceinfo" $true
Check-Minimal "idevicepair" $true
Check-Minimal "ideviceinstaller" $false
Check-Minimal "idevicesyslog" $false
Check-Minimal "afcclient" $false
Write-Host ""

Write-Host "========================================"
if ($missing -eq 0) {
    Write-Host "✅ Basic tools available" -ForegroundColor $ColorFound
    Write-Host "⚠️  Install Python 3 for complete preflight check" -ForegroundColor $ColorOptional
    exit 0
} else {
    Write-Host "❌ Critical tools missing" -ForegroundColor $ColorMissing
    Write-Host "⚠️  Install Python 3 for complete preflight check" -ForegroundColor $ColorOptional
    exit 1
}
