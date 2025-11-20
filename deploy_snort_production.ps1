# Deploy Production Snort Configuration
# This script copies the production configuration and rules to Snort directory

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Snort Production Configuration Deployment" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Please right-click and select 'Run as Administrator'" -ForegroundColor Yellow
    pause
    exit 1
}

# Define paths
$projectRoot = $PSScriptRoot
$snortConfigDir = "C:\Snort\etc"
$snortRulesDir = "C:\Snort\rules"

# Check if Snort is installed
if (-not (Test-Path "C:\Snort")) {
    Write-Host "ERROR: Snort installation not found at C:\Snort" -ForegroundColor Red
    Write-Host "Please install Snort first!" -ForegroundColor Yellow
    pause
    exit 1
}

# Create directories if they don't exist
if (-not (Test-Path $snortConfigDir)) {
    New-Item -ItemType Directory -Path $snortConfigDir -Force | Out-Null
    Write-Host "[+] Created config directory: $snortConfigDir" -ForegroundColor Green
}

if (-not (Test-Path $snortRulesDir)) {
    New-Item -ItemType Directory -Path $snortRulesDir -Force | Out-Null
    Write-Host "[+] Created rules directory: $snortRulesDir" -ForegroundColor Green
}

Write-Host ""
Write-Host "Deploying production configuration..." -ForegroundColor Yellow

# Copy production configuration
try {
    Copy-Item "$projectRoot\snort_production.conf" -Destination "$snortConfigDir\snort_production.conf" -Force
    Write-Host "[+] Copied snort_production.conf" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to copy snort_production.conf: $_" -ForegroundColor Red
}

# Copy production rules
try {
    Copy-Item "$projectRoot\production-threats.rules" -Destination "$snortRulesDir\production-threats.rules" -Force
    Write-Host "[+] Copied production-threats.rules" -ForegroundColor Green
} catch {
    Write-Host "[!] Failed to copy production-threats.rules: $_" -ForegroundColor Red
}

# Backup existing configuration if it exists
if (Test-Path "$snortConfigDir\snort.conf") {
    $backupName = "snort.conf.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item "$snortConfigDir\snort.conf" -Destination "$snortConfigDir\$backupName" -Force
    Write-Host "[+] Backed up existing snort.conf to $backupName" -ForegroundColor Green
}

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Configuration Files Deployed" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration file:" -ForegroundColor White
Write-Host "  $snortConfigDir\snort_production.conf" -ForegroundColor Gray
Write-Host ""
Write-Host "Rules file:" -ForegroundColor White
Write-Host "  $snortRulesDir\production-threats.rules" -ForegroundColor Gray
Write-Host ""
Write-Host "What's Changed:" -ForegroundColor Yellow
Write-Host "  [+] Removed noisy test rules (ICMP alerts on all traffic)" -ForegroundColor Green
Write-Host "  [+] Added real threat detection rules:" -ForegroundColor Green
Write-Host "      - Malware detection (Wannacry, Emotet, Cobalt Strike)" -ForegroundColor Gray
Write-Host "      - SQL Injection attacks" -ForegroundColor Gray
Write-Host "      - Remote Code Execution attempts" -ForegroundColor Gray
Write-Host "      - Brute force attacks (SSH, RDP)" -ForegroundColor Gray
Write-Host "      - Web shells and backdoors" -ForegroundColor Gray
Write-Host "      - Data exfiltration patterns" -ForegroundColor Gray
Write-Host "      - DoS attacks" -ForegroundColor Gray
Write-Host "      - Refined port scan detection (less noise)" -ForegroundColor Gray
Write-Host ""
Write-Host "  [+] Adjusted thresholds to reduce false positives" -ForegroundColor Green
Write-Host "  [+] Network scans now require 50+ ports in 60 seconds" -ForegroundColor Green
Write-Host "  [+] Focus on actual attack patterns, not normal traffic" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Update your HOME_NET in snort_production.conf" -ForegroundColor White
Write-Host "     (Currently set to 'any' - should be your network range)" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Restart your Snort backend to use new configuration:" -ForegroundColor White
Write-Host "     python snort_backend.py" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Test with real attack patterns, not normal browsing" -ForegroundColor White
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
