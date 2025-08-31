@echo off
cd /d "C:\Program Files\Suricata"
echo Checking WinPcap/Npcap installation...
if not exist "%SystemRoot%\System32\Npcap" (
    if not exist "%SystemRoot%\System32\WinPcap" (
        echo ERROR: Neither WinPcap nor Npcap found. Please install one of them.
        pause
        exit /b 1
    )
)
echo Starting Suricata in console mode...
echo Press Ctrl+C to stop monitoring
"C:\Program Files\Suricata\suricata.exe" -c "C:\Users\panna\Documents\GitHub\Secbot\suricata\suricata.yaml" --pcap-buffer-size=262144 --runmode=workers --pcap=Wi-Fi -l "C:\Users\panna\Documents\GitHub\Secbot\suricata\logs" -v
set EXIT_CODE=%ERRORLEVEL%
if %EXIT_CODE% NEQ 0 (
    echo.
    echo Suricata exited with error code %EXIT_CODE%
    if %EXIT_CODE%==-1073741819 (
        echo This error (0xC0000005) might be caused by interface or permissions issues.
        echo Try running as administrator or checking WinPcap/Npcap installation.
    )
    pause
) else (
    echo.
    echo Suricata stopped normally. Press any key to close window...
    pause > nul
)
