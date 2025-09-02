@echo off
echo Starting Snort Backend as Administrator...
echo.
echo IMPORTANT: This window must remain open for the Snort backend to work
echo.
echo The backend will be available at: http://127.0.0.1:5001
echo.
cd /d "C:\Users\panna\Documents\GitHub\Secbot"
python snort_backend.py
echo.
echo Snort backend has stopped. Press any key to close...
pause
