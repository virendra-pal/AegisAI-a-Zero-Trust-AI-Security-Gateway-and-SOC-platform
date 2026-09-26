@echo off
title AegisAI - Zero-Trust AI Security Gateway
echo =====================================================================
echo  [AegisAI] Zero-Trust AI Security Gateway and SOC Defense Platform
echo  Securing Systems That Learn and Autonomous Agents
echo =====================================================================
echo.
echo Launching AegisAI Server...
py server.py
if %ERRORLEVEL% NEQ 0 (
    echo [!] 'py' launcher not found. Trying 'python'...
    python server.py
)
pause
