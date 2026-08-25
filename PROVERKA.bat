@echo off
chcp 65001 > nul
title RuFreedom self-test
cd /d "%~dp0"

REM WinDivert driver needs admin rights, so ask for them first.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PYEXE="
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" set "PYEXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not defined PYEXE (py -3 -c "import sys" >nul 2>&1 && set "PYEXE=py -3")
if not defined PYEXE (python -c "import sys" >nul 2>&1 && set "PYEXE=python")
if not defined PYEXE (
    echo Python not found. Install it from python.org
    pause
    exit /b 1
)

%PYEXE% "%~dp0selftest.py"
pause
