@echo off
REM RuFreedom - консольный режим (CLI) с автоповышением прав.

cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Требуются права администратора. Запрашиваю повышение...
    powershell -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
    exit /b
)

set "PYEXE="
for %%P in ("py -3" "python" "python3") do (
    if not defined PYEXE (
        %%~P -c "import sys" >nul 2>&1 && set "PYEXE=%%~P"
    )
)
if not defined PYEXE (
    if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
        set "PYEXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
    )
)
if not defined PYEXE (
    echo [!] Рабочий Python не найден. Установите Python 3 с python.org
    pause
    exit /b 1
)

%PYEXE% -c "import pydivert" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Устанавливаю зависимости...
    %PYEXE% -m pip install -r "%~dp0requirements.txt"
)

echo.
%PYEXE% "%~dp0rufreedom.py" %*

echo.
pause
