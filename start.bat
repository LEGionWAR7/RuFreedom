@echo off
REM RuFreedom 0.0.1 - запуск GUI без консоли (она закроется сразу после старта).
REM WinDivert требует прав администратора для перехвата пакетов.

cd /d "%~dp0"

REM Повышение прав до администратора
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM --- поиск РАБОЧЕГО Python (с консолью, для установки зависимостей) ---
REM ВНИМАНИЕ: 'python' в PATH часто указывает на заглушку Microsoft Store,
REM которая ничего не запускает, поэтому проверяем несколько кандидатов.
set "PYEXE="
for %%P in ("py -3" "python" "python3") do (
    if not defined PYEXE (
        %%~P -c "import sys" >nul 2>&1 && set "PYEXE=%%~P"
    )
)
if not defined PYEXE if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" set "PYEXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not defined PYEXE (
    echo [!] Рабочий Python не найден. Установите Python 3 с python.org
    echo     и включите "Add python.exe to PATH".
    pause
    exit /b 1
)

REM --- оконный Python (pythonw) для запуска БЕЗ консоли ---
set "PYWEXE="
for %%P in ("pyw -3" "pythonw") do (
    if not defined PYWEXE (
        %%~P -c "import sys" >nul 2>&1 && set "PYWEXE=%%~P"
    )
)
if not defined PYWEXE if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\pythonw.exe" set "PYWEXE=%LOCALAPPDATA%\Python\pythoncore-3.14-64\pythonw.exe"
if not defined PYWEXE set "PYWEXE=%PYEXE%"

REM --- установка зависимостей при первом запуске (видимая консоль) ---
%PYEXE% -c "import pydivert, webview, pystray, PIL" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Устанавливаю зависимости ^(WinDivert, окно, трей^)...
    %PYEXE% -m pip install -r "%~dp0requirements.txt"
)

REM --- запуск окна без консоли и немедленное закрытие этого окна ---
start "" %PYWEXE% "%~dp0app.py" %*
exit /b
