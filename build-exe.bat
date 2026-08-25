@echo off
REM Сборка RuFreedom в один файл RuFreedom.exe (PyInstaller).
REM Результат: dist\RuFreedom.exe — самодостаточный, с иконкой и запросом
REM прав администратора (UAC), с вшитым драйвером WinDivert.

cd /d "%~dp0"

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
    echo [!] Рабочий Python не найден.
    pause
    exit /b 1
)
echo [*] Python: %PYEXE%

echo [*] Устанавливаю зависимости и PyInstaller...
%PYEXE% -m pip install -r "%~dp0requirements.txt" pyinstaller

echo [*] Сборка...
REM Всё описано в RuFreedom.spec (файлы web/assets/config, webview, WinDivert,
REM запрос прав администратора) — держим настройки сборки в одном месте.
%PYEXE% -m PyInstaller --noconfirm --clean RuFreedom.spec

echo.
if exist "dist\RuFreedom.exe" (
    echo [OK] Готово: dist\RuFreedom.exe
) else (
    echo [!] Сборка не удалась — см. вывод выше.
)
pause
