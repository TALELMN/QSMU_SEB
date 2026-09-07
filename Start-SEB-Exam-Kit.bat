@echo off
REM Launcher for teachers: double-click this file.
REM Keeps the console open on failure so the error is readable rather than
REM flashing past - the usual reason a teacher gives up on a tool like this.

cd /d "%~dp0"
title MedTech SEB Exam Kit

where python >nul 2>&1
if errorlevel 1 (
    echo.
    echo   Python was not found on this computer.
    echo.
    echo   Install it from https://www.python.org/downloads/
    echo   and tick "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)

python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    echo Installing a required component, one moment...
    python -m pip install --quiet cryptography
    if errorlevel 1 (
        echo.
        echo   Could not install the 'cryptography' component.
        echo   Try running this from a terminal:  python -m pip install cryptography
        echo.
        pause
        exit /b 1
    )
)

python -m sebkit ui
if errorlevel 1 pause
