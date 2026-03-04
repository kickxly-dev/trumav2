@echo off
title TRAUMA Security Toolkit
color 0A
cls

echo.
echo  Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [ERROR] Python is not installed or not in PATH
    echo  Please install Python 3.x from https://python.org
    echo.
    pause
    exit /b
)

echo  Python found!
echo.
echo  Checking dependencies...
pip show rich >nul 2>&1
if errorlevel 1 (
    echo  Installing dependencies...
    pip install -r requirements.txt
)

echo.
echo  Launching TRAUMA Security Toolkit...
echo.
python trauma.py

pause
