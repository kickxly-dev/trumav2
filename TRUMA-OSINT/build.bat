@echo off
title TRAUMA OSINT - Build EXE
color 0a
echo.
echo  ============================================
echo   TRAUMA OSINT - Building Windows EXE
echo  ============================================
echo.

REM Check if node_modules exists
if not exist "node_modules" (
    echo  Installing dependencies...
    call npm install
    echo.
)

REM Create dist directory
if not exist "dist" mkdir dist

echo  Building EXE with pkg...
echo.

REM Build the EXE
call npx pkg . --targets node18-win-x64 --output dist/TRAUMA-OSINT.exe

if %ERRORLEVEL% EQU 0 (
    echo.
    echo  Copying supporting files...
    
    REM Copy required JS files
    copy license.js dist\ >nul 2>&1
    copy api-config.js dist\ >nul 2>&1
    copy report-template.js dist\ >nul 2>&1
    
    REM Create data directories
    if not exist "dist\licenses" mkdir dist\licenses
    if not exist "dist\results" mkdir dist\results
    if not exist "dist\reports" mkdir dist\reports
    if not exist "dist\cache" mkdir dist\cache
    
    echo.
    echo  ============================================
    echo   BUILD SUCCESSFUL!
    echo  ============================================
    echo.
    echo   Output: dist\TRAUMA-OSINT.exe
    echo.
    echo   To distribute, zip the entire dist\ folder
    echo.
) else (
    echo.
    echo  ============================================
    echo   BUILD FAILED!
    echo  ============================================
    echo.
    echo   Error code: %ERRORLEVEL%
    echo.
)

pause
