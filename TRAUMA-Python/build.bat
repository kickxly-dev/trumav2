@echo off
title TRAUMA Builder
color 0a
cls

echo.
echo  ========================================
echo   TRAUMA Security Toolkit - Builder
echo  ========================================
echo.
echo  This will compile TRAUMA into a protected
echo  standalone executable that cannot be 
echo  easily viewed or modified.
echo.
echo  Choose build method:
echo.
echo   [1] PyInstaller (Easy, Medium protection)
echo   [2] Nuitka (Harder, High protection)
echo   [3] Install build tools
echo   [4] Exit
echo.

set /p choice="Select option: "

if "%choice%"=="1" goto pyinstaller
if "%choice%"=="2" goto nuitka
if "%choice%"=="3" goto install
if "%choice%"=="4" exit
goto end

:install
echo.
echo Installing build tools...
pip install pyinstaller nuitka ordered-set zstandard
echo.
echo Done! Press any key to return...
pause >nul
goto :start

:pyinstaller
echo.
echo Building with PyInstaller...
echo This creates a standalone .exe file
echo.

REM Create spec file for better control
echo Creating build configuration...

pyinstaller --onefile ^
    --name "TRAUMA" ^
    --console ^
    --icon=NONE ^
    --add-data "requirements.txt;." ^
    --hidden-import=rich ^
    --hidden-import=requests ^
    --hidden-import=colorama ^
    --hidden-import=dns ^
    --hidden-import=dns.resolver ^
    --collect-all rich ^
    --noconfirm ^
    trauma.py

if exist "dist\TRAUMA.exe" (
    echo.
    echo ========================================
    echo  BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo  Executable created: dist\TRAUMA.exe
    echo.
    echo  You can now distribute TRAUMA.exe
    echo  Users don't need Python installed!
    echo.
) else (
    echo.
    echo Build failed. Check errors above.
)

goto end

:nuitka
echo.
echo Building with Nuitka...
echo This compiles Python to C code for better protection.
echo.

python -m nuitka ^
    --standalone ^
    --onefile ^
    --console ^
    --output-filename=TRAUMA.exe ^
    --include-package=rich ^
    --include-package=requests ^
    --include-package=colorama ^
    --include-package=dns ^
    --include-package=dns.resolver ^
    --assume-yes-for-downloads ^
    trauma.py

if exist "TRAUMA.exe" (
    echo.
    echo ========================================
    echo  BUILD SUCCESSFUL!
    echo ========================================
    echo.
    echo  Executable created: TRAUMA.exe
    echo  This version has better code protection.
    echo.
) else (
    if exist "trauma.dist\TRAUMA.exe" (
        move trauma.dist\TRAUMA.exe .
        echo.
        echo Build successful! Executable: TRAUMA.exe
    ) else (
        echo.
        echo Build may have completed. Check for TRAUMA.exe
    )
)

goto end

:end
echo.
pause
