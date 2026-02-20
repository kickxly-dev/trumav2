@echo off
title TRUMA - Advanced Network Security Suite
setlocal enabledelayedexpansion

:: ============================================
:: TRUMA - Advanced Network Security Suite
:: Version 1.0 - CLI Edition
:: ============================================

:: Initialize paths
set "TRUMA_HOME=%~dp0"
set "DATA_DIR=%TRUMA_HOME%data"
set "LOGS_DIR=%TRUMA_HOME%logs"
set "USERS_FILE=%DATA_DIR%\users.db"
set "SESSION_FILE=%DATA_DIR%\session.tmp"

:: Create directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

:: Simple colors for CMD compatibility
set "RED=[31m"
set "GREEN=[32m"
set "YELLOW=[33m"
set "CYAN=[36m"
set "WHITE=[37m"
set "GRAY=[90m"
set "RESET=[0m"

:: Use simple echo without ANSI codes for compatibility
color 0C

:: Initialize session
set "CURRENT_USER="
set "IS_LOGGED_IN=0"

:: Check for existing session
if exist "%SESSION_FILE%" (
    set /p CURRENT_USER=<"%SESSION_FILE%"
    if not "!CURRENT_USER!"=="" (
        set "IS_LOGGED_IN=1"
    )
)

:main_menu
cls
call :draw_header

echo.
echo  +==============================================================+
echo  ^|                         MAIN MENU                              ^|
echo  +==============================================================+
echo.

if "%IS_LOGGED_IN%"=="1" (
    echo   [1] Network Tools
    echo   [2] System Tools
    echo   [3] Security Tools
    echo   [4] Utilities
    echo.
    echo   [5] My Profile [User: %CURRENT_USER%]
    echo   [6] View Logs
    echo   [7] Logout
    echo.
    echo   [0] Exit TRUMA
) else (
    echo      Welcome to TRUMA Network Security Suite
    echo.
    echo   [1] Login
    echo   [2] Sign Up (Create Account)
    echo.
    echo   [3] Guest Access (Limited Tools)
    echo.
    echo   [0] Exit
)

echo.
echo +==============================================================+
echo.
set /p choice="> Enter choice: "

if "%IS_LOGGED_IN%"=="1" (
    if "%choice%"=="1" goto network_tools
    if "%choice%"=="2" goto system_tools
    if "%choice%"=="3" goto security_tools
    if "%choice%"=="4" goto utilities
    if "%choice%"=="5" goto user_profile
    if "%choice%"=="6" goto view_logs
    if "%choice%"=="7" goto logout
    if "%choice%"=="0" goto exit_truma
) else (
    if "%choice%"=="1" goto login
    if "%choice%"=="2" goto signup
    if "%choice%"=="3" goto guest_access
    if "%choice%"=="0" goto exit_truma
)

goto main_menu

:: ============================================
:: LOGIN SYSTEM
:: ============================================
:login
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                         USER LOGIN                             ^|
echo +==============================================================+
echo.
set /p username="> Username: "
set /p password="> Password: "

:: Check if user exists
if not exist "%USERS_FILE%" (
    echo.
    echo [!] No users found. Please sign up first.
    pause
    goto main_menu
)

:: Validate credentials
set "found=0"
for /f "tokens=1,2 delims=:" %%a in ('type "%USERS_FILE%"') do (
    if "%%a"=="%username%" (
        if "%%b"=="%password%" (
            set "found=1"
            set "CURRENT_USER=%username%"
        )
    )
)

if "%found%"=="1" (
    set "IS_LOGGED_IN=1"
    echo %username%>%SESSION_FILE%
    echo.
    echo [OK] Login successful! Welcome back, %username%
    call :log_activity "User logged in: %username%"
    timeout /t 2 >nul
    goto main_menu
) else (
    echo.
    echo [!] Invalid username or password
    pause
    goto main_menu
)

:: ============================================
:: SIGNUP SYSTEM
:: ============================================
:signup
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       CREATE ACCOUNT                           ^|
echo +==============================================================+
echo.
set /p newuser="> Choose username: "
set /p newpass="> Choose password: "
set /p confpass="> Confirm password: "

:: Validation
if "%newuser%"=="" (
    echo [!] Username cannot be empty
    pause
    goto signup
)

if not "%newpass%"=="%confpass%" (
    echo [!] Passwords do not match
    pause
    goto signup
)

:: Check if user already exists
if exist "%USERS_FILE%" (
    findstr /B "%newuser%:" "%USERS_FILE%" >nul
    if %errorlevel%==0 (
        echo [!] Username already exists
        pause
        goto signup
    )
)

:: Create user
echo %newuser%:%newpass%>>"%USERS_FILE%"
echo.
echo [OK] Account created successfully!
call :log_activity "New user registered: %newuser%"
timeout /t 2 >nul

set "CURRENT_USER=%newuser%"
set "IS_LOGGED_IN=1"
echo %newuser%>%SESSION_FILE%

goto main_menu

:: ============================================
:: GUEST ACCESS
:: ============================================
:guest_access
cls
call :draw_header

echo.
echo [!] Guest Access - Limited Tools Only
echo     Some features require login
echo.
timeout /t 2 >nul
goto network_tools

:: ============================================
:: NETWORK TOOLS MENU
:: ============================================
:network_tools
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       NETWORK TOOLS                            ^|
echo +==============================================================+
echo.
echo   [1] IP Information Lookup
echo   [2] Ping / Latency Tester
echo   [3] DNS Lookup Tool
echo   [4] Port Scanner
echo   [5] Network Scanner (ARP Table)
echo   [6] WHOIS Lookup
echo.
echo   [0] Back to Main Menu
echo.
echo +==============================================================+
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_ip_lookup
if "%choice%"=="2" goto tool_ping
if "%choice%"=="3" goto tool_dns
if "%choice%"=="4" goto tool_port_scan
if "%choice%"=="5" goto tool_network_scan
if "%choice%"=="6" goto tool_whois
if "%choice%"=="0" goto main_menu

goto network_tools

:: ============================================
:: IP LOOKUP TOOL
:: ============================================
:tool_ip_lookup
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                    IP INFORMATION LOOKUP                       ^|
echo +==============================================================+
echo.
set /p target="> Enter IP or Domain: "

echo.
echo [i] Looking up: %target%
echo ---------------------------------------------------------------

:: Resolve domain if needed
ping -n 1 %target% >nul 2>&1
if %errorlevel%==0 (
    echo [OK] Host is reachable
) else (
    echo [!] Host may be unreachable or blocking ping
)

:: Show IP config
echo.
echo Your Network Info:
ipconfig | findstr /i "ipv4"

:: Show routing
echo.
echo Trace Route (first 5 hops):
tracert -d -h 5 %target% 2>nul

echo.
echo ---------------------------------------------------------------
call :log_activity "IP Lookup: %target%"
pause
goto network_tools

:: ============================================
:: PING TOOL
:: ============================================
:tool_ping
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                     PING / LATENCY TESTER                      ^|
echo +==============================================================+
echo.
set /p target="> Enter target (IP/Domain): "
set /p count="> Number of packets (default 4): "
if "%count%"=="" set count=4

echo.
echo [i] Sending %count% packets to %target%...
echo ---------------------------------------------------------------
echo.

ping -n %count% %target%

echo.
echo ---------------------------------------------------------------
call :log_activity "Ping: %target% (%count% packets)"
pause
goto network_tools

:: ============================================
:: DNS LOOKUP TOOL
:: ============================================
:tool_dns
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       DNS LOOKUP TOOL                        ^|
echo +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo [i] Resolving DNS for: %domain%
echo ---------------------------------------------------------------
echo.

echo A Records (IPv4):
nslookup -type=A %domain% 2>nul | findstr /B "Address" | findstr /v "#"

echo.
echo NS Records (Nameservers):
nslookup -type=NS %domain% 2>nul | findstr "nameserver"

echo.
echo MX Records (Mail):
nslookup -type=MX %domain% 2>nul | findstr "mail exchanger"

echo.
echo ---------------------------------------------------------------
call :log_activity "DNS Lookup: %domain%"
pause
goto network_tools

:: ============================================
:: PORT SCANNER
:: ============================================
:tool_port_scan
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                        PORT SCANNER                          ^|
echo +==============================================================+
echo.
echo Common Ports: 21(FTP) 22(SSH) 23(Telnet) 25(SMTP)
echo               53(DNS) 80(HTTP) 443(HTTPS) 3389(RDP)
echo.
set /p target="> Enter target IP: "
set /p ports="> Ports to scan (e.g., 80,443,22): "

echo.
echo [i] Scanning %target% on ports: %ports%
echo ---------------------------------------------------------------
echo PORT     STATUS
echo ----------------

:: Port scan with PowerShell
powershell -Command "$target='%target%'; $ports='%ports%' -split ','; foreach ($port in $ports) { $port=$port.Trim(); if ($port -match '^\d+$') { try { $tcp=New-Object Net.Sockets.TcpClient; $conn=$tcp.BeginConnect($target,$port,$null,$null); $wait=$conn.AsyncWaitHandle.WaitOne(300,$false); if($wait -and $tcp.Connected) { Write-Host ('{0,-8} OPEN' -f $port); $tcp.Close() } else { Write-Host ('{0,-8} closed/filtered' -f $port) } } catch { Write-Host ('{0,-8} error' -f $port) } } }"

echo.
echo ---------------------------------------------------------------
call :log_activity "Port scan: %target% (%ports%)"
pause
goto network_tools

:: ============================================
:: NETWORK SCANNER (ARP)
:: ============================================
:tool_network_scan
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                    NETWORK SCANNER (ARP)                     ^|
echo +==============================================================+
echo.
echo [i] Scanning local network...
echo ---------------------------------------------------------------
echo.
echo Discovered Devices (ARP Table):
echo.

arp -a

echo.
echo ---------------------------------------------------------------
call :log_activity "Network ARP scan"
pause
goto network_tools

:: ============================================
:: WHOIS LOOKUP
:: ============================================
:tool_whois
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                        WHOIS LOOKUP                          ^|
echo +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo [i] Querying: %domain%
echo ---------------------------------------------------------------
echo.

echo Domain Info:
nslookup %domain% 2>nul | findstr /i "Name:\|Address:"

echo.
echo Note: Full WHOIS requires internet connection
echo RDAP lookup (if curl available):
where curl >nul 2>&1
if %errorlevel%==0 (
    curl -s "https://rdap.org/domain/%domain%" 2>nul | findstr "ldhName" | head -2
)

echo.
echo ---------------------------------------------------------------
call :log_activity "WHOIS: %domain%"
pause
goto network_tools

:: ============================================
:: SYSTEM TOOLS MENU
:: ============================================
:system_tools
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                        SYSTEM TOOLS                            ^|
echo +==============================================================+
echo.
echo   [1] Active Connections (netstat)
echo   [2] Firewall Status
echo   [3] System Information
echo   [4] Process Monitor
echo.
echo   [0] Back to Main Menu
echo.
echo +==============================================================+
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_connections
if "%choice%"=="2" goto tool_firewall
if "%choice%"=="3" goto tool_sysinfo
if "%choice%"=="4" goto tool_processes
if "%choice%"=="0" goto main_menu

goto system_tools

:: ============================================
:: ACTIVE CONNECTIONS
:: ============================================
:tool_connections
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                  ACTIVE NETWORK CONNECTIONS                    ^|
echo +==============================================================+
echo.
netstat -an | findstr "ESTABLISHED LISTENING" | more
echo.
pause
goto system_tools

:: ============================================
:: FIREWALL STATUS
:: ============================================
:tool_firewall
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                      FIREWALL STATUS                           ^|
echo +==============================================================+
echo.
netsh advfirewall show allprofiles
echo.
pause
goto system_tools

:: ============================================
:: SYSTEM INFO
:: ============================================
:tool_sysinfo
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                     SYSTEM INFORMATION                         ^|
echo +==============================================================+
echo.
echo Computer Name: %computername%
echo User Name: %username%
echo.
echo OS Version:
ver
echo.
echo Network:
ipconfig | findstr /i "ipv4 subnet" 2>nul

echo.
echo CPU:
wmic cpu get name /value 2>nul | findstr "="

echo.
echo Memory:
wmic ComputerSystem get TotalPhysicalMemory /value 2>nul | findstr "="

echo.
pause
goto system_tools

:: ============================================
:: PROCESS MONITOR
:: ============================================
:tool_processes
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       PROCESS MONITOR                          ^|
echo +==============================================================+
echo.
echo Running Processes (top by memory):
echo.
tasklist | sort /+58 | more +3
echo.
pause
goto system_tools

:: ============================================
:: SECURITY TOOLS MENU
:: ============================================
:security_tools
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       SECURITY TOOLS                         ^|
echo +==============================================================+
echo.
echo   [1] SSL Certificate Checker
echo   [2] Hash Generator (MD5/SHA256)
echo   [3] Password Strength Checker
echo   [4] Base64 Encoder/Decoder
echo.
echo   [0] Back to Main Menu
echo.
echo +==============================================================+
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_ssl
if "%choice%"=="2" goto tool_hash
if "%choice%"=="3" goto tool_password
if "%choice%"=="4" goto tool_base64
if "%choice%"=="0" goto main_menu

goto security_tools

:: ============================================
:: SSL CHECKER
:: ============================================
:tool_ssl
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                   SSL CERTIFICATE CHECKER                      ^|
echo +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo [i] Checking SSL for: %domain%
echo ---------------------------------------------------------------
echo.

:: Try PowerShell SSL test
powershell -Command "try { $tcp=New-Object Net.Sockets.TcpClient('%domain%',443); $stream=$tcp.GetStream(); $ssl=New-Object Net.Security.SslStream($stream); $ssl.AuthenticateAsClient('%domain%'); $cert=$ssl.RemoteCertificate; Write-Host ('Valid until: ' + $cert.GetExpirationDateString()); $tcp.Close() } catch { Write-Host 'SSL connection failed' }"

echo.
echo ---------------------------------------------------------------
pause
goto security_tools

:: ============================================
:: HASH GENERATOR
:: ============================================
:tool_hash
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                      HASH GENERATOR                          ^|
echo +==============================================================+
echo.
set /p text="> Enter text to hash: "

echo.
echo MD5 Hash:
echo %text% > __temp__.txt
certutil -hashfile __temp__.txt MD5 2>nul | findstr /v "Certutil\|md5"
del __temp__.txt 2>nul

echo.
echo SHA256 Hash:
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA256]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ([BitConverter]::ToString($hash).Replace('-','').ToLower())"

echo.
pause
goto security_tools

:: ============================================
:: PASSWORD CHECKER
:: ============================================
:tool_password
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                 PASSWORD STRENGTH CHECKER                    ^|
echo +==============================================================+
echo.
set /p pass="> Enter password: "

echo.
echo ---------------------------------------------------------------

:: Check length
set "len=0"
for /l %%i in (0,1,100) do (
    if not "!pass:~%%i,1!"=="" set /a len+=1
)

echo Length: %len% characters

:: Simple strength check
if %len% lss 8 (
    echo Strength: WEAK - Too short
) else if %len% lss 12 (
    echo Strength: MODERATE - Consider 12+ chars
) else (
    echo Strength: GOOD
)

echo.
echo ---------------------------------------------------------------
pause
goto security_tools

:: ============================================
:: BASE64 TOOL
:: ============================================
:tool_base64
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                  BASE64 ENCODER/DECODER                        ^|
echo +==============================================================+
echo.
echo [1] Encode
echo [2] Decode
echo.
set /p action="> Choose (1/2): "
set /p text="> Enter text: "

echo.
if "%action%"=="1" (
    echo Encoded:
    powershell -Command "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%'))"
) else (
    echo Decoded:
    powershell -Command "try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%')) } catch { 'Invalid Base64' }"
)

echo.
pause
goto security_tools

:: ============================================
:: UTILITIES MENU
:: ============================================
:utilities
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                         UTILITIES                              ^|
echo +==============================================================+
echo.
echo   [1] JSON Formatter
echo   [2] URL Encoder/Decoder
echo   [3] JWT Decoder
echo.
echo   [0] Back to Main Menu
echo.
echo +==============================================================+
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_json
if "%choice%"=="2" goto tool_url
if "%choice%"=="3" goto tool_jwt
if "%choice%"=="0" goto main_menu

goto utilities

:: ============================================
:: JSON FORMATTER
:: ============================================
:tool_json
echo.
echo Paste JSON (single line) or press Enter to skip:
set /p jsonin="> "

echo.
echo Formatted:
powershell -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 3 } catch { 'Invalid JSON' }"

echo.
pause
goto utilities

:: ============================================
:: URL ENCODER
:: ============================================
:tool_url
echo.
echo [1] Encode
echo [2] Decode
echo.
set /p action="> Choose (1/2): "
set /p text="> Enter text: "

echo.
if "%action%"=="1" (
    echo Encoded:
    powershell -Command "Add-Type -AssemblyName System.Web; [Web.HttpUtility]::UrlEncode('%text%')"
) else (
    echo Decoded:
    powershell -Command "Add-Type -AssemblyName System.Web; [Web.HttpUtility]::UrlDecode('%text%')"
)

echo.
pause
goto utilities

:: ============================================
:: JWT DECODER
:: ============================================
:tool_jwt
echo.
set /p token="> Paste JWT token: "

echo.
echo ---------------------------------------------------------------
echo Decoded JWT:
echo.

:: Split and decode
for /f "delims=. tokens=1,2" %%a in ("%token%") do (
    echo Header:
    powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ([Text.Encoding]::UTF8.GetString($bytes)) } catch { 'Error' }"
    echo.
    echo Payload:
    powershell -Command "try { $b='%%b'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ([Text.Encoding]::UTF8.GetString($bytes)) } catch { 'Error' }"
)

echo.
echo ---------------------------------------------------------------
pause
goto utilities

:: ============================================
:: USER PROFILE
:: ============================================
:user_profile
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                        USER PROFILE                          ^|
echo +==============================================================+
echo.
echo Username: %CURRENT_USER%
echo Status: Logged In
echo.
echo Recent Activity:
if exist "%LOGS_DIR%\%CURRENT_USER%.log" (
    type "%LOGS_DIR%\%CURRENT_USER%.log" 2>nul | tail -10
) else (
    echo No activity logged yet
)
echo.
pause
goto main_menu

:: ============================================
:: VIEW LOGS
:: ============================================
:view_logs
cls
call :draw_header

echo.
echo +==============================================================+
echo ^|                       ACTIVITY LOGS                          ^|
echo +==============================================================+
echo.
if exist "%LOGS_DIR%\activity.log" (
    type "%LOGS_DIR%\activity.log" 2>nul | more
) else (
    echo No logs available
)
echo.
pause
goto main_menu

:: ============================================
:: LOGOUT
:: ============================================
:logout
echo.
echo Logging out...
if exist "%SESSION_FILE%" del "%SESSION_FILE%"
set "CURRENT_USER="
set "IS_LOGGED_IN=0"
timeout /t 1 >nul
goto main_menu

:: ============================================
:: EXIT
:: ============================================
:exit_truma
cls
call :draw_header
echo.
echo Thank you for using TRUMA Network Security Suite!
echo Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0

:: ============================================
:: HELPER FUNCTIONS
:: ============================================
:draw_header
echo.
echo  =================================================================
echo  ^|                                                               ^|
echo  ^|   TTTTT RRRR  U   U M   M  AAA    Advanced Network Security   ^|
echo  ^|     T   R   R U   U MM MM A   A   -------------------------    ^|
echo  ^|     T   RRRR  U   U M M M AAAAA       CLI Edition v1.0       ^|
echo  ^|     T   R  R  U   U M   M A   A                             ^|
echo  ^|     T   R   R  UUU  M   M A   A                             ^|
echo  ^|                                                               ^|
echo  =================================================================
echo.
goto :eof

:log_activity
echo [%date% %time%] %~1 >> "%LOGS_DIR%\activity.log"
if "%IS_LOGGED_IN%"=="1" (
    echo [%date% %time%] %~1 >> "%LOGS_DIR%\%CURRENT_USER%.log"
)
goto :eof
