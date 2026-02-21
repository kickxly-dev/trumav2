@echo off
setlocal enabledelayedexpansion
title TRUMA - Advanced Network Security Suite v2.0

:: ============================================
:: TRUMA CLI v2.0 - Enhanced Edition
:: ============================================

:: Version check for updater
set "VERSION=2.0"
set "UPDATE_URL=https://raw.githubusercontent.com/kickxly-dev/trumav2/master/TRUMA-CLI/version.txt"

:: Initialize paths
set "TRUMA_HOME=%~dp0"
set "DATA_DIR=%TRUMA_HOME%data"
set "LOGS_DIR=%TRUMA_HOME%logs"
set "UPDATE_DIR=%TRUMA_HOME%update"
set "USERS_FILE=%DATA_DIR%\users.db"
set "SESSION_FILE=%DATA_DIR%\session.tmp"
set "CONFIG_FILE=%DATA_DIR%\config.ini"

:: Create directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%UPDATE_DIR%" mkdir "%UPDATE_DIR%"

:: Crimson theme
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

:: ============================================
:: MAIN MENU
:: ============================================
:main_menu
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                         MAIN MENU                              ^|
echo    +==============================================================+
echo.

if "%IS_LOGGED_IN%"=="1" (
    echo    [1] Network Tools              [5] My Profile
    echo    [2] System Tools               [6] View Logs  
    echo    [3] Security Tools             [7] Logout
    echo    [4] Utilities                  [U] Check Updates
    echo.
    echo    [0] Exit TRUMA                 [User: %CURRENT_USER%]
) else (
    echo       Welcome to TRUMA Network Security Suite v%VERSION%
    echo.
    echo    [1] Login                      [U] Check Updates
    echo    [2] Sign Up (Create Account)
    echo    [3] Guest Access (Limited)
    echo.
    echo    [0] Exit
)

echo.
echo    ================================================================
echo.
set /p choice="> Enter choice: "

if "%IS_LOGGED_IN%"=="1" (
    if /i "%choice%"=="1" goto network_tools
    if /i "%choice%"=="2" goto system_tools
    if /i "%choice%"=="3" goto security_tools
    if /i "%choice%"=="4" goto utilities_menu
    if /i "%choice%"=="5" goto user_profile
    if /i "%choice%"=="6" goto view_logs
    if /i "%choice%"=="7" goto logout
    if /i "%choice%"=="U" goto check_updates
    if /i "%choice%"=="0" goto exit_truma
) else (
    if /i "%choice%"=="1" goto login
    if /i "%choice%"=="2" goto signup
    if /i "%choice%"=="3" goto guest_access
    if /i "%choice%"=="U" goto check_updates
    if /i "%choice%"=="0" goto exit_truma
)

goto main_menu

:: ============================================
:: LOGIN SYSTEM
:: ============================================
:login
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                         USER LOGIN                             ^|
echo    +==============================================================+
echo.
set /p username="> Username: "
set /p password="> Password: "

:: Check if user exists
if not exist "%USERS_FILE%" (
    echo.
    echo    [!] No users found. Please sign up first.
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
    echo    [OK] Login successful! Welcome back, %username%
    call :log_activity "User logged in: %username%"
    timeout /t 2 >nul
    goto main_menu
) else (
    echo.
    echo    [!] Invalid username or password
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
echo    +==============================================================+
echo    ^|                       CREATE ACCOUNT                           ^|
echo    +==============================================================+
echo.
set /p newuser="> Choose username: "
set /p newpass="> Choose password: "
set /p confpass="> Confirm password: "

:: Validation
if "%newuser%"=="" (
    echo    [!] Username cannot be empty
    pause
    goto signup
)

if not "%newpass%"=="%confpass%" (
    echo    [!] Passwords do not match
    pause
    goto signup
)

:: Check if user already exists
if exist "%USERS_FILE%" (
    findstr /B "%newuser%:" "%USERS_FILE%" >nul
    if %errorlevel%==0 (
        echo    [!] Username already exists
        pause
        goto signup
    )
)

:: Create user
echo %newuser%:%newpass%>>"%USERS_FILE%"
echo.
echo    [OK] Account created successfully!
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
echo    [!] Guest Access - Limited Tools Only
set "CURRENT_USER=Guest"
goto network_tools

:: ============================================
:: NETWORK TOOLS MENU
:: ============================================
:network_tools
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                       NETWORK TOOLS                            ^|
echo    +==============================================================+
echo.
echo    [1] IP Information Lookup     [6] WHOIS Lookup
    echo    [2] Ping / Latency Tester     [7] Traceroute
    echo    [3] DNS Lookup Tool            [8] Subnet Calculator
    echo    [4] Port Scanner               [9] WiFi Scanner
    echo    [5] Network Scanner (ARP)
echo.
echo    [0] Back to Main Menu
echo.
echo    ================================================================
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_ip_lookup
if "%choice%"=="2" goto tool_ping
if "%choice%"=="3" goto tool_dns
if "%choice%"=="4" goto tool_port_scan
if "%choice%"=="5" goto tool_network_scan
if "%choice%"=="6" goto tool_whois
if "%choice%"=="7" goto tool_traceroute
if "%choice%"=="8" goto tool_subnet
if "%choice%"=="9" goto tool_wifi
if "%choice%"=="0" goto main_menu

goto network_tools

:: ============================================
:: IP LOOKUP TOOL
:: ============================================
:tool_ip_lookup
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                    IP INFORMATION LOOKUP                       ^|
echo    +==============================================================+
echo.
set /p target="> Enter IP or Domain: "

echo.
echo    [i] Looking up: %target%
echo    ---------------------------------------------------------------

ping -n 1 %target% >nul 2>&1
if %errorlevel%==0 (
    echo    [OK] Host is reachable
) else (
    echo    [!] Host may be unreachable
)

echo.
echo    Your Network Info:
ipconfig | findstr /i "ipv4"

echo.
echo    ---------------------------------------------------------------
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
echo    +==============================================================+
echo    ^|                     PING / LATENCY TESTER                      ^|
echo    +==============================================================+
echo.
set /p target="> Enter target (IP/Domain): "
set /p count="> Number of packets (default 4): "
if "%count%"=="" set count=4

echo.
echo    [i] Sending %count% packets to %target%...
echo    ---------------------------------------------------------------
echo.

ping -n %count% %target%

echo.
echo    ---------------------------------------------------------------
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
echo    +==============================================================+
echo    ^|                       DNS LOOKUP TOOL                        ^|
echo    +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo    [i] Resolving DNS for: %domain%
echo    ---------------------------------------------------------------
echo.

echo    A Records (IPv4):
nslookup -type=A %domain% 2>nul | findstr /B "Address" | findstr /v "#"

echo.
echo    NS Records (Nameservers):
nslookup -type=NS %domain% 2>nul | findstr "nameserver"

echo.
echo    MX Records (Mail):
nslookup -type=MX %domain% 2>nul | findstr "mail exchanger"

echo.
echo    ---------------------------------------------------------------
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
echo    +==============================================================+
echo    ^|                        PORT SCANNER                          ^|
echo    +==============================================================+
echo.
echo    Common Ports: 21(FTP) 22(SSH) 23(Telnet) 25(SMTP)
echo                  53(DNS) 80(HTTP) 443(HTTPS) 3389(RDP)
echo.
set /p target="> Enter target IP: "
set /p ports="> Ports (e.g., 80,443,22): "

echo.
echo    [i] Scanning %target% on ports: %ports%
echo    ---------------------------------------------------------------
echo    PORT     STATUS
echo    ----------------

powershell -Command "$t='%target%'; $p='%ports%' -split ','; foreach ($port in $p) { $port=$port.Trim(); if ($port -match '^\d+$') { try { $tcp=New-Object Net.Sockets.TcpClient; $c=$tcp.BeginConnect($t,[int]$port,$null,$null); $w=$c.AsyncWaitHandle.WaitOne(300,$false); if($w -and $tcp.Connected) { Write-Host ('    {0,-8} OPEN' -f $port) -ForegroundColor Green; $tcp.Close() } else { Write-Host ('    {0,-8} closed' -f $port) -ForegroundColor Red } } catch { Write-Host ('    {0,-8} error' -f $port) -ForegroundColor Yellow } } }"

echo.
echo    ---------------------------------------------------------------
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
echo    +==============================================================+
echo    ^|                    NETWORK SCANNER (ARP)                     ^|
echo    +==============================================================+
echo.
echo    [i] Scanning local network...
echo    ---------------------------------------------------------------
echo.
echo    Discovered Devices (ARP Table):
echo.

arp -a

echo.
echo    ---------------------------------------------------------------
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
echo    +==============================================================+
echo    ^|                        WHOIS LOOKUP                          ^|
echo    +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo    [i] Querying: %domain%
echo    ---------------------------------------------------------------
echo.

echo    Domain Info:
nslookup %domain% 2>nul | findstr /i "Name:\|Address:"

where curl >nul 2>&1
if %errorlevel%==0 (
    echo.
    echo    RDAP Data:
    curl -s "https://rdap.org/domain/%domain%" 2>nul | findstr "ldhName" | head -2
)

echo.
echo    ---------------------------------------------------------------
call :log_activity "WHOIS: %domain%"
pause
goto network_tools

:: ============================================
:: TRACEROUTE TOOL
:: ============================================
:tool_traceroute
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                      TRACEROUTE TOOL                         ^|
echo    +==============================================================+
echo.
set /p target="> Enter target (IP/Domain): "
set /p hops="> Max hops (default 30): "
if "%hops%"=="" set hops=30

echo.
echo    [i] Tracing route to %target% (max %hops% hops)...
echo    ---------------------------------------------------------------
echo.

tracert -d -h %hops% %target%

echo.
echo    ---------------------------------------------------------------
call :log_activity "Traceroute: %target% (%hops% hops)"
pause
goto network_tools

:: ============================================
:: SUBNET CALCULATOR
:: ============================================
:tool_subnet
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                    SUBNET CALCULATOR                         ^|
echo    +==============================================================+
echo.
echo    Enter IP with CIDR (e.g., 192.168.1.0/24)
set /p subnet="> IP/CIDR: "

echo.
echo    [i] Calculating subnet info for: %subnet%
echo    ---------------------------------------------------------------

powershell -Command "
$input='%subnet%';
if ($input -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
    $ip=$matches[1];
    $cidr=[int]$matches[2];
    $mask=[uint32]([math]::Pow(2,32)-[math]::Pow(2,32-$cidr));
    $ipBytes=$ip.Split('.');
    $ipInt=([uint32]$ipBytes[0]*16777216)+([uint32]$ipBytes[1]*65536)+([uint32]$ipBytes[2]*256)+[uint32]$ipBytes[3];
    $networkInt=$ipInt -band $mask;
    $broadcastInt=$networkInt -bor ([uint32]([math]::Pow(2,32-$cidr)-1));
    $hosts=[math]::Pow(2,32-$cidr)-2;
    Write-Host '    Network Address: '([IPAddress]([BitConverter]::GetBytes([uint32]$networkInt) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString;
    Write-Host '    Broadcast:       '([IPAddress]([BitConverter]::GetBytes([uint32]$broadcastInt) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString;
    Write-Host '    Hosts:           '$hosts;
} else { Write-Host '    Invalid format. Use: IP/CIDR (e.g., 192.168.1.0/24)' }"

echo.
echo    ---------------------------------------------------------------
call :log_activity "Subnet calc: %subnet%"
pause
goto network_tools

:: ============================================
:: WIFI SCANNER
:: ============================================
:tool_wifi
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                      WIFI SCANNER                            ^|
echo    +==============================================================+
echo.
echo    [i] Scanning WiFi networks...
echo    ---------------------------------------------------------------
echo.

netsh wlan show networks mode=bssid

echo.
echo    ---------------------------------------------------------------
call :log_activity "WiFi scan"
pause
goto network_tools

:: ============================================
:: SYSTEM TOOLS MENU
:: ============================================
:system_tools
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                        SYSTEM TOOLS                            ^|
echo    +==============================================================+
echo.
echo    [1] Active Connections        [3] System Information
    echo    [2] Firewall Status           [4] Process Monitor
echo.
echo    [0] Back to Main Menu
echo.
echo    ================================================================
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
echo    +==============================================================+
echo    ^|                  ACTIVE NETWORK CONNECTIONS                    ^|
echo    +==============================================================+
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
echo    +==============================================================+
echo    ^|                      FIREWALL STATUS                           ^|
echo    +==============================================================+
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
echo    +==============================================================+
echo    ^|                     SYSTEM INFORMATION                         ^|
echo    +==============================================================+
echo.
echo    Computer Name: %computername%
echo    User Name: %username%
echo.
echo    OS Version:
ver
echo.
echo    Network:
ipconfig | findstr /i "ipv4 subnet" 2>nul

echo.
echo    CPU:
wmic cpu get name /value 2>nul | findstr "="

echo.
echo    Memory:
wmic ComputerSystem get TotalPhysicalMemory /value 2>nul | findstr "="

echo.
echo    Disk Space:
wmic logicaldisk get size,freespace,caption 2>nul | findstr /v "Size"

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
echo    +==============================================================+
echo    ^|                       PROCESS MONITOR                          ^|
echo    +==============================================================+
echo.
echo    Running Processes (sorted by memory):
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
echo    +==============================================================+
echo    ^|                       SECURITY TOOLS                         ^|
echo    +==============================================================+
echo.
echo    [1] SSL Certificate Checker   [3] Password Strength
    echo    [2] Hash Generator            [4] Base64 Encoder
echo.
echo    [0] Back to Main Menu
echo.
echo    ================================================================
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
echo    +==============================================================+
echo    ^|                   SSL CERTIFICATE CHECKER                      ^|
echo    +==============================================================+
echo.
set /p domain="> Enter domain: "

echo.
echo    [i] Checking SSL for: %domain%
echo    ---------------------------------------------------------------
echo.

powershell -Command "try { $tcp=New-Object Net.Sockets.TcpClient('%domain%',443); $stream=$tcp.GetStream(); $ssl=New-Object Net.Security.SslStream($stream); $ssl.AuthenticateAsClient('%domain%'); $cert=$ssl.RemoteCertificate; Write-Host ('    Valid until: ' + $cert.GetExpirationDateString()) -ForegroundColor Green; $tcp.Close() } catch { Write-Host '    [!] SSL connection failed' -ForegroundColor Red }"

echo.
echo    ---------------------------------------------------------------
pause
goto security_tools

:: ============================================
:: HASH GENERATOR
:: ============================================
:tool_hash
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                      HASH GENERATOR                          ^|
echo    +==============================================================+
echo.
set /p text="> Enter text to hash: "

echo.
echo    MD5 Hash:
echo %text% > __temp__.txt
certutil -hashfile __temp__.txt MD5 2>nul | findstr /v "Certutil\|md5"
del __temp__.txt 2>nul

echo.
echo    SHA256 Hash:
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
echo    +==============================================================+
echo    ^|                 PASSWORD STRENGTH CHECKER                    ^|
echo    +==============================================================+
echo.
set /p pass="> Enter password: "

echo.
echo    ---------------------------------------------------------------

set "len=0"
for /l %%i in (0,1,100) do (
    if not "!pass:~%%i,1!"=="" set /a len+=1
)

echo    Length: %len% characters

if %len% lss 8 (
    echo    Strength: WEAK - Too short
) else if %len% lss 12 (
    echo    Strength: MODERATE - Consider 12+ chars
) else (
    echo    Strength: GOOD
)

echo.
echo    ---------------------------------------------------------------
pause
goto security_tools

:: ============================================
:: BASE64 TOOL
:: ============================================
:tool_base64
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                  BASE64 ENCODER/DECODER                        ^|
echo    +==============================================================+
echo.
echo    [1] Encode
echo    [2] Decode
echo.
set /p action="> Choose (1/2): "
set /p text="> Enter text: "

echo.
if "%action%"=="1" (
    echo    Encoded:
    powershell -Command "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%'))"
) else (
    echo    Decoded:
    powershell -Command "try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%')) } catch { 'Invalid Base64' }"
)

echo.
pause
goto security_tools

:: ============================================
:: UTILITIES MENU
:: ============================================
:utilities_menu
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                         UTILITIES                              ^|
echo    +==============================================================+
echo.
echo    [1] JSON Formatter            [3] JWT Decoder
    echo    [2] URL Encoder/Decoder
echo.
echo    [0] Back to Main Menu
echo.
echo    ================================================================
echo.
set /p choice="> Enter choice: "

if "%choice%"=="1" goto tool_json
if "%choice%"=="2" goto tool_url
if "%choice%"=="3" goto tool_jwt
if "%choice%"=="0" goto main_menu

goto utilities_menu

:: ============================================
:: JSON FORMATTER
:: ============================================
:tool_json
echo.
echo    Paste JSON (single line):
set /p jsonin="> "

echo.
echo    Formatted:
powershell -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 3 } catch { 'Invalid JSON' }"

echo.
pause
goto utilities_menu

:: ============================================
:: URL ENCODER
:: ============================================
:tool_url
echo.
echo    [1] Encode
echo    [2] Decode
echo.
set /p action="> Choose (1/2): "
set /p text="> Enter text: "

echo.
if "%action%"=="1" (
    echo    Encoded:
    powershell -Command "Add-Type -AssemblyName System.Web; [Web.HttpUtility]::UrlEncode('%text%')"
) else (
    echo    Decoded:
    powershell -Command "Add-Type -AssemblyName System.Web; [Web.HttpUtility]::UrlDecode('%text%')"
)

echo.
pause
goto utilities_menu

:: ============================================
:: JWT DECODER
:: ============================================
:tool_jwt
echo.
set /p token="> Paste JWT token: "

echo.
echo    ---------------------------------------------------------------
echo    Decoded JWT:
echo.

for /f "delims=. tokens=1,2" %%a in ("%token%") do (
    echo    Header:
    powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    '+[Text.Encoding]::UTF8.GetString($bytes)) } catch { 'Error' }"
    echo.
    echo    Payload:
    powershell -Command "try { $b='%%b'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    '+[Text.Encoding]::UTF8.GetString($bytes)) } catch { 'Error' }"
)

echo.
echo    ---------------------------------------------------------------
pause
goto utilities_menu

:: ============================================
:: USER PROFILE
:: ============================================
:user_profile
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                        USER PROFILE                          ^|
echo    +==============================================================+
echo.
echo    Username: %CURRENT_USER%
echo    Status: Logged In
echo    Version: %VERSION%
echo.
echo    Recent Activity:
if exist "%LOGS_DIR%\%CURRENT_USER%.log" (
    type "%LOGS_DIR%\%CURRENT_USER%.log" 2>nul | more +0
) else (
    echo    No activity logged yet
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
echo    +==============================================================+
echo    ^|                       ACTIVITY LOGS                          ^|
echo    +==============================================================+
echo.
if exist "%LOGS_DIR%\activity.log" (
    type "%LOGS_DIR%\activity.log" 2>nul | more
) else (
    echo    No logs available
)
echo.
pause
goto main_menu

:: ============================================
:: LOGOUT
:: ============================================
:logout
echo.
echo    Logging out...
if exist "%SESSION_FILE%" del "%SESSION_FILE%"
set "CURRENT_USER="
set "IS_LOGGED_IN=0"
timeout /t 1 >nul
goto main_menu

:: ============================================
:: CHECK FOR UPDATES
:: ============================================
:check_updates
cls
call :draw_header

echo.
echo    +==============================================================+
echo    ^|                      UPDATE CHECKER                        ^|
echo    +==============================================================+
echo.
echo    Current Version: %VERSION%
echo.
echo    [i] Checking for updates...

where curl >nul 2>&1
if %errorlevel%==0 (
    echo    [i] Connecting to update server...
    curl -sL "%UPDATE_URL%" > "%UPDATE_DIR%\latest.txt" 2>nul
    if exist "%UPDATE_DIR%\latest.txt" (
        set /p LATEST_VERSION=<"%UPDATE_DIR%\latest.txt"
        if "!LATEST_VERSION!"=="%VERSION%" (
            echo.
            echo    [OK] You are running the latest version!
        ) else (
            echo.
            echo    [!] New version available: !LATEST_VERSION!
            echo.
            echo    Would you like to download the update?
            set /p update_choice="> (Y/N): "
            if /i "!update_choice!"=="Y" (
                echo    [i] Opening download page...
                start https://github.com/kickxly-dev/trumav2/releases
            )
        )
        del "%UPDATE_DIR%\latest.txt" 2>nul
    ) else (
        echo    [!] Could not check for updates
    )
) else (
    echo    [!] curl not found. Cannot check for updates.
    echo    [!] Please visit: https://github.com/kickxly-dev/trumav2/releases
)

echo.
pause
goto main_menu

:: ============================================
:: EXIT
:: ============================================
:exit_truma
cls
call :draw_header
echo.
echo    Thank you for using TRUMA Network Security Suite!
echo    Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0

:: ============================================
:: HELPER FUNCTIONS
:: ============================================
:draw_header
echo.
echo     TTTTT RRRR  U   U M   M  AAA
echo       T   R   R U   U MM MM A   A
    echo       T   RRRR  U   U M M M AAAAA
echo       T   R  R  U   U M   M A   A
echo       T   R   R  UUU  M   M A   A
echo     ===================================
echo       Advanced Network Security v%VERSION%
echo.
goto :eof

:log_activity
echo [%date% %time%] %~1 >> "%LOGS_DIR%\activity.log"
if "%IS_LOGGED_IN%"=="1" (
    echo [%date% %time%] %~1 >> "%LOGS_DIR%\%CURRENT_USER%.log"
)
goto :eof
