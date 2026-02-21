@echo off
setlocal enabledelayedexpansion
title TRUMA - Advanced Network Security Suite v2.0

:: ============================================
:: TRUMA CLI v2.0 - Enhanced Edition (Fixed)
:: ============================================

:: Version check for updater
set "VERSION=2.0"
set "UPDATE_URL=https://raw.githubusercontent.com/kickxly-dev/trumav2/master/TRUMA-CLI/version.txt"

:: Initialize paths
set "TRUMA_HOME=%~dp0"
set "DATA_DIR=%TRUMA_HOME%data"
set "LOGS_DIR=%TRUMA_HOME%logs"
set "UPDATE_DIR=%TRUMA_HOME%update"
set "REPORTS_DIR=%TRUMA_HOME%reports"
set "USERS_FILE=%DATA_DIR%\users.db"
set "SESSION_FILE=%DATA_DIR%\session.tmp"
set "CONFIG_FILE=%DATA_DIR%\config.ini"

:: Create directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%UPDATE_DIR%" mkdir "%UPDATE_DIR%"
if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%"

:: Theme system - Load or default
set "THEME=CRIMSON"
if exist "%CONFIG_FILE%" (
    for /f "tokens=2 delims=" %%a in ('type "%CONFIG_FILE%" ^| findstr "THEME="') do set "THEME=%%a"
)

:: Apply theme colors (simple CMD colors)
call :apply_theme

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
    echo    [4] Utilities                  [T] Theme [%THEME%]
    echo    [U] Check Updates
    echo.
    echo    [0] Exit TRUMA                 [User: %CURRENT_USER%]
) else (
    echo       Welcome to TRUMA Network Security Suite v%VERSION%
    echo.
    echo    [1] Login                      [T] Theme [%THEME%]
    echo    [2] Sign Up (Create Account)   [U] Check Updates
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
    if /i "%choice%"=="T" goto theme_menu
    if /i "%choice%"=="U" goto check_updates
    if /i "%choice%"=="0" goto exit_truma
) else (
    if /i "%choice%"=="1" goto login
    if /i "%choice%"=="2" goto signup
    if /i "%choice%"=="3" goto guest_access
    if /i "%choice%"=="T" goto theme_menu
    if /i "%choice%"=="U" goto check_updates
    if /i "%choice%"=="0" goto exit_truma
)

goto main_menu

:: ============================================
:: THEME SYSTEM
:: ============================================
:theme_menu
cls
call :draw_header
echo.
echo    +==============================================================+
echo    ^|                       THEME SETTINGS                           ^|
echo    +==============================================================+
echo.
echo    Select theme:
echo.
echo    [1] CRIMSON (Red)
echo    [2] CYBER (Blue)  
echo    [3] MATRIX (Green)
echo    [4] GOLD (Yellow)
echo    [5] DARK (Gray)
echo.
echo    [0] Back
echo.
echo    ================================================================
echo.
set /p theme_choice="> Select theme: "

if "%theme_choice%"=="1" set "THEME=CRIMSON"
if "%theme_choice%"=="2" set "THEME=CYBER"
if "%theme_choice%"=="3" set "THEME=MATRIX"
if "%theme_choice%"=="4" set "THEME=GOLD"
if "%theme_choice%"=="5" set "THEME=DARK"
if "%theme_choice%"=="0" goto main_menu

:: Save theme to config
echo THEME=%THEME% > "%CONFIG_FILE%"
call :apply_theme

echo.
echo    [OK] Theme applied: %THEME%
timeout /t 1 >nul
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

echo.
echo    [i] Authenticating...
timeout /t 1 >nul

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

echo.
echo    [i] Creating account...
timeout /t 1 >nul

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
echo    [1] IP Information Lookup     [7] Traceroute
    echo    [2] Ping / Latency Tester     [8] Subnet Calculator
    echo    [3] DNS Lookup Tool            [9] WiFi Scanner
    echo    [4] Port Scanner               [10] HTTP Headers
    echo    [5] Network Scanner (ARP)      [11] IP Reputation
    echo    [6] WHOIS Lookup               [12] Speed Test
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
if "%choice%"=="10" goto tool_http_headers
if "%choice%"=="11" goto tool_ip_reputation
if "%choice%"=="12" goto tool_speedtest
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
echo    [i] Resolving...

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
call :save_report "IP Lookup: %target%"
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
call :save_report "Ping: %target%"
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
echo    [i] Querying...
timeout /t 1 >nul
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
echo    TXT Records:
nslookup -type=TXT %domain% 2>nul | findstr "text" | head -3

echo.
echo    ---------------------------------------------------------------
call :log_activity "DNS Lookup: %domain%"
call :save_report "DNS Lookup: %domain%"
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
echo    [i] Please wait...
timeout /t 1 >nul
echo.
echo    PORT     STATUS
echo    ----------------

:: Scan ports using PowerShell (simple output)
powershell -Command "$t='%target%'; $ports='%ports%' -split ','; foreach ($p in $ports) { $port=$p.Trim(); if ($port -match '^\d+$') { try { $tcp=New-Object Net.Sockets.TcpClient; $c=$tcp.BeginConnect($t,[int]$port,$null,$null); $w=$c.AsyncWaitHandle.WaitOne(500,$false); if($w -and $tcp.Connected) { Write-Host ('    ' + $port + '      OPEN'); $tcp.Close() } else { Write-Host ('    ' + $port + '      closed') } } catch { Write-Host ('    ' + $port + '      error') } } }"

echo.
echo    ---------------------------------------------------------------
call :log_activity "Port scan: %target% (%ports%)"
call :save_report "Port scan: %target%"
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
echo    [i] Discovering devices...
timeout /t 1 >nul
echo.

echo    Discovered Devices (ARP Table):
echo.
arp -a | findstr /v "Interface"

echo.
echo    ---------------------------------------------------------------
call :log_activity "Network ARP scan"
call :save_report "Network ARP scan"
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
echo    [i] Fetching WHOIS data...
timeout /t 1 >nul
echo.

echo    Domain Info:
nslookup %domain% 2>nul | findstr /i "Name:\|Address:"

where curl >nul 2>&1
if %errorlevel%==0 (
    echo.
    echo    RDAP Data:
    curl -s "https://rdap.org/domain/%domain%" 2>nul | findstr "ldhName\|status" | head -3
)

echo.
echo    ---------------------------------------------------------------
call :log_activity "WHOIS: %domain%"
call :save_report "WHOIS: %domain%"
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
call :save_report "Traceroute: %target%"
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
echo    [i] Computing...
timeout /t 1 >nul
echo.

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
    $firstUsable=$networkInt+1;
    $lastUsable=$broadcastInt-1;
    Write-Host ('    Network Address:  ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$networkInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString);
    Write-Host ('    Broadcast:          ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$broadcastInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString);
    Write-Host ('    First Usable:       ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$firstUsable) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString);
    Write-Host ('    Last Usable:        ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$lastUsable) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString);
    Write-Host ('    Total Hosts:        ' + $hosts);
    Write-Host ('    Subnet Mask:        ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$mask) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString);
} else { Write-Host '    Invalid format. Use: IP/CIDR (e.g., 192.168.1.0/24)' }"

echo.
echo    ---------------------------------------------------------------
call :log_activity "Subnet calc: %subnet%"
call :save_report "Subnet calc: %subnet%"
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
echo    [i] Please wait...
timeout /t 1 >nul
echo.

netsh wlan show networks mode=bssid

echo.
echo    ---------------------------------------------------------------
call :log_activity "WiFi scan"
call :save_report "WiFi scan"
pause
goto network_tools

:: ============================================
:: HTTP HEADERS TOOL
:: ============================================
:tool_http_headers
cls
call :draw_header
echo.
echo    +==============================================================+
echo    ^|                    HTTP HEADERS CHECKER                      ^|
echo    +==============================================================+
echo.
set /p url="> Enter URL (e.g., https://google.com): "

echo.
echo    [i] Fetching HTTP headers for: %url%
echo    [i] Connecting...
timeout /t 1 >nul
echo.

where curl >nul 2>&1
if %errorlevel%==0 (
    curl -sI "%url%" 2>nul
) else (
    echo    [!] curl not found. Cannot fetch headers.
    echo    Install curl or use full URL with http://
)

echo.
echo    ---------------------------------------------------------------
call :log_activity "HTTP Headers: %url%"
call :save_report "HTTP Headers: %url%"
pause
goto network_tools

:: ============================================
:: IP REPUTATION TOOL
:: ============================================
:tool_ip_reputation
cls
call :draw_header
echo.
echo    +==============================================================+
echo    ^|                     IP REPUTATION CHECK                      ^|
echo    +==============================================================+
echo.
set /p ip="> Enter IP to check: "

echo.
echo    [i] Checking reputation for: %ip%
echo    [i] Querying databases...
timeout /t 1 >nul
echo.

:: Check if reachable
ping -n 1 %ip% >nul 2>&1
if %errorlevel%==0 (
    echo    [OK] IP is reachable (not blocking ping)
) else (
    echo    [!] IP not responding to ping (may be blocking)
)

:: Reverse DNS check
nslookup %ip% 2>nul | findstr /i "name:" >nul
if %errorlevel%==0 (
    echo    [OK] Has PTR record (legitimate server likely)
) else (
    echo    [!] No PTR record (could be suspicious)
)

:: Check if private IP using PowerShell
powershell -Command "
$ip='%ip%';
$ipBytes=$ip.Split('.');
if (($ipBytes[0] -eq '10') -or ($ipBytes[0] -eq '192' -and $ipBytes[1] -eq '168') -or ($ipBytes[0] -eq '172' -and [int]$ipBytes[1] -ge 16 -and [int]$ipBytes[1] -le 31)) {
    Write-Host '    [!] PRIVATE IP - Not routable on internet';
} elseif ($ipBytes[0] -eq '127') {
    Write-Host '    [!] LOOPBACK IP - Localhost only';
} elseif ($ipBytes[0] -eq '0' -or $ipBytes[0] -eq '255') {
    Write-Host '    [!] RESERVED IP - Invalid for hosts';
} else {
    Write-Host '    [OK] PUBLIC IP - Routable on internet';
}"

echo.
echo    For detailed threat intel, visit:
echo    - abuseipdb.com/check/%ip%
echo    - virustotal.com/gui/ip-address/%ip%

echo.
echo    ---------------------------------------------------------------
call :log_activity "IP Reputation: %ip%"
call :save_report "IP Reputation: %ip%"
pause
goto network_tools

:: ============================================
:: SPEED TEST
:: ============================================
:tool_speedtest
cls
call :draw_header
echo.
echo    +==============================================================+
echo    ^|                     INTERNET SPEED TEST                        ^|
echo    +==============================================================+
echo.
echo    [i] Testing download speed...
echo    [i] Downloading 10MB test file...
timeout /t 1 >nul
echo.

:: Use PowerShell to download and measure
powershell -Command "
$url='http://speedtest.tele2.net/10MB.zip';
$sizeMB=10;
$start=Get-Date;
try {
    $wc=New-Object System.Net.WebClient;
    $data=$wc.DownloadData($url);
    $end=Get-Date;
    $duration=($end-$start).TotalSeconds;
    $speedMbps=($sizeMB*8)/$duration;
    Write-Host ('    Download Speed: ' + [math]::Round($speedMbps,2) + ' Mbps');
    Write-Host ('    Duration: ' + [math]::Round($duration,2) + ' seconds');
    if ($speedMbps -gt 50) { Write-Host '    [Excellent]'; }
    elseif ($speedMbps -gt 25) { Write-Host '    [Good]'; }
    elseif ($speedMbps -gt 10) { Write-Host '    [Average]'; }
    else { Write-Host '    [Slow]'; }
} catch {
    Write-Host '    [!] Speed test failed. Check internet connection.';
}"

echo.
echo    ---------------------------------------------------------------
call :log_activity "Speed test completed"
call :save_report "Speed test"
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
echo    [1] Active Connections (netstat)
echo    [2] Firewall Status
echo    [3] System Information
echo    [4] Process Monitor
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
echo    [1] SSL Certificate Checker
echo    [2] Hash Generator (MD5/SHA256)
echo    [3] Password Strength Checker
echo    [4] Base64 Encoder/Decoder
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
echo    [i] Connecting via SSL...
timeout /t 1 >nul
echo.

powershell -Command "
try {
    $tcp=New-Object Net.Sockets.TcpClient('%domain%',443);
    $stream=$tcp.GetStream();
    $ssl=New-Object Net.Security.SslStream($stream);
    $ssl.AuthenticateAsClient('%domain%');
    $cert=$ssl.RemoteCertificate;
    $expiry=$cert.GetExpirationDateString();
    $days=($cert.NotAfter - (Get-Date)).Days;
    Write-Host ('    Valid until: ' + $expiry);
    Write-Host ('    Days remaining: ' + $days);
    Write-Host ('    Issuer: ' + $cert.Issuer);
    $tcp.Close();
} catch {
    Write-Host '    [!] SSL connection failed';
    Write-Host ('    Error: ' + $_.Exception.Message);
}"

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
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA256]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('    ' + [BitConverter]::ToString($hash).Replace('-','').ToLower())"

echo.
echo    SHA512 Hash:
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA512]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('    ' + [BitConverter]::ToString($hash).Replace('-','').ToLower())"

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
set "has_lower=0"
set "has_upper=0"
set "has_number=0"

for /l %%i in (0,1,100) do (
    if not "!pass:~%%i,1!"=="" (
        set /a len+=1
        echo !pass:~%%i,1! | findstr /r "[a-z]" >nul && set has_lower=1
        echo !pass:~%%i,1! | findstr /r "[A-Z]" >nul && set has_upper=1
        echo !pass:~%%i,1! | findstr /r "[0-9]" >nul && set has_number=1
    )
)

echo    Length: %len% characters

:: Calculate strength score
set /a score=0
if %len% geq 8 set /a score+=1
if %len% geq 12 set /a score+=1
if %has_lower%==1 set /a score+=1
if %has_upper%==1 set /a score+=1
if %has_number%==1 set /a score+=1

if %score% lss 2 (
    echo    Strength: VERY WEAK
    echo    ^< 8 chars, no complexity
) else if %score%==2 (
    echo    Strength: WEAK
) else if %score%==3 (
    echo    Strength: MODERATE
) else if %score%==4 (
    echo    Strength: STRONG
) else (
    echo    Strength: VERY STRONG
    echo    Excellent password!
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
    powershell -Command "Write-Host ('    ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%')))"
) else (
    echo    Decoded:
    powershell -Command "try { Write-Host ('    ' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%'))) } catch { Write-Host '    [!] Invalid Base64' }"
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
echo    [1] JSON Formatter
echo    [2] URL Encoder/Decoder
echo    [3] JWT Decoder
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
powershell -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 10 } catch { Write-Host '    [!] Invalid JSON' }"

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
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ('    ' + [Web.HttpUtility]::UrlEncode('%text%'))"
) else (
    echo    Decoded:
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ('    ' + [Web.HttpUtility]::UrlDecode('%text%'))"
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
    powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    ' + [Text.Encoding]::UTF8.GetString($bytes)) } catch { Write-Host '    [!] Error' }"
    echo.
    echo    Payload:
    powershell -Command "try { $b='%%b'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); $json=[Text.Encoding]::UTF8.GetString($bytes); Write-Host ('    ' + $json); $payload=$json | ConvertFrom-Json; if($payload.exp) { $exp=[datetime]::UnixEpoch.AddSeconds($payload.exp); $days=($exp-(Get-Date)).Days; Write-Host ('    Token expires: ' + $exp + ' (' + $days + ' days)') } } catch { Write-Host '    [!] Error' }"
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
echo    Theme: %THEME%
echo.
echo    ---------------------------------------------------------------
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
    echo    [!] No logs available
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
echo    [OK] Logged out successfully
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
    echo    Please visit: https://github.com/kickxly-dev/trumav2/releases
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
echo    Thank you for using TRUMA!
echo    Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0

:: ============================================
:: HELPER FUNCTIONS
:: ============================================
:apply_theme
if "%THEME%"=="CRIMSON" (
    color 0C
) else if "%THEME%"=="CYBER" (
    color 0B
) else if "%THEME%"=="MATRIX" (
    color 0A
) else if "%THEME%"=="GOLD" (
    color 0E
) else if "%THEME%"=="DARK" (
    color 0F
)
goto :eof

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

:save_report
echo.
echo    Save this report to file? (Y/N)
set /p save_choice="> "
if /i "%save_choice%"=="Y" (
    set "report_file=%REPORTS_DIR%\report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt"
    set "report_file=!report_file: =0!"
    echo TRUMA Security Report > "!report_file!"
    echo Date: %date% %time% >> "!report_file!"
    echo ====================================== >> "!report_file!"
    echo %~1 >> "!report_file!"
    echo    [OK] Report saved to: !report_file!
)
goto :eof

:log_activity
echo [%date% %time%] %~1 >> "%LOGS_DIR%\activity.log"
if "%IS_LOGGED_IN%"=="1" (
    echo [%date% %time%] %~1 >> "%LOGS_DIR%\%CURRENT_USER%.log"
)
goto :eof
