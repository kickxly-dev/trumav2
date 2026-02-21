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

:: Apply theme
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
call :color_box "MAIN MENU" %COLOR_PRIMARY%
echo.

if "%IS_LOGGED_IN%"=="1" (
    call :colored_echo "[1]" %COLOR_SUCCESS% "Network Tools"
    call :colored_echo "[2]" %COLOR_SUCCESS% "System Tools"
    call :colored_echo "[3]" %COLOR_SUCCESS% "Security Tools"
    call :colored_echo "[4]" %COLOR_SUCCESS% "Utilities"
    echo.
    call :colored_echo "[5]" %COLOR_INFO% "My Profile"
    call :colored_echo "[6]" %COLOR_INFO% "View Logs"
    call :colored_echo "[7]" %COLOR_INFO% "Logout"
    call :colored_echo "[T]" %COLOR_WARNING% "Theme [Current: %THEME%]"
    call :colored_echo "[U]" %COLOR_WARNING% "Check Updates"
    echo.
    call :colored_echo "[0]" %COLOR_DANGER% "Exit TRUMA"
    echo.
    call :colored_echo "User:" %COLOR_INFO% "%CURRENT_USER%"
) else (
    echo    Welcome to TRUMA Network Security Suite v%VERSION%
    echo.
    call :colored_echo "[1]" %COLOR_SUCCESS% "Login"
    call :colored_echo "[2]" %COLOR_SUCCESS% "Sign Up (Create Account)"
    call :colored_echo "[3]" %COLOR_WARNING% "Guest Access (Limited)"
    echo.
    call :colored_echo "[T]" %COLOR_INFO% "Theme [Current: %THEME%]"
    call :colored_echo "[U]" %COLOR_WARNING% "Check Updates"
    echo.
    call :colored_echo "[0]" %COLOR_DANGER% "Exit"
)

echo.
call :draw_line
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
call :color_box "THEME SETTINGS" %COLOR_PRIMARY%
echo.
echo    Select theme:
echo.
call :colored_echo "[1]" %COLOR_DANGER% "CRIMSON (Red)"
call :colored_echo "[2]" %COLOR_INFO% "CYBER (Blue)"
call :colored_echo "[3]" %COLOR_SUCCESS% "MATRIX (Green)"
call :colored_echo "[4]" %COLOR_WARNING% "GOLD (Yellow)"
call :colored_echo "[5]" %COLOR_PRIMARY% "DARK (Gray)"
echo.
echo    [0] Back
echo.
call :draw_line
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
call :loading_animation "Applying theme"

pause
goto main_menu

:: ============================================
:: LOGIN SYSTEM
:: ============================================
:login
cls
call :draw_header
echo.
call :color_box "USER LOGIN" %COLOR_PRIMARY%
echo.
set /p username="> Username: "
set /p password="> Password: "

:: Check if user exists
if not exist "%USERS_FILE%" (
    echo.
    call :colored_echo "[!]" %COLOR_DANGER% "No users found. Please sign up first."
    pause
    goto main_menu
)

:: Loading animation
call :loading_animation "Authenticating"

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
    call :colored_echo "[OK]" %COLOR_SUCCESS% "Login successful! Welcome back, %username%"
    call :log_activity "User logged in: %username%"
    timeout /t 2 >nul
    goto main_menu
) else (
    echo.
    call :colored_echo "[!]" %COLOR_DANGER% "Invalid username or password"
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
call :color_box "CREATE ACCOUNT" %COLOR_PRIMARY%
echo.
set /p newuser="> Choose username: "
set /p newpass="> Choose password: "
set /p confpass="> Confirm password: "

:: Validation
if "%newuser%"=="" (
    call :colored_echo "[!]" %COLOR_DANGER% "Username cannot be empty"
    pause
    goto signup
)

if not "%newpass%"=="%confpass%" (
    call :colored_echo "[!]" %COLOR_DANGER% "Passwords do not match"
    pause
    goto signup
)

:: Check if user already exists
if exist "%USERS_FILE%" (
    findstr /B "%newuser%:" "%USERS_FILE%" >nul
    if %errorlevel%==0 (
        call :colored_echo "[!]" %COLOR_DANGER% "Username already exists"
        pause
        goto signup
    )
)

call :loading_animation "Creating account"

:: Create user
echo %newuser%:%newpass%>>"%USERS_FILE%"
echo.
call :colored_echo "[OK]" %COLOR_SUCCESS% "Account created successfully!"
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
call :colored_echo "[!]" %COLOR_WARNING% "Guest Access - Limited Tools Only"
set "CURRENT_USER=Guest"
goto network_tools

:: ============================================
:: NETWORK TOOLS MENU
:: ============================================
:network_tools
cls
call :draw_header
echo.
call :color_box "NETWORK TOOLS" %COLOR_PRIMARY%
echo.
call :colored_echo "[1]" %COLOR_SUCCESS% "IP Information Lookup"
call :colored_echo "[2]" %COLOR_SUCCESS% "Ping / Latency Tester"
call :colored_echo "[3]" %COLOR_SUCCESS% "DNS Lookup Tool"
call :colored_echo "[4]" %COLOR_SUCCESS% "Port Scanner"
call :colored_echo "[5]" %COLOR_SUCCESS% "Network Scanner (ARP)"
call :colored_echo "[6]" %COLOR_SUCCESS% "WHOIS Lookup"
call :colored_echo "[7]" %COLOR_SUCCESS% "Traceroute"
call :colored_echo "[8]" %COLOR_SUCCESS% "Subnet Calculator"
call :colored_echo "[9]" %COLOR_SUCCESS% "WiFi Scanner"
call :colored_echo "[10]" %COLOR_INFO% "HTTP Headers"
call :colored_echo "[11]" %COLOR_INFO% "IP Reputation"
call :colored_echo "[12]" %COLOR_INFO% "Speed Test"
echo.
call :colored_echo "[0]" %COLOR_DANGER% "Back to Main Menu"
echo.
call :draw_line
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
call :color_box "IP INFORMATION LOOKUP" %COLOR_PRIMARY%
echo.
set /p target="> Enter IP or Domain: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Looking up: %target%"
call :draw_line

:: Loading animation
call :loading_animation "Resolving host"

ping -n 1 %target% >nul 2>&1
if %errorlevel%==0 (
    call :colored_echo "[OK]" %COLOR_SUCCESS% "Host is reachable"
) else (
    call :colored_echo "[!]" %COLOR_DANGER% "Host may be unreachable"
)

echo.
call :colored_echo "Your Network Info:" %COLOR_INFO%
ipconfig | findstr /i "ipv4"

call :draw_line
call :log_activity "IP Lookup: %target%"

:: Offer to save report
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
call :color_box "PING / LATENCY TESTER" %COLOR_PRIMARY%
echo.
set /p target="> Enter target (IP/Domain): "
set /p count="> Number of packets (default 4): "
if "%count%"=="" set count=4

echo.
call :colored_echo "[i]" %COLOR_INFO% "Sending %count% packets to %target%..."
call :draw_line
echo.

:: Animated ping
powershell -Command "
$target='%target%';
$count=%count%;
Write-Host '    Pinging ' $target ' with 32 bytes of data:' -ForegroundColor Cyan;
for ($i=1; $i -le $count; $i++) {
    $ping=Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue;
    if ($ping) {
        $result=Test-Connection -ComputerName $target -Count 1 -ErrorAction SilentlyContinue;
        Write-Host ('    Reply from ' + $target + ': bytes=32 time=' + $result.ResponseTime + 'ms TTL=' + $result.ResponseTime) -ForegroundColor Green;
    } else {
        Write-Host ('    Request timed out.') -ForegroundColor Red;
    }
    Start-Sleep -Milliseconds 500;
}"

echo.
call :draw_line
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
call :color_box "DNS LOOKUP TOOL" %COLOR_PRIMARY%
echo.
set /p domain="> Enter domain: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Resolving DNS for: %domain%"
call :loading_animation "Querying DNS"
echo.

call :colored_echo "A Records (IPv4):" %COLOR_WARNING%
nslookup -type=A %domain% 2>nul | findstr /B "Address" | findstr /v "#"

call :colored_echo "NS Records:" %COLOR_WARNING%
nslookup -type=NS %domain% 2>nul | findstr "nameserver"

call :colored_echo "MX Records:" %COLOR_WARNING%
nslookup -type=MX %domain% 2>nul | findstr "mail exchanger"

call :colored_echo "TXT Records:" %COLOR_WARNING%
nslookup -type=TXT %domain% 2>nul | findstr "text"

call :draw_line
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
call :color_box "PORT SCANNER" %COLOR_PRIMARY%
echo.
echo    Common Ports: 21(FTP) 22(SSH) 23(Telnet) 25(SMTP)
echo                  53(DNS) 80(HTTP) 443(HTTPS) 3389(RDP)
echo.
set /p target="> Enter target IP: "
set /p ports="> Ports (e.g., 80,443,22 or 1-1000): "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Scanning %target% on ports: %ports%"
call :loading_animation "Scanning"
echo.
echo    PORT     STATUS     SERVICE
echo    ---------------------------

:: Check if range or list
if "%ports:~0,1%"=="1-" (
    :: Port range - scan first 100 only for speed
    for /l %%p in (1,1,100) do (
        call :scan_port %target% %%p
    )
) else (
    :: Port list
    for %%p in (%ports%) do (
        call :scan_port %target% %%p
    )
)

echo.
call :draw_line
call :log_activity "Port scan: %target% (%ports%)"
call :save_report "Port scan: %target% on ports %ports%"
pause
goto network_tools

:scan_port
:: Subroutine to scan single port
powershell -Command "$target='%1'; $port=%2; try { $tcp=New-Object Net.Sockets.TcpClient; $conn=$tcp.BeginConnect($target,$port,$null,$null); $wait=$conn.AsyncWaitHandle.WaitOne(500,$false); if($wait -and $tcp.Connected) { Write-Host ('    {0,-8} {1,-10} {2}' -f $port,'OPEN',(Get-Service -Port $port)) -ForegroundColor Green; $tcp.Close() } } catch { }" 2>nul
exit /b

:: ============================================
:: NETWORK SCANNER (ARP)
:: ============================================
:tool_network_scan
cls
call :draw_header
echo.
call :color_box "NETWORK SCANNER (ARP)" %COLOR_PRIMARY%
echo.
call :colored_echo "[i]" %COLOR_INFO% "Scanning local network..."
call :loading_animation "Discovering devices"
echo.

echo    Discovered Devices:
echo    IP Address        MAC Address          Vendor
echo    ------------------------------------------------
arp -a | findstr /v "Interface" | findstr "[0-9]"

call :draw_line
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
call :color_box "WHOIS LOOKUP" %COLOR_PRIMARY%
echo.
set /p domain="> Enter domain: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Querying: %domain%"
call :loading_animation "Fetching WHOIS"
echo.

echo    Domain Info:
nslookup %domain% 2>nul | findstr /i "Name:\|Address:"

where curl >nul 2>&1
if %errorlevel%==0 (
    echo.
    call :colored_echo "RDAP Data:" %COLOR_WARNING%
    curl -s "https://rdap.org/domain/%domain%" 2>nul | powershell -Command "$json=ConvertFrom-Json $input; Write-Host ('    Registrar: ' + $json.entities[0].vcardArray[1][1][3]); Write-Host ('    Created: ' + $json.events[0].eventDate); Write-Host ('    Expires: ' + $json.events[1].eventDate)" 2>nul
)

call :draw_line
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
call :color_box "TRACEROUTE TOOL" %COLOR_PRIMARY%
echo.
set /p target="> Enter target (IP/Domain): "
set /p hops="> Max hops (default 30): "
if "%hops%"=="" set hops=30

echo.
call :colored_echo "[i]" %COLOR_INFO% "Tracing route to %target% (max %hops% hops)..."
call :draw_line
echo.

:: Animated traceroute
for /l %%h in (1,1,%hops%) do (
    call :loading_animation "Hop %%h"
    for /f "tokens=*" %%r in ('tracert -d -h %%h %target% 2^>nul ^| findstr /B "%%h"') do (
        echo    %%r
    )
)

echo.
call :draw_line
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
call :color_box "SUBNET CALCULATOR" %COLOR_PRIMARY%
echo.
echo    Enter IP with CIDR (e.g., 192.168.1.0/24)
set /p subnet="> IP/CIDR: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Calculating subnet info..."
call :loading_animation "Computing"
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
    Write-Host ('    Network Address:  ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$networkInt) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString) -ForegroundColor Cyan;
    Write-Host ('    Broadcast:          ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$broadcastInt) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString) -ForegroundColor Cyan;
    Write-Host ('    First Usable:       ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$firstUsable) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString) -ForegroundColor Green;
    Write-Host ('    Last Usable:        ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$lastUsable) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString) -ForegroundColor Green;
    Write-Host ('    Total Hosts:        ' + $hosts) -ForegroundColor Yellow;
    Write-Host ('    Subnet Mask:        ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$mask) | ForEach-Object { $_ } | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString) -ForegroundColor Magenta;
} else { Write-Host '    Invalid format. Use: IP/CIDR (e.g., 192.168.1.0/24)' -ForegroundColor Red }"

call :draw_line
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
call :color_box "WIFI SCANNER" %COLOR_PRIMARY%
echo.
call :colored_echo "[i]" %COLOR_INFO% "Scanning WiFi networks..."
call :loading_animation "Scanning"
echo.

netsh wlan show networks mode=bssid | powershell -Command "$input | ForEach-Object { if ($_.Contains('SSID')) { Write-Host $_ -ForegroundColor Cyan } elseif ($_.Contains('Signal')) { $signal=$_.Substring($_.IndexOf(':')+1).Trim(); if ([int]$signal.Replace('%','') -gt 70) { Write-Host $_ -ForegroundColor Green } elseif ([int]$signal.Replace('%','') -gt 40) { Write-Host $_ -ForegroundColor Yellow } else { Write-Host $_ -ForegroundColor Red } } else { Write-Host $_ } }"

call :draw_line
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
call :color_box "HTTP HEADERS CHECKER" %COLOR_PRIMARY%
echo.
set /p url="> Enter URL (e.g., https://google.com): "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Fetching HTTP headers for: %url%"
call :loading_animation "Connecting"
echo.

where curl >nul 2>&1
if %errorlevel%==0 (
    curl -sI "%url%" 2>nul | powershell -Command "$input | ForEach-Object { if ($_.Contains('HTTP/')) { Write-Host $_ -ForegroundColor Cyan } elseif ($_.Contains('server:') -or $_.Contains('Server:')) { Write-Host $_ -ForegroundColor Green } elseif ($_.Contains('security') -or $_.Contains('Security')) { Write-Host $_ -ForegroundColor Yellow } else { Write-Host $_ } }"
) else (
    call :colored_echo "[!]" %COLOR_DANGER% "curl not found. Cannot fetch headers."
    echo    Install curl or use full URL with http://
)

call :draw_line
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
call :color_box "IP REPUTATION CHECK" %COLOR_PRIMARY%
echo.
set /p ip="> Enter IP to check: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Checking reputation for: %ip%"
call :loading_animation "Querying databases"
echo.

:: Check against AbuseIPDB (requires API key) or use simple ping/nslookup
:: For now, show basic info
ping -n 1 %ip% >nul 2>&1
if %errorlevel%==0 (
    call :colored_echo "[OK]" %COLOR_SUCCESS% "IP is reachable (not blocking ping)"
) else (
    call :colored_echo "[!]" %COLOR_WARNING% "IP not responding to ping (may be blocking)"
)

:: Reverse DNS lookup
nslookup %ip% 2>nul | findstr /i "name:" >nul
if %errorlevel%==0 (
    call :colored_echo "[i]" %COLOR_INFO% "Has PTR record (legitimate server likely)"
) else (
    call :colored_echo "[!]" %COLOR_WARNING% "No PTR record (could be suspicious)"
)

:: Check if private IP
powershell -Command "
$ip='%ip%';
$ipBytes=$ip.Split('.');
if (($ipBytes[0] -eq '10') -or ($ipBytes[0] -eq '192' -and $ipBytes[1] -eq '168') -or ($ipBytes[0] -eq '172' -and [int]$ipBytes[1] -ge 16 -and [int]$ipBytes[1] -le 31)) {
    Write-Host '    [!] PRIVATE IP - Not routable on internet' -ForegroundColor Yellow;
} elseif ($ipBytes[0] -eq '127') {
    Write-Host '    [!] LOOPBACK IP - Localhost' -ForegroundColor Red;
} elseif ($ipBytes[0] -eq '0' -or $ipBytes[0] -eq '255') {
    Write-Host '    [!] RESERVED IP - Invalid for hosts' -ForegroundColor Red;
} else {
    Write-Host '    [OK] PUBLIC IP - Routable on internet' -ForegroundColor Green;
}"

echo.
echo    For detailed threat intel, visit:
echo    - abuseipdb.com/check/%ip%
echo    - virustotal.com/gui/ip-address/%ip%

call :draw_line
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
call :color_box "INTERNET SPEED TEST" %COLOR_PRIMARY%
echo.
call :colored_echo "[i]" %COLOR_INFO% "Testing download speed..."
call :loading_animation "Testing"

:: Use PowerShell to download a test file and measure
powershell -Command "
$url='http://speedtest.tele2.net/10MB.zip';
$size=10MB;
$start=Get-Date;
try {
    $wc=New-Object System.Net.WebClient;
    $data=$wc.DownloadData($url);
    $end=Get-Date;
    $duration=($end-$start).TotalSeconds;
    $speedMbps=($size*8)/$duration/1000000;
    Write-Host ('    Download Speed: ' + [math]::Round($speedMbps,2) + ' Mbps') -ForegroundColor Green;
    Write-Host ('    Duration: ' + [math]::Round($duration,2) + ' seconds') -ForegroundColor Cyan;
    if ($speedMbps -gt 50) { Write-Host '    [Excellent]' -ForegroundColor Green; }
    elseif ($speedMbps -gt 25) { Write-Host '    [Good]' -ForegroundColor Green; }
    elseif ($speedMbps -gt 10) { Write-Host '    [Average]' -ForegroundColor Yellow; }
    else { Write-Host '    [Slow]' -ForegroundColor Red; }
} catch {
    Write-Host '    [!] Speed test failed. Check internet connection.' -ForegroundColor Red;
}"

call :draw_line
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
call :color_box "SYSTEM TOOLS" %COLOR_PRIMARY%
echo.
call :colored_echo "[1]" %COLOR_SUCCESS% "Active Connections (netstat)"
call :colored_echo "[2]" %COLOR_SUCCESS% "Firewall Status"
call :colored_echo "[3]" %COLOR_SUCCESS% "System Information"
call :colored_echo "[4]" %COLOR_SUCCESS% "Process Monitor"
echo.
call :colored_echo "[0]" %COLOR_DANGER% "Back to Main Menu"
echo.
call :draw_line
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
call :color_box "ACTIVE NETWORK CONNECTIONS" %COLOR_PRIMARY%
echo.
netstat -an | findstr "ESTABLISHED LISTENING" | powershell -Command "$input | ForEach-Object { if ($_.Contains('ESTABLISHED')) { Write-Host $_ -ForegroundColor Green } elseif ($_.Contains('LISTENING')) { Write-Host $_ -ForegroundColor Cyan } else { Write-Host $_ } }" | more
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
call :color_box "FIREWALL STATUS" %COLOR_PRIMARY%
echo.
netsh advfirewall show allprofiles | powershell -Command "$input | ForEach-Object { if ($_.Contains('ON')) { Write-Host $_ -ForegroundColor Green } elseif ($_.Contains('OFF')) { Write-Host $_ -ForegroundColor Red } else { Write-Host $_ } }"
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
call :color_box "SYSTEM INFORMATION" %COLOR_PRIMARY%
echo.
powershell -Command "
Write-Host '    Computer Name:  %computername%' -ForegroundColor Cyan;
Write-Host '    User Name:      %username%' -ForegroundColor Cyan;
Write-Host '    OS Version:' -ForegroundColor Cyan;
Get-WmiObject Win32_OperatingSystem | ForEach-Object { Write-Host ('    ' + $_.Caption + ' ' + $_.Version) -ForegroundColor White };
Write-Host '    CPU:' -ForegroundColor Cyan;
Get-WmiObject Win32_Processor | ForEach-Object { Write-Host ('    ' + $_.Name) -ForegroundColor White };
Write-Host '    Memory:' -ForegroundColor Cyan;
$total=Get-WmiObject Win32_ComputerSystem | ForEach-Object { [math]::Round($_.TotalPhysicalMemory/1GB,2) }; Write-Host ('    ' + $total + ' GB') -ForegroundColor White;
Write-Host '    Disk Space:' -ForegroundColor Cyan;
Get-WmiObject Win32_LogicalDisk | ForEach-Object { $free=[math]::Round($_.FreeSpace/1GB,2); $size=[math]::Round($_.Size/1GB,2); $percent=[math]::Round(($free/$size)*100,0); $color='Green'; if ($percent -lt 20) { $color='Red' } elseif ($percent -lt 50) { $color='Yellow' }; Write-Host ('    ' + $_.DeviceID + ' ' + $free + 'GB free / ' + $size + 'GB total (' + $percent + '%)') -ForegroundColor $color };"

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
call :color_box "PROCESS MONITOR" %COLOR_PRIMARY%
echo.
echo    Top Processes by Memory:
echo.
:: Use PowerShell for colorful output
powershell -Command "
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 15 | ForEach-Object {
    $mem=[math]::Round($_.WorkingSet/1MB,1);
    $color='White';
    if ($mem -gt 500) { $color='Red'; }
    elseif ($mem -gt 200) { $color='Yellow'; }
    elseif ($mem -gt 100) { $color='Cyan'; }
    else { $color='Green'; }
    Write-Host ('    {0,-25} {1,10} MB' -f $_.ProcessName,$mem) -ForegroundColor $color
}"
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
call :color_box "SECURITY TOOLS" %COLOR_PRIMARY%
echo.
call :colored_echo "[1]" %COLOR_SUCCESS% "SSL Certificate Checker"
call :colored_echo "[2]" %COLOR_SUCCESS% "Hash Generator (MD5/SHA256)"
call :colored_echo "[3]" %COLOR_SUCCESS% "Password Strength Checker"
call :colored_echo "[4]" %COLOR_SUCCESS% "Base64 Encoder/Decoder"
echo.
call :colored_echo "[0]" %COLOR_DANGER% "Back to Main Menu"
echo.
call :draw_line
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
call :color_box "SSL CERTIFICATE CHECKER" %COLOR_PRIMARY%
echo.
set /p domain="> Enter domain: "

echo.
call :colored_echo "[i]" %COLOR_INFO% "Checking SSL for: %domain%"
call :loading_animation "Connecting via SSL"
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
    Write-Host ('    Valid until: ' + $expiry) -ForegroundColor Green;
    Write-Host ('    Days remaining: ' + $days) -ForegroundColor $(if($days -lt 30){'Red'}elseif($days -lt 90){'Yellow'}else{'Green'});
    Write-Host ('    Issuer: ' + $cert.Issuer) -ForegroundColor Cyan;
    $tcp.Close();
} catch {
    Write-Host '    [!] SSL connection failed' -ForegroundColor Red;
    Write-Host ('    Error: ' + $_.Exception.Message) -ForegroundColor Red;
}"

echo.
call :draw_line
pause
goto security_tools

:: ============================================
:: HASH GENERATOR
:: ============================================
:tool_hash
cls
call :draw_header
echo.
call :color_box "HASH GENERATOR" %COLOR_PRIMARY%
echo.
set /p text="> Enter text to hash: "

echo.
call :colored_echo "MD5:" %COLOR_WARNING%
echo %text% > __temp__.txt
certutil -hashfile __temp__.txt MD5 2>nul | findstr /v "Certutil\|md5"
del __temp__.txt 2>nul

echo.
call :colored_echo "SHA256:" %COLOR_WARNING%
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA256]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('    ' + [BitConverter]::ToString($hash).Replace('-','').ToLower()) -ForegroundColor Cyan"

echo.
call :colored_echo "SHA512:" %COLOR_WARNING%
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA512]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('    ' + [BitConverter]::ToString($hash).Replace('-','').ToLower()) -ForegroundColor Cyan"

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
call :color_box "PASSWORD STRENGTH CHECKER" %COLOR_PRIMARY%
echo.
set /p pass="> Enter password: "

echo.
call :draw_line

set "len=0"
set "has_lower=0"
set "has_upper=0"
set "has_number=0"
set "has_special=0"

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
    call :colored_echo "Strength:" %COLOR_DANGER% "VERY WEAK"
    echo    ^< 8 chars, no complexity
) else if %score%==2 (
    call :colored_echo "Strength:" %COLOR_WARNING% "WEAK"
) else if %score%==3 (
    call :colored_echo "Strength:" %COLOR_WARNING% "MODERATE"
) else if %score%==4 (
    call :colored_echo "Strength:" %COLOR_SUCCESS% "STRONG"
) else (
    call :colored_echo "Strength:" %COLOR_SUCCESS% "VERY STRONG"
    echo    Excellent password!
)

echo.
call :draw_line
pause
goto security_tools

:: ============================================
:: BASE64 TOOL
:: ============================================
:tool_base64
cls
call :draw_header
echo.
call :color_box "BASE64 ENCODER/DECODER" %COLOR_PRIMARY%
echo.
echo    [1] Encode
echo    [2] Decode
echo.
set /p action="> Choose (1/2): "
set /p text="> Enter text: "

echo.
if "%action%"=="1" (
    call :colored_echo "Encoded:" %COLOR_SUCCESS%
    powershell -Command "Write-Host ('    ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%'))) -ForegroundColor Cyan"
) else (
    call :colored_echo "Decoded:" %COLOR_SUCCESS%
    powershell -Command "try { Write-Host ('    ' + [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%'))) -ForegroundColor Cyan } catch { Write-Host '    [!] Invalid Base64' -ForegroundColor Red }"
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
call :color_box "UTILITIES" %COLOR_PRIMARY%
echo.
call :colored_echo "[1]" %COLOR_SUCCESS% "JSON Formatter"
call :colored_echo "[2]" %COLOR_SUCCESS% "URL Encoder/Decoder"
call :colored_echo "[3]" %COLOR_SUCCESS% "JWT Decoder"
echo.
call :colored_echo "[0]" %COLOR_DANGER% "Back to Main Menu"
echo.
call :draw_line
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
call :colored_echo "Paste JSON (single line or press Enter for multiline):" %COLOR_INFO%
set /p jsonin="> "

echo.
call :colored_echo "Formatted:" %COLOR_SUCCESS%
powershell -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 10 | ForEach-Object { Write-Host ('    ' + $_) -ForegroundColor Cyan } } catch { Write-Host '    [!] Invalid JSON' -ForegroundColor Red }"

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
    call :colored_echo "Encoded:" %COLOR_SUCCESS%
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ('    ' + [Web.HttpUtility]::UrlEncode('%text%')) -ForegroundColor Cyan"
) else (
    call :colored_echo "Decoded:" %COLOR_SUCCESS%
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ('    ' + [Web.HttpUtility]::UrlDecode('%text%')) -ForegroundColor Cyan"
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
call :draw_line
call :colored_echo "Decoded JWT:" %COLOR_INFO%
echo.

for /f "delims=. tokens=1,2" %%a in ("%token%") do (
    call :colored_echo "Header:" %COLOR_WARNING%
    powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    ' + [Text.Encoding]::UTF8.GetString($bytes)) -ForegroundColor Cyan } catch { Write-Host '    [!] Error' -ForegroundColor Red }"
    echo.
    call :colored_echo "Payload:" %COLOR_WARNING%
    powershell -Command "try { $b='%%b'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); $json=[Text.Encoding]::UTF8.GetString($bytes); Write-Host ('    ' + $json) -ForegroundColor Cyan; $payload=$json | ConvertFrom-Json; if($payload.exp) { $exp=[datetime]::UnixEpoch.AddSeconds($payload.exp); $days=($exp-(Get-Date)).Days; Write-Host ('    Token expires: ' + $exp + ' (' + $days + ' days)') -ForegroundColor $(if($days -lt 7){'Red'}else{'Green'}) } } catch { Write-Host '    [!] Error' -ForegroundColor Red }"
)

echo.
call :draw_line
pause
goto utilities_menu

:: ============================================
:: USER PROFILE
:: ============================================
:user_profile
cls
call :draw_header
echo.
call :color_box "USER PROFILE" %COLOR_PRIMARY%
echo.
call :colored_echo "Username:" %COLOR_INFO% "%CURRENT_USER%"
call :colored_echo "Status:" %COLOR_SUCCESS% "Logged In"
call :colored_echo "Version:" %COLOR_INFO% "%VERSION%"
call :colored_echo "Theme:" %COLOR_INFO% "%THEME%"
echo.
call :draw_line
echo.
call :colored_echo "Recent Activity:" %COLOR_WARNING%
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
call :color_box "ACTIVITY LOGS" %COLOR_PRIMARY%
echo.
if exist "%LOGS_DIR%\activity.log" (
    type "%LOGS_DIR%\activity.log" 2>nul | more
) else (
    call :colored_echo "[!]" %COLOR_WARNING% "No logs available"
)
echo.
pause
goto main_menu

:: ============================================
:: LOGOUT
:: ============================================
:logout
echo.
call :loading_animation "Logging out"
if exist "%SESSION_FILE%" del "%SESSION_FILE%"
set "CURRENT_USER="
set "IS_LOGGED_IN=0"
call :colored_echo "[OK]" %COLOR_SUCCESS% "Logged out successfully"
timeout /t 1 >nul
goto main_menu

:: ============================================
:: CHECK FOR UPDATES
:: ============================================
:check_updates
cls
call :draw_header
echo.
call :color_box "UPDATE CHECKER" %COLOR_PRIMARY%
echo.
call :colored_echo "Current Version:" %COLOR_INFO% "%VERSION%"
echo.
call :colored_echo "[i]" %COLOR_INFO% "Checking for updates..."

where curl >nul 2>&1
if %errorlevel%==0 (
    call :loading_animation "Connecting"
    curl -sL "%UPDATE_URL%" > "%UPDATE_DIR%\latest.txt" 2>nul
    if exist "%UPDATE_DIR%\latest.txt" (
        set /p LATEST_VERSION=<"%UPDATE_DIR%\latest.txt"
        if "!LATEST_VERSION!"=="%VERSION%" (
            echo.
            call :colored_echo "[OK]" %COLOR_SUCCESS% "You are running the latest version!"
        ) else (
            echo.
            call :colored_echo "[!]" %COLOR_WARNING% "New version available: !LATEST_VERSION!"
            echo.
            echo    Would you like to download the update?
            set /p update_choice="> (Y/N): "
            if /i "!update_choice!"=="Y" (
                call :colored_echo "[i]" %COLOR_INFO% "Opening download page..."
                start https://github.com/kickxly-dev/trumav2/releases
            )
        )
        del "%UPDATE_DIR%\latest.txt" 2>nul
    ) else (
        call :colored_echo "[!]" %COLOR_DANGER% "Could not check for updates"
    )
) else (
    call :colored_echo "[!]" %COLOR_DANGER% "curl not found. Cannot check for updates."
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
call :colored_echo "Thank you for using TRUMA!" %COLOR_SUCCESS%
echo    Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0

:: ============================================
:: HELPER FUNCTIONS
:: ============================================
:apply_theme
if "%THEME%"=="CRIMSON" (
    set "COLOR_PRIMARY=Red"
    set "COLOR_SUCCESS=Green"
    set "COLOR_WARNING=Yellow"
    set "COLOR_DANGER=Red"
    set "COLOR_INFO=Cyan"
    color 0C
) else if "%THEME%"=="CYBER" (
    set "COLOR_PRIMARY=Cyan"
    set "COLOR_SUCCESS=Green"
    set "COLOR_WARNING=Yellow"
    set "COLOR_DANGER=Red"
    set "COLOR_INFO=Blue"
    color 0B
) else if "%THEME%"=="MATRIX" (
    set "COLOR_PRIMARY=Green"
    set "COLOR_SUCCESS=Green"
    set "COLOR_WARNING=Yellow"
    set "COLOR_DANGER=Red"
    set "COLOR_INFO=Green"
    color 0A
) else if "%THEME%"=="GOLD" (
    set "COLOR_PRIMARY=Yellow"
    set "COLOR_SUCCESS=Green"
    set "COLOR_WARNING=Yellow"
    set "COLOR_DANGER=Red"
    set "COLOR_INFO=Cyan"
    color 0E
) else if "%THEME%"=="DARK" (
    set "COLOR_PRIMARY=White"
    set "COLOR_SUCCESS=Green"
    set "COLOR_WARNING=Yellow"
    set "COLOR_DANGER=Red"
    set "COLOR_INFO=Gray"
    color 0F
)
goto :eof

:draw_header
echo.
echo     ████████╗██████╗ ██╗   ██╗███╗   ███╗ █████╗
echo     ╚══██╔══╝██╔══██╗██║   ██║████╗ ████║██╔══██╗
echo        ██║   ██████╔╝██║   ██║██╔████╔██║███████║
echo        ██║   ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║
echo        ██║   ██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║
echo        ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝
echo     ═══════════════════════════════════════════════
echo           Advanced Network Security v%VERSION%
echo.
goto :eof

:color_box
echo    +==============================================================+
echo    ^|  %~1                                                          ^|
echo    +==============================================================+
goto :eof

:draw_line
echo    ═══════════════════════════════════════════════════════════════
goto :eof

:colored_echo
:: %1 = prefix/icon, %2 = color, %3 = text
powershell -Command "Write-Host ('    %~1 %~3') -ForegroundColor %~2"
goto :eof

:loading_animation
set "msg=%~1"
for /l %%i in (1,1,3) do (
    cls
    call :draw_header
    echo.
    echo    %msg%...
    timeout /t 1 >nul
)
goto :eof

:save_report
:: Ask if user wants to save report
set "report_data=%~1"
echo.
echo    Save this report to file? (Y/N)
set /p save_choice="> "
if /i "%save_choice%"=="Y" (
    set "report_file=%REPORTS_DIR%\report_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.txt"
    set "report_file=!report_file: =0!"
    echo TRUMA Security Report > "!report_file!"
    echo Date: %date% %time% >> "!report_file!"
    echo ====================================== >> "!report_file!"
    echo %report_data% >> "!report_file!"
    call :colored_echo "[OK]" %COLOR_SUCCESS% "Report saved to: !report_file!"
)
goto :eof

:log_activity
echo [%date% %time%] %~1 >> "%LOGS_DIR%\activity.log"
if "%IS_LOGGED_IN%"=="1" (
    echo [%date% %time%] %~1 >> "%LOGS_DIR%\%CURRENT_USER%.log"
)
goto :eof
