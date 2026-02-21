@echo off
setlocal enabledelayedexpansion
title TRUMA - Advanced Network Security Suite v2.0

:: Version
set "VERSION=2.0"

:: Initialize paths
set "TRUMA_HOME=%~dp0"
set "DATA_DIR=%TRUMA_HOME%data"
set "LOGS_DIR=%TRUMA_HOME%logs"
set "USERS_FILE=%DATA_DIR%\users.db"
set "SESSION_FILE=%DATA_DIR%\session.tmp"

:: Create directories
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

:: Theme
set "THEME=CRIMSON"
color 0C

:: Initialize session
set "CURRENT_USER="
set "IS_LOGGED_IN=0"

:: Check for existing session
if exist "%SESSION_FILE%" (
    set /p CURRENT_USER=<"%SESSION_FILE%"
    if not "!CURRENT_USER!"=="" set "IS_LOGGED_IN=1"
)

:: Main Menu
:main_menu
cls
echo.
echo     TTTTT RRRR  U   U M   M  AAA
echo       T   R   R U   U MM MM A   A
echo       T   RRRR  U   U M M M AAAAA
echo       T   R  R  U   U M   M A   A
echo       T   R   R  UUU  M   M A   A
echo     ===================================
echo       Advanced Network Security v%VERSION%
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

:theme_menu
cls
echo.
echo     THEME SETTINGS
echo     ==============
echo.
echo    [1] CRIMSON (Red)
echo    [2] CYBER (Blue)  
echo    [3] MATRIX (Green)
echo    [4] GOLD (Yellow)
echo    [5] DARK (Gray)
echo.
echo    [0] Back
echo.
set /p theme_choice="> Select theme: "

if "%theme_choice%"=="1" set "THEME=CRIMSON" & color 0C
if "%theme_choice%"=="2" set "THEME=CYBER" & color 0B
if "%theme_choice%"=="3" set "THEME=MATRIX" & color 0A
if "%theme_choice%"=="4" set "THEME=GOLD" & color 0E
if "%theme_choice%"=="5" set "THEME=DARK" & color 0F
if "%theme_choice%"=="0" goto main_menu

echo.
echo    Theme applied: %THEME%
pause
goto main_menu

:login
cls
echo.
echo     USER LOGIN
echo     ==========
echo.
set /p username="> Username: "
set /p password="> Password: "

if not exist "%USERS_FILE%" (
    echo.
    echo    [!] No users found. Please sign up first.
    pause
    goto main_menu
)

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
    timeout /t 2 >nul
    goto main_menu
) else (
    echo.
    echo    [!] Invalid username or password
    pause
    goto main_menu
)

:signup
cls
echo.
echo     CREATE ACCOUNT
echo     ==============
echo.
set /p newuser="> Choose username: "
set /p newpass="> Choose password: "
set /p confpass="> Confirm password: "

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

if exist "%USERS_FILE%" (
    findstr /B "%newuser%:" "%USERS_FILE%" >nul
    if %errorlevel%==0 (
        echo    [!] Username already exists
        pause
        goto signup
    )
)

echo %newuser%:%newpass%>>"%USERS_FILE%"
echo.
echo    [OK] Account created successfully!
set "CURRENT_USER=%newuser%"
set "IS_LOGGED_IN=1"
echo %newuser%>%SESSION_FILE%
timeout /t 2 >nul
goto main_menu

:guest_access
set "CURRENT_USER=Guest"

:network_tools
cls
echo.
echo     NETWORK TOOLS
echo     =============
echo.
echo    [1] IP Information Lookup     [7] Traceroute
    echo    [2] Ping / Latency Tester     [8] Subnet Calculator
    echo    [3] DNS Lookup Tool            [9] WiFi Scanner
    echo    [4] Port Scanner               [10] HTTP Headers
    echo    [5] Network Scanner (ARP)      [11] IP Reputation
    echo    [6] WHOIS Lookup               [12] Speed Test
    echo    [0] Back to Main Menu
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

:tool_ip_lookup
cls
echo.
echo     IP INFORMATION LOOKUP
set /p target="> Enter IP or Domain: "
echo.
echo    [i] Looking up: %target%
ping -n 1 %target% >nul 2>&1
if %errorlevel%==0 (
    echo    [OK] Host is reachable
) else (
    echo    [!] Host may be unreachable
)
ipconfig | findstr /i "ipv4"
pause
goto network_tools

:tool_ping
cls
echo.
echo     PING / LATENCY TESTER
set /p target="> Enter target: "
set /p count="> Packets (default 4): "
if "%count%"=="" set count=4
echo.
ping -n %count% %target%
pause
goto network_tools

:tool_dns
cls
echo.
echo     DNS LOOKUP TOOL
set /p domain="> Enter domain: "
echo.
echo    A Records:
nslookup -type=A %domain% 2>nul | findstr /B "Address" | findstr /v "#"
echo.
echo    NS Records:
nslookup -type=NS %domain% 2>nul | findstr "nameserver"
echo.
echo    MX Records:
nslookup -type=MX %domain% 2>nul | findstr "mail"
pause
goto network_tools

:tool_port_scan
cls
echo.
echo     PORT SCANNER
echo    Common: 21(FTP) 22(SSH) 80(HTTP) 443(HTTPS)
set /p target="> Target IP: "
set /p ports="> Ports (e.g., 80,443): "
echo.
echo    Scanning... (please wait)
powershell -NoProfile -Command "$t='%target%'; $ports='%ports%' -split ','; foreach ($p in $ports) { $port=$p.Trim(); if ($port -match '^\d+$') { try { $tcp=New-Object Net.Sockets.TcpClient; $c=$tcp.BeginConnect($t,[int]$port,$null,$null); $w=$c.AsyncWaitHandle.WaitOne(500,$false); if($w -and $tcp.Connected) { Write-Host ('    ' + $port + ' OPEN'); $tcp.Close() } else { Write-Host ('    ' + $port + ' closed') } } catch { } } }"
pause
goto network_tools

:tool_network_scan
cls
echo.
echo     NETWORK SCANNER (ARP)
echo    [i] Scanning local network...
arp -a | findstr /v "Interface"
pause
goto network_tools

:tool_whois
cls
echo.
echo     WHOIS LOOKUP
set /p domain="> Enter domain: "
echo.
nslookup %domain% 2>nul | findstr /i "Name:\|Address:"
where curl >nul 2>&1
if %errorlevel%==0 (
    echo.
    echo    RDAP Data:
    curl -s "https://rdap.org/domain/%domain%" 2>nul | findstr "ldhName" | head -2
)
pause
goto network_tools

:tool_traceroute
cls
echo.
echo     TRACEROUTE TOOL
set /p target="> Enter target: "
set /p hops="> Max hops (default 30): "
if "%hops%"=="" set hops=30
echo.
tracert -d -h %hops% %target%
pause
goto network_tools

:tool_subnet
cls
echo.
echo     SUBNET CALCULATOR
echo    Enter IP/CIDR (e.g., 192.168.1.0/24)
set /p subnet="> IP/CIDR: "
echo.
powershell -NoProfile -Command "$input='%subnet%'; if ($input -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { $ip=$matches[1]; $cidr=[int]$matches[2]; $mask=[uint32]([math]::Pow(2,32)-[math]::Pow(2,32-$cidr)); $ipBytes=$ip.Split('.'); $ipInt=([uint32]$ipBytes[0]*16777216)+([uint32]$ipBytes[1]*65536)+([uint32]$ipBytes[2]*256)+[uint32]$ipBytes[3]; $networkInt=$ipInt -band $mask; $broadcastInt=$networkInt -bor ([uint32]([math]::Pow(2,32-$cidr)-1)); $hosts=[math]::Pow(2,32-$cidr)-2; Write-Host ('    Network: ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$networkInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString); Write-Host ('    Broadcast: ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$broadcastInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString); Write-Host ('    Hosts: ' + $hosts); } else { Write-Host '    Invalid format' }"
pause
goto network_tools

:tool_wifi
cls
echo.
echo     WIFI SCANNER
netsh wlan show networks mode=bssid
pause
goto network_tools

:tool_http_headers
cls
echo.
echo     HTTP HEADERS CHECKER
set /p url="> Enter URL: "
echo.
where curl >nul 2>&1
if %errorlevel%==0 (
    curl -sI "%url%" 2>nul
) else (
    echo    [!] curl not found
)
pause
goto network_tools

:tool_ip_reputation
cls
echo.
echo     IP REPUTATION CHECK
set /p ip="> Enter IP: "
echo.
ping -n 1 %ip% >nul 2>&1
if %errorlevel%==0 (echo    [OK] IP reachable) else (echo    [!] IP not responding)
nslookup %ip% 2>nul | findstr /i "name:" >nul
if %errorlevel%==0 (echo    [OK] Has PTR record) else (echo    [!] No PTR record)
echo.
echo    Check online:
echo    - abuseipdb.com/check/%ip%
echo    - virustotal.com/gui/ip-address/%ip%
pause
goto network_tools

:tool_speedtest
cls
echo.
echo     INTERNET SPEED TEST
echo    [i] Downloading 10MB test file...
powershell -NoProfile -Command "$url='http://speedtest.tele2.net/10MB.zip'; $sizeMB=10; $start=Get-Date; try { $wc=New-Object System.Net.WebClient; $data=$wc.DownloadData($url); $end=Get-Date; $duration=($end-$start).TotalSeconds; $speedMbps=($sizeMB*8)/$duration; Write-Host ('    Speed: ' + [math]::Round($speedMbps,2) + ' Mbps'); Write-Host ('    Duration: ' + [math]::Round($duration,2) + ' sec'); } catch { Write-Host '    [!] Failed'; }"
pause
goto network_tools

:system_tools
cls
echo.
echo     SYSTEM TOOLS
echo    [1] Active Connections
echo    [2] Firewall Status
echo    [3] System Information
echo    [4] Process Monitor
echo    [0] Back
echo.
set /p choice="> Enter choice: "
if "%choice%"=="1" netstat -an | findstr "ESTABLISHED LISTENING" | more & pause & goto system_tools
if "%choice%"=="2" netsh advfirewall show allprofiles & pause & goto system_tools
if "%choice%"=="3" echo Computer: %computername% & ver & ipconfig | findstr /i "ipv4" & wmic cpu get name /value 2>nul | findstr "=" & wmic ComputerSystem get TotalPhysicalMemory /value 2>nul | findstr "=" & pause & goto system_tools
if "%choice%"=="4" tasklist | sort /+58 | more +3 & pause & goto system_tools
if "%choice%"=="0" goto main_menu
goto system_tools

:security_tools
cls
echo.
echo     SECURITY TOOLS
echo    [1] SSL Certificate Checker
echo    [2] Hash Generator
echo    [3] Password Strength
echo    [4] Base64 Encoder
echo    [0] Back
echo.
set /p choice="> Enter choice: "
if "%choice%"=="1" goto tool_ssl
if "%choice%"=="2" goto tool_hash
if "%choice%"=="3" goto tool_password
if "%choice%"=="4" goto tool_base64
if "%choice%"=="0" goto main_menu
goto security_tools

:tool_ssl
cls
echo.
echo     SSL CERTIFICATE CHECKER
set /p domain="> Enter domain: "
echo.
powershell -NoProfile -Command "try { $tcp=New-Object Net.Sockets.TcpClient('%domain%',443); $stream=$tcp.GetStream(); $ssl=New-Object Net.Security.SslStream($stream); $ssl.AuthenticateAsClient('%domain%'); $cert=$ssl.RemoteCertificate; Write-Host ('    Valid until: ' + $cert.GetExpirationDateString()); $tcp.Close(); } catch { Write-Host '    [!] SSL failed'; }"
pause
goto security_tools

:tool_hash
cls
echo.
echo     HASH GENERATOR
set /p text="> Enter text: "
echo.
echo    MD5:
echo %text% > __t__.txt
certutil -hashfile __t__.txt MD5 2>nul | findstr /v "Certutil\|md5"
del __t__.txt 2>nul
echo.
echo    SHA256:
powershell -NoProfile -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA256]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('    ' + [BitConverter]::ToString($hash).Replace('-','').ToLower())"
pause
goto security_tools

:tool_password
cls
echo.
echo     PASSWORD STRENGTH CHECKER
set /p pass="> Enter password: "
echo.
set "len=0"
for /l %%i in (0,1,100) do (if not "!pass:~%%i,1!"=="" set /a len+=1)
echo    Length: %len%
if %len% lss 8 (echo    Strength: WEAK) else if %len% lss 12 (echo    Strength: MODERATE) else (echo    Strength: STRONG)
pause
goto security_tools

:tool_base64
cls
echo.
echo     BASE64 ENCODER/DECODER
echo    [1] Encode
echo    [2] Decode
echo.
set /p action="> Choice: "
set /p text="> Text: "
echo.
if "%action%"=="1" (
    echo    Encoded:
    powershell -NoProfile -Command "Write-Host ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%')))"
) else (
    echo    Decoded:
    powershell -NoProfile -Command "try { Write-Host ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%'))) } catch { Write-Host '    [!] Invalid' }"
)
pause
goto security_tools

:utilities_menu
cls
echo.
echo     UTILITIES
echo    [1] JSON Formatter
echo    [2] URL Encoder/Decoder
echo    [3] JWT Decoder
echo    [0] Back
echo.
set /p choice="> Choice: "
if "%choice%"=="1" goto tool_json
if "%choice%"=="2" goto tool_url
if "%choice%"=="3" goto tool_jwt
if "%choice%"=="0" goto main_menu
goto utilities_menu

:tool_json
echo.
echo     JSON FORMATTER
set /p jsonin="> Paste JSON: "
echo.
powershell -NoProfile -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 10 } catch { Write-Host '    [!] Invalid JSON' }"
pause
goto utilities_menu

:tool_url
echo.
echo     URL ENCODER/DECODER
echo    [1] Encode
echo    [2] Decode
echo.
set /p action="> Choice: "
set /p text="> Text: "
echo.
if "%action%"=="1" (
    powershell -NoProfile -Command "Add-Type -AssemblyName System.Web; Write-Host ([Web.HttpUtility]::UrlEncode('%text%'))"
) else (
    powershell -NoProfile -Command "Add-Type -AssemblyName System.Web; Write-Host ([Web.HttpUtility]::UrlDecode('%text%'))"
)
pause
goto utilities_menu

:tool_jwt
echo.
echo     JWT DECODER
set /p token="> Paste JWT: "
echo.
echo    Header:
for /f "delims=. tokens=1" %%a in ("%token%") do powershell -NoProfile -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    ' + [Text.Encoding]::UTF8.GetString($bytes)) } catch { }"
echo.
echo    Payload:
for /f "delims=. tokens=2" %%a in ("%token%") do powershell -NoProfile -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('    ' + [Text.Encoding]::UTF8.GetString($bytes)) } catch { }"
pause
goto utilities_menu

:user_profile
cls
echo.
echo     USER PROFILE
echo    Username: %CURRENT_USER%
echo    Version: %VERSION%
echo    Theme: %THEME%
echo.
if exist "%LOGS_DIR%\%CURRENT_USER%.log" (
    echo    Recent Activity:
    type "%LOGS_DIR%\%CURRENT_USER%.log" 2>nul | more +0
) else (
    echo    No activity yet
)
pause
goto main_menu

:view_logs
cls
echo.
echo     ACTIVITY LOGS
if exist "%LOGS_DIR%\activity.log" (
    type "%LOGS_DIR%\activity.log" 2>nul | more
) else (
    echo    No logs available
)
pause
goto main_menu

:logout
echo.
echo    Logging out...
if exist "%SESSION_FILE%" del "%SESSION_FILE%"
set "CURRENT_USER="
set "IS_LOGGED_IN=0"
echo    [OK] Logged out
timeout /t 1 >nul
goto main_menu

:check_updates
cls
echo.
echo     UPDATE CHECKER
echo    Current Version: %VERSION%
echo.
where curl >nul 2>&1
if %errorlevel%==0 (
    echo    [i] Checking...
    curl -sL "https://raw.githubusercontent.com/kickxly-dev/trumav2/master/TRUMA-CLI/version.txt" > "%TEMP%\truma_ver.txt" 2>nul
    if exist "%TEMP%\truma_ver.txt" (
        set /p LATEST=<"%TEMP%\truma_ver.txt"
        if "!LATEST!"=="%VERSION%" (
            echo    [OK] Latest version!
        ) else (
            echo    [!] New version: !LATEST!
            echo    Visit: github.com/kickxly-dev/trumav2/releases
        )
        del "%TEMP%\truma_ver.txt" 2>nul
    ) else (
        echo    [!] Check failed
    )
) else (
    echo    [!] curl not found
    echo    Visit: github.com/kickxly-dev/trumav2/releases
)
pause
goto main_menu

:exit_truma
cls
echo.
echo     Thank you for using TRUMA!
echo     Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0
