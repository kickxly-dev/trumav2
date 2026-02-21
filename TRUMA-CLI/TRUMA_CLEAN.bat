@echo off
setlocal enabledelayedexpansion
title TRUMA Network Security Suite v2.0

set VERSION=2.0
set TRUMA_HOME=%~dp0
set DATA_DIR=%TRUMA_HOME%data
set LOGS_DIR=%TRUMA_HOME%logs
set USERS_FILE=%DATA_DIR%\users.db
set SESSION_FILE=%DATA_DIR%\session.tmp

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"

set THEME=CRIMSON
color 0C

set CURRENT_USER=
set IS_LOGGED_IN=0

if exist "%SESSION_FILE%" (
    set /p CURRENT_USER=<"%SESSION_FILE%"
    if not "!CURRENT_USER!"=="" set IS_LOGGED_IN=1
)

:main_menu
cls
echo.
echo  TRUMA Network Security Suite v%VERSION%
echo  ======================================
echo.

if %IS_LOGGED_IN%==1 (
    echo  [1] Network Tools    [5] My Profile
    echo  [2] System Tools     [6] View Logs
    echo  [3] Security Tools   [7] Logout
    echo  [4] Utilities        [U] Updates
    echo.
    echo  [0] Exit             User: %CURRENT_USER%
) else (
    echo  Welcome to TRUMA
    echo.
    echo  [1] Login            [U] Updates
    echo  [2] Sign Up
    echo  [3] Guest Access
    echo.
    echo  [0] Exit
)

echo.
set /p choice=Choice: 

if %IS_LOGGED_IN%==1 (
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

:login
cls
echo.
echo  USER LOGIN
echo  ==========
echo.
set /p username=Username: 
set /p password=Password: 

if not exist "%USERS_FILE%" (
    echo.
    echo  No users found. Please sign up first.
    pause
    goto main_menu
)

set found=0
for /f "tokens=1,2 delims=:" %%a in ('type "%USERS_FILE%"') do (
    if "%%a"=="%username%" (
        if "%%b"=="%password%" (
            set found=1
            set CURRENT_USER=%username%
        )
    )
)

if %found%==1 (
    set IS_LOGGED_IN=1
    echo %CURRENT_USER%>%SESSION_FILE%
    echo.
    echo  Login successful! Welcome back, %CURRENT_USER%
    call :log_activity "User logged in: %CURRENT_USER%"
    pause
    goto main_menu
) else (
    echo.
    echo  Invalid username or password
    pause
    goto main_menu
)

:signup
cls
echo.
echo  CREATE ACCOUNT
echo  ==============
echo.
set /p newuser=Choose username: 
set /p newpass=Choose password: 
set /p confpass=Confirm password: 

if "%newuser%"=="" (
    echo Username cannot be empty
    pause
    goto signup
)

if not "%newpass%"=="%confpass%" (
    echo Passwords do not match
    pause
    goto signup
)

if exist "%USERS_FILE%" (
    findstr /B "%newuser%:" "%USERS_FILE%" >nul
    if %errorlevel%==0 (
        echo Username already exists
        pause
        goto signup
    )
)

echo %newuser%:%newpass%>>"%USERS_FILE%"
echo.
echo Account created successfully!
call :log_activity "New user registered: %newuser%"
set CURRENT_USER=%newuser%
set IS_LOGGED_IN=1
echo %newuser%>%SESSION_FILE%
pause
goto main_menu

:guest_access
set CURRENT_USER=Guest
set IS_LOGGED_IN=1
call :log_activity "Guest login"

:network_tools
cls
echo.
echo  NETWORK TOOLS
echo  =============
echo.
echo  [1] IP Lookup
    echo  [2] Ping Test
    echo  [3] DNS Lookup
    echo  [4] Port Scanner
    echo  [5] ARP Scanner
    echo  [6] WHOIS Lookup
    echo  [7] Traceroute
    echo  [8] Subnet Calc
    echo  [9] WiFi Scanner
    echo  [10] HTTP Headers
    echo  [11] IP Reputation
    echo  [12] Speed Test
    echo  [0] Back
    echo.
    set /p choice=Choice: 

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
echo  IP INFORMATION LOOKUP
set /p target=Enter IP or Domain: 
echo.
echo  Looking up: %target%
ping -n 1 %target% >nul 2>&1
if %errorlevel%==0 (
    echo  Host is reachable
) else (
    echo  Host may be unreachable
)
ipconfig | findstr /i "ipv4"
call :log_activity "IP Lookup: %target%"
pause
goto network_tools

:tool_ping
cls
echo.
echo  PING TEST
set /p target=Enter target: 
set /p count=Packets (default 4): 
if "%count%"=="" set count=4
echo.
ping -n %count% %target%
call :log_activity "Ping: %target% (%count% packets)"
pause
goto network_tools

:tool_dns
cls
echo.
echo  DNS LOOKUP
set /p domain=Enter domain: 
echo.
echo  A Records:
nslookup -type=A %domain% 2>nul | findstr /B "Address" | findstr /v "#"
echo.
echo  NS Records:
nslookup -type=NS %domain% 2>nul | findstr "nameserver"
echo.
echo  MX Records:
nslookup -type=MX %domain% 2>nul | findstr "mail"
call :log_activity "DNS Lookup: %domain%"
pause
goto network_tools

:tool_port_scan
cls
echo.
echo  PORT SCANNER
set /p target=Target IP: 
set /p ports=Ports (e.g., 80,443): 
echo.
echo  Scanning... (please wait)
powershell -Command "$t='%target%'; $p='%ports%' -split ','; foreach ($port in $p) { $port=$port.Trim(); if ($port -match '^\d+$') { try { $tcp=New-Object Net.Sockets.TcpClient; $c=$tcp.BeginConnect($t,[int]$port,$null,$null); $w=$c.AsyncWaitHandle.WaitOne(500,$false); if($w -and $tcp.Connected) { Write-Host ('  ' + $port + ' OPEN'); $tcp.Close() } else { Write-Host ('  ' + $port + ' closed') } } catch { } } }"
call :log_activity "Port scan: %target% (%ports%)"
pause
goto network_tools

:tool_network_scan
cls
echo.
echo  NETWORK SCANNER (ARP)
echo  Scanning local network...
arp -a | findstr /v "Interface"
call :log_activity "Network ARP scan"
pause
goto network_tools

:tool_whois
cls
echo.
echo  WHOIS LOOKUP
set /p domain=Enter domain: 
echo.
nslookup %domain% 2>nul | findstr /i "Name:"
where curl >nul 2>&1
if %errorlevel%==0 (
    echo.
    echo  RDAP Data:
    curl -s "https://rdap.org/domain/%domain%" 2>nul
)
call :log_activity "WHOIS: %domain%"
pause
goto network_tools

:tool_traceroute
cls
echo.
echo  TRACEROUTE
set /p target=Enter target: 
set /p hops=Max hops (default 30): 
if "%hops%"=="" set hops=30
echo.
tracert -d -h %hops% %target%
call :log_activity "Traceroute: %target% (%hops% hops)"
pause
goto network_tools

:tool_subnet
cls
echo.
echo  SUBNET CALCULATOR
echo  Enter IP/CIDR (e.g., 192.168.1.0/24)
set /p subnet=IP/CIDR: 
echo.
powershell -Command "$input='%subnet%'; if ($input -match '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') { $ip=$matches[1]; $cidr=[int]$matches[2]; $mask=[uint32]([math]::Pow(2,32)-[math]::Pow(2,32-$cidr)); $ipBytes=$ip.Split('.'); $ipInt=([uint32]$ipBytes[0]*16777216)+([uint32]$ipBytes[1]*65536)+([uint32]$ipBytes[2]*256)+[uint32]$ipBytes[3]; $networkInt=$ipInt -band $mask; $broadcastInt=$networkInt -bor ([uint32]([math]::Pow(2,32-$cidr)-1)); $hosts=[math]::Pow(2,32-$cidr)-2; Write-Host ('  Network: ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$networkInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString); Write-Host ('  Broadcast: ' + ([IPAddress]([BitConverter]::GetBytes([uint32]$broadcastInt) | ForEach-Object { [int]$_ } | ForEach-Object { [string]$_ } -join '.')).IPAddressToString); Write-Host ('  Hosts: ' + $hosts); } else { Write-Host '  Invalid format' }"
call :log_activity "Subnet calc: %subnet%"
pause
goto network_tools

:tool_wifi
cls
echo.
echo  WIFI SCANNER
netsh wlan show networks mode=bssid
call :log_activity "WiFi scan"
pause
goto network_tools

:tool_http_headers
cls
echo.
echo  HTTP HEADERS CHECKER
set /p url=Enter URL: 
echo.
where curl >nul 2>&1
if %errorlevel%==0 (
    curl -sI "%url%" 2>nul
) else (
    echo  curl not found
)
call :log_activity "HTTP Headers: %url%"
pause
goto network_tools

:tool_ip_reputation
cls
echo.
echo  IP REPUTATION CHECK
set /p ip=Enter IP: 
echo.
ping -n 1 %ip% >nul 2>&1
if %errorlevel%==0 (echo  IP reachable) else (echo  IP not responding)
nslookup %ip% 2>nul | findstr /i "name:" >nul
if %errorlevel%==0 (echo  Has PTR record) else (echo  No PTR record)
echo.
echo  Check online:
echo  - abuseipdb.com/check/%ip%
echo  - virustotal.com/gui/ip-address/%ip%
call :log_activity "IP Reputation: %ip%"
pause
goto network_tools

:tool_speedtest
cls
echo.
echo  INTERNET SPEED TEST
echo  Downloading 10MB test file...
powershell -Command "$url='http://speedtest.tele2.net/10MB.zip'; $sizeMB=10; $start=Get-Date; try { $wc=New-Object System.Net.WebClient; $data=$wc.DownloadData($url); $end=Get-Date; $duration=($end-$start).TotalSeconds; $speedMbps=($sizeMB*8)/$duration; Write-Host ('  Speed: ' + [math]::Round($speedMbps,2) + ' Mbps'); } catch { Write-Host '  Speed test failed'; }"
call :log_activity "Speed test completed"
pause
goto network_tools

:system_tools
cls
echo.
echo  SYSTEM TOOLS
echo  [1] Active Connections
echo  [2] Firewall Status
echo  [3] System Information
echo  [4] Process Monitor
echo  [0] Back
echo.
set /p choice=Choice: 
if "%choice%"=="1" (
    netstat -an | findstr "ESTABLISHED LISTENING" | more
    call :log_activity "Viewed active connections"
    pause
    goto system_tools
)
if "%choice%"=="2" (
    netsh advfirewall show allprofiles
    call :log_activity "Viewed firewall status"
    pause
    goto system_tools
)
if "%choice%"=="3" (
    echo Computer: %computername%
    ver
    ipconfig | findstr /i "ipv4"
    wmic cpu get name /value 2>nul | findstr "="
    wmic ComputerSystem get TotalPhysicalMemory /value 2>nul | findstr "="
    call :log_activity "Viewed system info"
    pause
    goto system_tools
)
if "%choice%"=="4" (
    tasklist | sort /+58 | more +3
    call :log_activity "Viewed process monitor"
    pause
    goto system_tools
)
if "%choice%"=="0" goto main_menu
goto system_tools

:security_tools
cls
echo.
echo  SECURITY TOOLS
echo  [1] SSL Certificate Checker
echo  [2] Hash Generator
echo  [3] Password Strength
echo  [4] Base64 Encoder
echo  [0] Back
echo.
set /p choice=Choice: 
if "%choice%"=="1" goto tool_ssl
if "%choice%"=="2" goto tool_hash
if "%choice%"=="3" goto tool_password
if "%choice%"=="4" goto tool_base64
if "%choice%"=="0" goto main_menu
goto security_tools

:tool_ssl
cls
echo.
echo  SSL CERTIFICATE CHECKER
set /p domain=Enter domain: 
echo.
powershell -Command "try { $tcp=New-Object Net.Sockets.TcpClient('%domain%',443); $stream=$tcp.GetStream(); $ssl=New-Object Net.Security.SslStream($stream); $ssl.AuthenticateAsClient('%domain%'); $cert=$ssl.RemoteCertificate; Write-Host ('  Valid until: ' + $cert.GetExpirationDateString()); $tcp.Close(); } catch { Write-Host '  SSL failed'; }"
call :log_activity "SSL check: %domain%"
pause
goto security_tools

:tool_hash
cls
echo.
echo  HASH GENERATOR
set /p text=Enter text: 
echo.
echo  MD5:
echo %text% > __temp.txt
certutil -hashfile __temp.txt MD5 2>nul | findstr /v "Certutil"
del __temp.txt 2>nul
echo.
echo  SHA256:
powershell -Command "$bytes=[Text.Encoding]::UTF8.GetBytes('%text%'); $sha=[Security.Cryptography.SHA256]::Create(); $hash=$sha.ComputeHash($bytes); Write-Host ('  ' + [BitConverter]::ToString($hash).Replace('-','').ToLower())"
call :log_activity "Hash generated"
pause
goto security_tools

:tool_password
cls
echo.
echo  PASSWORD STRENGTH CHECKER
set /p pass=Enter password: 
echo.
set len=0
for /l %%i in (0,1,100) do (
    if not "!pass:~%%i,1!"=="" set /a len+=1
)
echo  Length: %len%
if %len% lss 8 (
    echo  Strength: WEAK
) else if %len% lss 12 (
    echo  Strength: MODERATE
) else (
    echo  Strength: STRONG
)
call :log_activity "Password strength checked"
pause
goto security_tools

:tool_base64
cls
echo.
echo  BASE64 ENCODER/DECODER
echo  [1] Encode
echo  [2] Decode
echo.
set /p action=Choice: 
set /p text=Text: 
echo.
if "%action%"=="1" (
    echo  Encoded:
    powershell -Command "Write-Host ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('%text%')))"
) else (
    echo  Decoded:
    powershell -Command "try { Write-Host ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%text%'))) } catch { Write-Host '  Invalid' }"
)
call :log_activity "Base64 operation"
pause
goto security_tools

:utilities_menu
cls
echo.
echo  UTILITIES
echo  [1] JSON Formatter
echo  [2] URL Encoder/Decoder
echo  [3] JWT Decoder
echo  [0] Back
echo.
set /p choice=Choice: 
if "%choice%"=="1" goto tool_json
if "%choice%"=="2" goto tool_url
if "%choice%"=="3" goto tool_jwt
if "%choice%"=="0" goto main_menu
goto utilities_menu

:tool_json
echo.
echo  JSON FORMATTER
set /p jsonin=Paste JSON: 
echo.
powershell -Command "try { $j=ConvertFrom-Json '%jsonin%'; ConvertTo-Json $j -Depth 10 } catch { Write-Host '  Invalid JSON' }"
call :log_activity "JSON formatted"
pause
goto utilities_menu

:tool_url
echo.
echo  URL ENCODER/DECODER
echo  [1] Encode
echo  [2] Decode
echo.
set /p action=Choice: 
set /p text=Text: 
echo.
if "%action%"=="1" (
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ([Web.HttpUtility]::UrlEncode('%text%'))"
) else (
    powershell -Command "Add-Type -AssemblyName System.Web; Write-Host ([Web.HttpUtility]::UrlDecode('%text%'))"
)
call :log_activity "URL encode/decode"
pause
goto utilities_menu

:tool_jwt
echo.
echo  JWT DECODER
set /p token=Paste JWT: 
echo.
echo  Header:
for /f "delims=. tokens=1" %%a in ("%token%") do powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('  ' + [Text.Encoding]::UTF8.GetString($bytes)) } catch { }"
echo.
echo  Payload:
for /f "delims=. tokens=2" %%a in ("%token%") do powershell -Command "try { $b='%%a'; while($b.Length%%4){$b+='='}; $bytes=[Convert]::FromBase64String($b.Replace('-','+').Replace('_','/')); Write-Host ('  ' + [Text.Encoding]::UTF8.GetString($bytes)) } catch { }"
call :log_activity "JWT decoded"
pause
goto utilities_menu

:user_profile
cls
echo.
echo  USER PROFILE
echo  Username: %CURRENT_USER%
echo  Version: %VERSION%
echo.
if exist "%LOGS_DIR%\%CURRENT_USER%.log" (
    echo  Recent Activity:
    type "%LOGS_DIR%\%CURRENT_USER%.log" 2>nul | more +0
) else (
    echo  No activity yet
)
pause
goto main_menu

:view_logs
cls
echo.
echo  ACTIVITY LOGS
if exist "%LOGS_DIR%\activity.log" (
    type "%LOGS_DIR%\activity.log" 2>nul | more
) else (
    echo  No logs available
)
pause
goto main_menu

:logout
echo.
echo  Logging out...
if exist "%SESSION_FILE%" del "%SESSION_FILE%"
set CURRENT_USER=
set IS_LOGGED_IN=0
echo  Logged out
timeout /t 1 >nul
goto main_menu

:check_updates
cls
echo.
echo  UPDATE CHECKER
echo  Current Version: %VERSION%
echo.
where curl >nul 2>&1
if %errorlevel%==0 (
    echo  Checking...
    curl -sL "https://raw.githubusercontent.com/kickxly-dev/trumav2/master/TRUMA-CLI/version.txt" > "%TEMP%\truma_ver.txt" 2>nul
    if exist "%TEMP%\truma_ver.txt" (
        set /p LATEST=<"%TEMP%\truma_ver.txt"
        if "!LATEST!"=="%VERSION%" (
            echo  Latest version!
        ) else (
            echo  New version: !LATEST!
            echo  Visit: github.com/kickxly-dev/trumav2/releases
        )
        del "%TEMP%\truma_ver.txt" 2>nul
    ) else (
        echo  Check failed
    )
) else (
    echo  curl not found
    echo  Visit: github.com/kickxly-dev/trumav2/releases
)
pause
goto main_menu

:exit_truma
cls
echo.
echo  Thank you for using TRUMA!
echo  Goodbye, %CURRENT_USER%
echo.
timeout /t 2 >nul
exit /b 0

:log_activity
echo [%date% %time%] %~1 >> "%LOGS_DIR%\activity.log"
if %IS_LOGGED_IN%==1 (
    echo [%date% %time%] %~1 >> "%LOGS_DIR%\%CURRENT_USER%.log"
)
goto :eof
