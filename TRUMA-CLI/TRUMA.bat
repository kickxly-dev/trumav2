@echo off
setlocal EnableExtensions EnableDelayedExpansion
title TRUMA - Advanced Network Security Suite

set "VERSION=2.0"
set "TRUMA_HOME=%~dp0"
set "DATA_DIR=%TRUMA_HOME%data"
set "LOGS_DIR=%TRUMA_HOME%logs"
set "USERS_FILE=%DATA_DIR%users.db"
set "SESSION_FILE=%DATA_DIR%session.tmp"
set "THEME=CRIMSON"

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%" >nul 2>nul
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%" >nul 2>nul

set "CURRENT_USER="
set "IS_LOGGED_IN=0"

if exist "%SESSION_FILE%" (
  set /p CURRENT_USER=<"%SESSION_FILE%"
  if not "!CURRENT_USER!"=="" set "IS_LOGGED_IN=1"
)

call :apply_theme
goto main_menu

:main_menu
cls
call :draw_header
echo.
call :line
echo  MAIN MENU
call :line
echo.

if "%IS_LOGGED_IN%"=="1" (
  echo  [1] Network Tools
  echo  [2] System Tools
  echo  [3] Security Tools
  echo  [4] Utilities
  echo  [5] My Profile
  echo  [6] View Logs
  echo  [7] Logout
  echo  [T] Theme   (Current: %THEME%)
  echo  [U] Updates
  echo.
  echo  [0] Exit
  echo.
  echo  User: %CURRENT_USER%
) else (
  echo  [1] Login
  echo  [2] Sign Up
  echo  [3] Guest Access
  echo  [T] Theme   (Current: %THEME%)
  echo  [U] Updates
  echo.
  echo  [0] Exit
)

echo.
set "choice="
set /p choice=^> 

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
call :draw_header
echo.
call :line
echo  THEME SETTINGS
call :line
echo.

echo  [1] CRIMSON (Red)
echo  [2] CYBER   (Blue)
echo  [3] MATRIX  (Green)
echo  [4] GOLD    (Yellow)
echo  [5] DARK    (Gray)
echo  [0] Back
echo.
set "theme_choice="
set /p theme_choice=^> 

if "%theme_choice%"=="1" set "THEME=CRIMSON"
if "%theme_choice%"=="2" set "THEME=CYBER"
if "%theme_choice%"=="3" set "THEME=MATRIX"
if "%theme_choice%"=="4" set "THEME=GOLD"
if "%theme_choice%"=="5" set "THEME=DARK"
if "%theme_choice%"=="0" goto main_menu

call :apply_theme
call :log_activity "Theme changed: %THEME%"
goto main_menu

:login
cls
call :draw_header
echo.
call :line
echo  LOGIN
call :line
echo.

set "username="
set "password="
set /p username=Username: 
set /p password=Password: 

if not exist "%USERS_FILE%" (
  echo.
  echo  No users found. Please sign up.
  pause
  goto main_menu
)

set "found=0"
for /f "usebackq tokens=1,2 delims=:" %%A in ("%USERS_FILE%") do (
  if "%%A"=="%username%" (
    if "%%B"=="%password%" (
      set "found=1"
    )
  )
)

if "%found%"=="1" (
  set "IS_LOGGED_IN=1"
  set "CURRENT_USER=%username%"
  >"%SESSION_FILE%" echo %CURRENT_USER%
  call :log_activity "Login: %CURRENT_USER%"
  echo.
  echo  Login successful.
  pause
  goto main_menu
)

echo.
echo  Invalid username or password.
pause
goto main_menu

:signup
cls
call :draw_header
echo.
call :line
echo  SIGN UP
call :line
echo.

set "newuser="
set "newpass="
set "confpass="
set /p newuser=Username: 
set /p newpass=Password: 
set /p confpass=Confirm: 

if "%newuser%"=="" (
  echo.
  echo  Username cannot be empty.
  pause
  goto signup
)

if not "%newpass%"=="%confpass%" (
  echo.
  echo  Passwords do not match.
  pause
  goto signup
)

if exist "%USERS_FILE%" (
  findstr /B /C:"%newuser%:" "%USERS_FILE%" >nul
  if "%errorlevel%"=="0" (
    echo.
    echo  Username already exists.
    pause
    goto signup
  )
)

>>"%USERS_FILE%" echo %newuser%:%newpass%
set "IS_LOGGED_IN=1"
set "CURRENT_USER=%newuser%"
>"%SESSION_FILE%" echo %CURRENT_USER%
call :log_activity "Signup: %CURRENT_USER%"

echo.
echo  Account created.
pause
goto main_menu

:guest_access
set "CURRENT_USER=Guest"
set "IS_LOGGED_IN=1"
call :log_activity "Guest access"
goto network_tools

:network_tools
cls
call :draw_header
echo.
call :line
echo  NETWORK TOOLS
call :line
echo.

echo  [1] IP / Host Reachability
echo  [2] Ping / Latency
echo  [3] DNS Lookup
echo  [4] Traceroute
echo  [5] ARP Table
echo  [6] Active Connections
echo  [7] Port Scan (TCP)
echo  [8] HTTP Headers
echo  [9] WiFi Scan
echo  [10] Subnet Calculator
echo  [11] WHOIS (RDAP)
echo  [12] Speed Test
echo  [0] Back
echo.
set "choice="
set /p choice=^> 

if "%choice%"=="1" goto tool_ip
if "%choice%"=="2" goto tool_ping
if "%choice%"=="3" goto tool_dns
if "%choice%"=="4" goto tool_tracert
if "%choice%"=="5" goto tool_arp
if "%choice%"=="6" goto tool_netstat
if "%choice%"=="7" goto tool_portscan
if "%choice%"=="8" goto tool_http_headers
if "%choice%"=="9" goto tool_wifi
if "%choice%"=="10" goto tool_subnet
if "%choice%"=="11" goto tool_whois
if "%choice%"=="12" goto tool_speed
if "%choice%"=="0" goto main_menu
goto network_tools

:system_tools
cls
call :draw_header
echo.
call :line
echo  SYSTEM TOOLS
call :line
echo.

echo  [1] System Info
echo  [2] Firewall Status
echo  [3] Process List
echo  [4] Disk Space
echo  [0] Back
echo.
set "choice="
set /p choice=^> 

if "%choice%"=="1" goto tool_sysinfo
if "%choice%"=="2" goto tool_firewall
if "%choice%"=="3" goto tool_tasklist
if "%choice%"=="4" goto tool_disk
if "%choice%"=="0" goto main_menu
goto system_tools

:security_tools
cls
call :draw_header
echo.
call :line
echo  SECURITY TOOLS
call :line
echo.

echo  [1] SSL Certificate Check
echo  [2] Hash Generator (MD5/SHA256)
echo  [3] Password Strength
echo  [4] Base64 Encode/Decode
echo  [5] JWT Decode
echo  [0] Back
echo.
set "choice="
set /p choice=^> 

if "%choice%"=="1" goto tool_ssl
if "%choice%"=="2" goto tool_hash
if "%choice%"=="3" goto tool_pass_strength
if "%choice%"=="4" goto tool_base64
if "%choice%"=="5" goto tool_jwt
if "%choice%"=="0" goto main_menu
goto security_tools

:utilities_menu
cls
call :draw_header
echo.
call :line
echo  UTILITIES
call :line
echo.

echo  [1] JSON Formatter
echo  [2] URL Encode/Decode
echo  [3] Random Password Generator
echo  [4] Timestamp
echo  [0] Back
echo.
set "choice="
set /p choice=^> 

if "%choice%"=="1" goto tool_json
if "%choice%"=="2" goto tool_url
if "%choice%"=="3" goto tool_passgen
if "%choice%"=="4" goto tool_timestamp
if "%choice%"=="0" goto main_menu
goto utilities_menu

:user_profile
cls
call :draw_header
echo.
call :line
echo  PROFILE
call :line
echo.

echo  User: %CURRENT_USER%
echo  Theme: %THEME%
echo  Version: %VERSION%
echo.
if exist "%LOGS_DIR%\%CURRENT_USER%.log" (
  echo  Recent activity:
  type "%LOGS_DIR%\%CURRENT_USER%.log" | more
) else (
  echo  No user log found.
)
pause
goto main_menu

:view_logs
cls
call :draw_header
echo.
call :line
echo  ACTIVITY LOG
call :line
echo.

if exist "%LOGS_DIR%\activity.log" (
  type "%LOGS_DIR%\activity.log" | more
) else (
  echo  No log file.
)
pause
goto main_menu

:logout
if exist "%SESSION_FILE%" del "%SESSION_FILE%" >nul 2>nul
set "CURRENT_USER="
set "IS_LOGGED_IN=0"
call :log_activity "Logout"
goto main_menu

:check_updates
cls
call :draw_header
echo.
call :line
echo  UPDATES
call :line
echo.

echo  Current version: %VERSION%
where curl >nul 2>nul
if not "%errorlevel%"=="0" (
  echo.
  echo  curl not found. Update check unavailable.
  pause
  goto main_menu
)

set "LATEST="
curl -sL "https://raw.githubusercontent.com/kickxly-dev/trumav2/master/TRUMA-CLI/version.txt" >"%TEMP%\truma_ver.txt" 2>nul
if not exist "%TEMP%\truma_ver.txt" (
  echo.
  echo  Update check failed.
  pause
  goto main_menu
)
set /p LATEST=<"%TEMP%\truma_ver.txt"
del "%TEMP%\truma_ver.txt" >nul 2>nul

if "%LATEST%"=="%VERSION%" (
  echo.
  echo  You are on the latest version.
  pause
  goto main_menu
)

echo.
echo  New version available: %LATEST%
echo  Visit: https://github.com/kickxly-dev/trumav2/releases
pause
goto main_menu

:exit_truma
cls
call :draw_header
echo.
echo  Goodbye.
timeout /t 2 >nul
exit /b 0

:tool_ip
cls
call :draw_header
echo.
echo  IP / HOST REACHABILITY
echo.
set "target="
set /p target=Target (IP/Host): 
call :sanitize target
echo.
ping -n 1 "%target%" >nul 2>nul
if "%errorlevel%"=="0" (
  echo  Reachable: YES
) else (
  echo  Reachable: NO
)
call :log_activity "Reachability: %target%"
pause
goto network_tools

:tool_ping
cls
call :draw_header
echo.
echo  PING / LATENCY
echo.
set "target="
set "count="
set /p target=Target: 
set /p count=Packets (default 4): 
if "%count%"=="" set "count=4"
call :sanitize target
echo.
ping -n %count% "%target%"
call :log_activity "Ping: %target% x%count%"
pause
goto network_tools

:tool_dns
cls
call :draw_header
echo.
echo  DNS LOOKUP
echo.
set "domain="
set /p domain=Domain: 
call :sanitize domain
echo.
nslookup "%domain%"
call :log_activity "DNS: %domain%"
pause
goto network_tools

:tool_tracert
cls
call :draw_header
echo.
echo  TRACEROUTE
echo.
set "target="
set /p target=Target: 
call :sanitize target
echo.
tracert -d "%target%"
call :log_activity "Traceroute: %target%"
pause
goto network_tools

:tool_arp
cls
call :draw_header
echo.
echo  ARP TABLE
echo.
arp -a
call :log_activity "ARP table"
pause
goto network_tools

:tool_netstat
cls
call :draw_header
echo.
echo  ACTIVE CONNECTIONS
echo.
netstat -ano | more
call :log_activity "Netstat"
pause
goto network_tools

:tool_portscan
cls
call :draw_header
echo.
echo  PORT SCAN (TCP)
echo.
set "target="
set "ports="
set /p target=Target IP/Host: 
set /p ports=Ports (comma-separated): 
call :sanitize target
call :sanitize ports

set "PS_SCRIPT=%TEMP%\truma_portscan.ps1"
>"%PS_SCRIPT%" echo $ErrorActionPreference='SilentlyContinue'
>>"%PS_SCRIPT%" echo $t='%target%'
>>"%PS_SCRIPT%" echo $ports='%ports%' -split ',' ^| ForEach-Object { $_.Trim() } ^| Where-Object { $_ -match '^[0-9]+$' }
>>"%PS_SCRIPT%" echo foreach($p in $ports){
>>"%PS_SCRIPT%" echo   $client=New-Object System.Net.Sockets.TcpClient
>>"%PS_SCRIPT%" echo   $ar=$client.BeginConnect($t,[int]$p,$null,$null)
>>"%PS_SCRIPT%" echo   if($ar.AsyncWaitHandle.WaitOne(500,$false) -and $client.Connected){ Write-Output ("$p OPEN") } else { Write-Output ("$p closed") }
>>"%PS_SCRIPT%" echo   $client.Close()
>>"%PS_SCRIPT%" echo }

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "Portscan: %target% (%ports%)"
pause
goto network_tools

:tool_http_headers
cls
call :draw_header
echo.
echo  HTTP HEADERS
echo.
set "url="
set /p url=URL: 
call :sanitize url
where curl >nul 2>nul
if not "%errorlevel%"=="0" (
  echo.
  echo  curl not found.
  pause
  goto network_tools
)

echo.
curl -sI "%url%"
call :log_activity "HTTP headers: %url%"
pause
goto network_tools

:tool_wifi
cls
call :draw_header
echo.
echo  WIFI SCAN
echo.
netsh wlan show networks mode=bssid
call :log_activity "WiFi scan"
pause
goto network_tools

:tool_subnet
cls
call :draw_header
echo.
echo  SUBNET CALCULATOR
echo.
set "cidr="
set /p cidr=IP/CIDR (e.g. 192.168.1.0/24): 
call :sanitize cidr

set "PS_SCRIPT=%TEMP%\truma_subnet.ps1"
>"%PS_SCRIPT%" echo $in='%cidr%'
>>"%PS_SCRIPT%" echo if($in -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$'){ Write-Output 'Invalid format'; exit 0 }
>>"%PS_SCRIPT%" echo $ip=$Matches[1]; $cidr=[int]$Matches[2]
>>"%PS_SCRIPT%" echo $mask=[uint32]([math]::Pow(2,32)-[math]::Pow(2,32-$cidr))
>>"%PS_SCRIPT%" echo $b=$ip.Split('.') ^| ForEach-Object {[uint32]$_}
>>"%PS_SCRIPT%" echo $ipInt=($b[0]*16777216)+($b[1]*65536)+($b[2]*256)+$b[3]
>>"%PS_SCRIPT%" echo $net=$ipInt -band $mask
>>"%PS_SCRIPT%" echo $bcast=$net -bor ([uint32]([math]::Pow(2,32-$cidr)-1))
>>"%PS_SCRIPT%" echo function IntToIp([uint32]$n){
>>"%PS_SCRIPT%" echo   $x=@(($n -shr 24) -band 255,(($n -shr 16) -band 255),(($n -shr 8) -band 255),($n -band 255));
>>"%PS_SCRIPT%" echo   return ($x -join '.')
>>"%PS_SCRIPT%" echo }
>>"%PS_SCRIPT%" echo $hosts=[math]::Pow(2,32-$cidr)-2
>>"%PS_SCRIPT%" echo Write-Output ("Network:   " + (IntToIp $net))
>>"%PS_SCRIPT%" echo Write-Output ("Broadcast: " + (IntToIp $bcast))
>>"%PS_SCRIPT%" echo Write-Output ("Hosts:     " + $hosts)

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "Subnet: %cidr%"
pause
goto network_tools

:tool_whois
cls
call :draw_header
echo.
echo  WHOIS (RDAP)
echo.
set "domain="
set /p domain=Domain: 
call :sanitize domain
where curl >nul 2>nul
if not "%errorlevel%"=="0" (
  echo.
  echo  curl not found.
  pause
  goto network_tools
)

echo.
curl -s "https://rdap.org/domain/%domain%"
call :log_activity "WHOIS: %domain%"
pause
goto network_tools

:tool_speed
cls
call :draw_header
echo.
echo  SPEED TEST
echo.

set "PS_SCRIPT=%TEMP%\truma_speed.ps1"
>"%PS_SCRIPT%" echo $url='http://speedtest.tele2.net/10MB.zip'
>>"%PS_SCRIPT%" echo $sizeMB=10
>>"%PS_SCRIPT%" echo $start=Get-Date
>>"%PS_SCRIPT%" echo try{
>>"%PS_SCRIPT%" echo   $wc=New-Object System.Net.WebClient
>>"%PS_SCRIPT%" echo   $null=$wc.DownloadData($url)
>>"%PS_SCRIPT%" echo   $dur=((Get-Date)-$start).TotalSeconds
>>"%PS_SCRIPT%" echo   if($dur -le 0){ $dur=0.01 }
>>"%PS_SCRIPT%" echo   $mbps=($sizeMB*8)/$dur
>>"%PS_SCRIPT%" echo   Write-Output ("Speed: " + [math]::Round($mbps,2) + " Mbps")
>>"%PS_SCRIPT%" echo }catch{ Write-Output 'Speed test failed' }

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "Speed test"
pause
goto network_tools

:tool_sysinfo
cls
call :draw_header
echo.
echo  SYSTEM INFO
echo.
ver
echo.
echo  Computer: %COMPUTERNAME%
echo  User: %USERNAME%
echo.
ipconfig | findstr /i "IPv4"
call :log_activity "System info"
pause
goto system_tools

:tool_firewall
cls
call :draw_header
echo.
echo  FIREWALL STATUS
echo.
netsh advfirewall show allprofiles
call :log_activity "Firewall status"
pause
goto system_tools

:tool_tasklist
cls
call :draw_header
echo.
echo  PROCESS LIST
echo.
tasklist | more
call :log_activity "Tasklist"
pause
goto system_tools

:tool_disk
cls
call :draw_header
echo.
echo  DISK SPACE
echo.
wmic logicaldisk get DeviceID,FreeSpace,Size,FileSystem 2>nul
call :log_activity "Disk space"
pause
goto system_tools

:tool_ssl
cls
call :draw_header
echo.
echo  SSL CERTIFICATE CHECK
echo.
set "domain="
set /p domain=Domain: 
call :sanitize domain

set "PS_SCRIPT=%TEMP%\truma_ssl.ps1"
>"%PS_SCRIPT%" echo $d='%domain%'
>>"%PS_SCRIPT%" echo try{
>>"%PS_SCRIPT%" echo   $tcp=New-Object Net.Sockets.TcpClient($d,443)
>>"%PS_SCRIPT%" echo   $ssl=New-Object Net.Security.SslStream($tcp.GetStream(),$false,({$true}))
>>"%PS_SCRIPT%" echo   $ssl.AuthenticateAsClient($d)
>>"%PS_SCRIPT%" echo   $cert=$ssl.RemoteCertificate
>>"%PS_SCRIPT%" echo   Write-Output ("Valid Until: " + $cert.GetExpirationDateString())
>>"%PS_SCRIPT%" echo   $tcp.Close()
>>"%PS_SCRIPT%" echo }catch{ Write-Output 'SSL check failed' }

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "SSL: %domain%"
pause
goto security_tools

:tool_hash
cls
call :draw_header
echo.
echo  HASH GENERATOR
echo.
set "text="
set /p text=Text: 

set "TMP=%TEMP%\truma_hash.txt"
>"%TMP%" echo %text%
echo.
echo  MD5:
certutil -hashfile "%TMP%" MD5 | findstr /v /i "hash certutil" 
echo.
echo  SHA256:
certutil -hashfile "%TMP%" SHA256 | findstr /v /i "hash certutil" 
del "%TMP%" >nul 2>nul
call :log_activity "Hash"
pause
goto security_tools

:tool_pass_strength
cls
call :draw_header
echo.
echo  PASSWORD STRENGTH
echo.
set "pass="
set /p pass=Password: 

set "len=0"
for /l %%I in (0,1,128) do (
  if not "!pass:~%%I,1!"=="" set /a len+=1
)

echo.
echo  Length: !len!
if !len! lss 8 (
  echo  Strength: WEAK
) else if !len! lss 12 (
  echo  Strength: MODERATE
) else (
  echo  Strength: STRONG
)
call :log_activity "Password strength"
pause
goto security_tools

:tool_base64
cls
call :draw_header
echo.
echo  BASE64
echo.
echo  [1] Encode
echo  [2] Decode
echo  [0] Back
echo.
set "action="
set /p action=^> 
if "%action%"=="0" goto security_tools

set "text="
set /p text=Text: 

set "PS_SCRIPT=%TEMP%\truma_b64.ps1"
>"%PS_SCRIPT%" echo $t=Get-Content -Raw -LiteralPath '%TEMP%\truma_b64_in.txt'
if "%action%"=="1" (
  >"%TEMP%\truma_b64_in.txt" echo %text%
  >>"%PS_SCRIPT%" echo [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t))
) else (
  >"%TEMP%\truma_b64_in.txt" echo %text%
  >>"%PS_SCRIPT%" echo try{ [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($t)) }catch{ 'Invalid Base64' }
)

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
del "%TEMP%\truma_b64_in.txt" >nul 2>nul
call :log_activity "Base64"
pause
goto security_tools

:tool_jwt
cls
call :draw_header
echo.
echo  JWT DECODE
echo.
set "token="
set /p token=JWT: 
call :sanitize token

set "PS_SCRIPT=%TEMP%\truma_jwt.ps1"
>"%PS_SCRIPT%" echo $t='%token%'
>>"%PS_SCRIPT%" echo $parts=$t -split '\.'
>>"%PS_SCRIPT%" echo function B64Url([string]$s){ $s=$s.Replace('-','+').Replace('_','/'); while($s.Length%%4){$s+='='}; return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
>>"%PS_SCRIPT%" echo if($parts.Length -ge 2){
>>"%PS_SCRIPT%" echo   'Header:'; B64Url $parts[0]
>>"%PS_SCRIPT%" echo   'Payload:'; B64Url $parts[1]
>>"%PS_SCRIPT%" echo } else { 'Invalid token' }

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "JWT"
pause
goto security_tools

:tool_json
cls
call :draw_header
echo.
echo  JSON FORMAT
echo.
set "jsonin="
set /p jsonin=JSON (single line): 

set "TMP=%TEMP%\truma_json.txt"
>"%TMP%" echo %jsonin%

set "PS_SCRIPT=%TEMP%\truma_json.ps1"
>"%PS_SCRIPT%" echo try{ $c=Get-Content -Raw -LiteralPath '%TMP%'; $j=$c ^| ConvertFrom-Json; $j ^| ConvertTo-Json -Depth 20 }catch{ 'Invalid JSON' }

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
del "%TMP%" >nul 2>nul
call :log_activity "JSON"
pause
goto utilities_menu

:tool_url
cls
call :draw_header
echo.
echo  URL ENCODE/DECODE
echo.
echo  [1] Encode
echo  [2] Decode
echo  [0] Back
echo.
set "action="
set /p action=^> 
if "%action%"=="0" goto utilities_menu

set "text="
set /p text=Text: 

set "TMP=%TEMP%\truma_url.txt"
>"%TMP%" echo %text%

set "PS_SCRIPT=%TEMP%\truma_url.ps1"
>"%PS_SCRIPT%" echo Add-Type -AssemblyName System.Web
>>"%PS_SCRIPT%" echo $c=Get-Content -Raw -LiteralPath '%TMP%'
if "%action%"=="1" (
  >>"%PS_SCRIPT%" echo [Web.HttpUtility]::UrlEncode($c)
) else (
  >>"%PS_SCRIPT%" echo [Web.HttpUtility]::UrlDecode($c)
)

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
del "%TMP%" >nul 2>nul
call :log_activity "URL"
pause
goto utilities_menu

:tool_passgen
cls
call :draw_header
echo.
echo  PASSWORD GENERATOR
echo.
set "n="
set /p n=Length (default 16): 
if "%n%"=="" set "n=16"

set "PS_SCRIPT=%TEMP%\truma_passgen.ps1"
>"%PS_SCRIPT%" echo $len=[int]'%n%'
>>"%PS_SCRIPT%" echo if($len -lt 6){$len=6}
>>"%PS_SCRIPT%" echo $chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%%^&*_-'
>>"%PS_SCRIPT%" echo $rng=New-Object System.Random
>>"%PS_SCRIPT%" echo $pw= -join (1..$len ^| ForEach-Object { $chars[$rng.Next(0,$chars.Length)] })
>>"%PS_SCRIPT%" echo $pw

call :ps_run "%PS_SCRIPT%"
del "%PS_SCRIPT%" >nul 2>nul
call :log_activity "Password generator"
pause
goto utilities_menu

:tool_timestamp
cls
call :draw_header
echo.
echo  TIMESTAMP
echo.
echo  %date% %time%
call :log_activity "Timestamp"
pause
goto utilities_menu

:apply_theme
if /i "%THEME%"=="CRIMSON" color 0C
if /i "%THEME%"=="CYBER"   color 0B
if /i "%THEME%"=="MATRIX"  color 0A
if /i "%THEME%"=="GOLD"    color 0E
if /i "%THEME%"=="DARK"    color 0F
goto :eof

:draw_header
echo.
echo  TTTTT RRRR  U   U M   M  AAA
echo    T   R   R U   U MM MM A   A
echo    T   RRRR  U   U M M M AAAAA
echo    T   R  R  U   U M   M A   A
echo    T   R   R  UUU  M   M A   A
echo  TRUMA - Advanced Network Security Suite v%VERSION%
goto :eof

:line
echo  ------------------------------------------------------------
goto :eof

:log_activity
>>"%LOGS_DIR%\activity.log" echo [%date% %time%] %~1
if "%IS_LOGGED_IN%"=="1" (
  if not "%CURRENT_USER%"=="" (
    >>"%LOGS_DIR%\%CURRENT_USER%.log" echo [%date% %time%] %~1
  )
)
goto :eof

:sanitize
set "__v=!%~1!"
set "__v=!__v:^= !"
set "__v=!__v:&= !"
set "__v=!__v:|= !"
set "__v=!__v:<= !"
set "__v=!__v:>= !"
set "__v=!__v:(= !"
set "__v=!__v:)= !"
set "__v=!__v:!= !"
set "__v=!__v:%= !"
for /f "tokens=* delims= " %%Z in ("!__v!") do set "__v=%%Z"
set "%~1=!__v!"
set "__v="
goto :eof

:ps_run
powershell -NoProfile -ExecutionPolicy Bypass -File %1
goto :eof
