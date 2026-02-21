# TRUMA CLI Changelog

## Version 2.0 - February 2025

### 🎉 Major Release - Complete Rewrite
- **Full restart from stable base** - Eliminated all insta-close crashes
- **New architecture** - PowerShell commands run via temporary .ps1 files for stability
- **Safe variable handling** - All comparisons properly quoted (`if "%VAR%"=="1"`)

### 🛠️ Features Added
- **12 Network Tools**
  - IP/Host Reachability Check
  - Ping / Latency Tester
  - DNS Lookup
  - Traceroute
  - ARP Table Scanner
  - Active Connections (netstat)
  - TCP Port Scanner
  - HTTP Headers Checker
  - WiFi Scanner
  - Subnet Calculator
  - WHOIS (RDAP) Lookup
  - Internet Speed Test

- **4 System Tools**
  - System Information
  - Firewall Status
  - Process Monitor
  - Disk Space

- **5 Security Tools**
  - SSL Certificate Checker
  - Hash Generator (MD5/SHA256)
  - Password Strength Analyzer
  - Base64 Encoder/Decoder
  - JWT Decoder

- **4 Utilities**
  - JSON Formatter
  - URL Encoder/Decoder
  - Random Password Generator
  - Timestamp Display

### 🎨 UI/UX Improvements
- **5 Color Themes**
  - CRIMSON (Red)
  - CYBER (Blue)
  - MATRIX (Green)
  - GOLD (Yellow)
  - DARK (Gray)

- **ASCII Art Header** - Professional TRUMA branding
- **Clean Menu System** - Organized tool categories
- **Status Indicators** - Clear success/error messages

### 🔐 Authentication System
- **User Registration** - Create accounts with username/password
- **Login System** - Secure session management
- **Guest Access** - Limited access without registration
- **Activity Logging** - Track all user actions

### 🌐 Network Features
- **Auto-Updater** - Checks GitHub for new versions
- **Input Sanitization** - Prevents command injection
- **Error Handling** - Graceful failure messages
- **Cross-Platform** - Works on Windows 10/11

### 🐛 Bug Fixes
- **Fixed insta-close crashes** - Proper variable quoting
- **Fixed PowerShell parsing** - Temporary .ps1 files instead of one-liners
- **Fixed redirection syntax** - Merged standalone `>` lines
- **Fixed login loop** - Proper delayed expansion
- **Fixed guest access** - Now sets IS_LOGGED_IN flag

### 🧹 Cleanup
- **Removed 40+ old versions** - Streamlined repository
- **Single TRUMA.bat** - One definitive version
- **Clean Git History** - Removed duplicate files

---

## Previous Versions (Archived)

### Legacy Versions (v1.x)
- Multiple experimental versions with various UI approaches
- Incremental feature additions and bug fixes
- All archived in Git history

---

## Installation
```bash
git clone https://github.com/kickxly-dev/trumav2.git
cd TRUMA-CLI
TRUMA.bat
```

## Support
- **Discord**: [Your Discord Server]
- **GitHub**: https://github.com/kickxly-dev/trumav2
- **Issues**: Report bugs on GitHub Issues

---

*TRUMA CLI - Advanced Network Security Suite for Windows*
