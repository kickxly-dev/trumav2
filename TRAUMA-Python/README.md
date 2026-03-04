# TRAUMA-Python
### All-in-One Security Toolkit

```
________  _______    ______   __    __  __       __   ______  
|        \|       \  /      \ |  \  |  \|  \     /  \ /      \ 
 \$$$$$$$$| $$$$$$$\|  $$$$$$\| $$  | $$| $$\   /  $$|  $$$$$$\
   | $$   | $$__| $$| $$__| $$| $$  | $$| $$$\ /  $$$| $$__| $$
   | $$   | $$    $$| $$    $$| $$  | $$| $$$$\  $$$$| $$    $$
   | $$   | $$$$$$$\| $$$$$$$$| $$  | $$| $$\$$ $$ $$| $$$$$$$$
   | $$   | $$  | $$| $$  | $$| $$__/ $$| $$ \$$$| $$| $$  | $$
   | $$   | $$  | $$| $$  | $$ \$$    $$| $$  \$ | $$| $$  | $$
    \$$    \$$   \$$ \$$   \$$  \$$$$$$  \$$      \$$ \$$   \$$
```

**Version 2.0** | Self-Contained Intelligence

---

## 📋 Features

### 🌐 Network Reconnaissance
- **Port Scanner** - Multi-threaded port scanning with banner grabbing
- **OS Detection** - Detect operating systems via TTL fingerprinting
- **Network Mapper** - Discover live hosts on a network
- **Ping Sweep** - Fast CIDR network scanning

### 🌍 Web Exploitation
- **SQLi Scanner** - Detect SQL injection vulnerabilities (15+ payloads)
- **XSS Scanner** - Cross-site scripting detection (25+ payloads)
- **LFI/RFI Scanner** - Local/Remote file inclusion testing
- **Directory Brute Force** - Discover hidden directories (80+ paths)
- **Header Analyzer** - Security headers analysis with scoring
- **Tech Detector** - Detect CMS, frameworks, analytics tools
- **CMS Scanner** - WordPress, Joomla, Drupal, Magento detection

### 🔐 Password Attacks
- **Hash Cracker** - MD5, SHA-1, SHA-256, SHA-512 cracking
- **Hash Identifier** - Identify hash types automatically
- **Wordlist Generator** - Create custom wordlists with leet speak
- **Password Strength** - Estimate crack time

### 🔍 Information Gathering
- **DNS Lookup** - Query all DNS record types
- **Subdomain Finder** - Discover subdomains (80+ common)
- **IP Geolocation** - GeoIP lookup with city, ISP, coordinates
- **Email OSINT** - Validate and analyze email addresses

### 💣 Payload Generator
- **Reverse Shells** - 15+ languages (Bash, Python, Perl, PHP, etc.)
- **XSS Payloads** - 25+ cross-site scripting payloads
- **Encoder/Decoder** - Base64, URL, Hex, ROT13, HTML

### 🔨 Brute Force
- **SSH Brute Force** - SSH login attacks (requires paramiko)
- **FTP Brute Force** - FTP authentication testing
- **HTTP Brute Force** - HTTP Basic Auth attacks

### 🔬 Forensics
- **File Analysis** - Magic bytes, hashes, entropy analysis
- **Metadata Extractor** - EXIF, PDF, Office, executable metadata
- **String Extractor** - Extract URLs, emails, IPs from binaries

### 🛡️ Anonymity Tools
- **Tor Checker** - Verify Tor connection status
- **Proxy Tools** - Test proxies, check IP, generate config
- **MAC Spoofer** - Change MAC address (Linux/Mac)

---

## 🚀 Installation

### Requirements
- Python 3.7+
- Windows/Linux/macOS

### Quick Start

```bash
# Clone or download
cd TRAUMA-Python

# Install dependencies
pip install -r requirements.txt

# Run
python trauma.py
```

### Windows
Double-click `TRAUMA.bat` for automatic dependency check and launch.

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `rich` | Beautiful CLI UI |
| `requests` | HTTP requests |
| `colorama` | ANSI colors (fallback) |
| `dnspython` | DNS queries |
| `paramiko` | SSH brute force (optional) |

---

## 💻 Usage

```
python trauma.py
```

Navigate through the animated menu system using number keys.

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY**

This tool is designed for:
- Security research
- Penetration testing (with authorization)
- Learning about cybersecurity

**Do NOT use for:**
- Unauthorized access
- Malicious activities
- Any illegal purposes

The developers are not responsible for misuse of this tool.

---

## 📜 License

MIT License - Use responsibly.

---

## 🤝 Contributing

Contributions welcome! Areas to improve:
- More payloads and attack vectors
- Additional forensics tools
- Better error handling
- Performance optimizations

---

## 📊 Statistics

- **Modules**: 10
- **Tools**: 35+
- **Lines of Code**: 3200+
- **Payloads**: 100+

---

<p align="center">
  <b>Stay safe. Hack responsibly.</b>
</p>
