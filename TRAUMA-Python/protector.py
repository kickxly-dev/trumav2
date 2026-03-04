#!/usr/bin/env python3
"""
TRAUMA Code Protector
Obfuscates Python code before compilation
"""

import os
import re
import base64
import zlib
import random
import string

def obfuscate_code(source_code: str) -> str:
    """Apply multiple obfuscation layers"""
    
    # Layer 1: Remove comments and docstrings
    lines = []
    in_docstring = False
    for line in source_code.split('\n'):
        stripped = line.strip()
        
        # Skip single-line comments
        if stripped.startswith('#') and not stripped.startswith('#!'):
            continue
            
        # Handle docstrings
        if '"""' in line or "'''" in line:
            if in_docstring:
                in_docstring = False
                continue
            else:
                in_docstring = True
                continue
                
        if in_docstring:
            continue
            
        lines.append(line)
    
    code = '\n'.join(lines)
    
    # Layer 2: Compress and encode
    compressed = zlib.compress(code.encode('utf-8'), 9)
    encoded = base64.b64encode(compressed).decode('ascii')
    
    # Layer 3: Create self-decoding stub
    decoder = f'''#!/usr/bin/env python3
import zlib,base64 as b
exec(__import__('zlib').decompress(__import__('base64').b64decode('{encoded}')).decode())
'''
    
    return decoder

def add_anti_tamper(source_code: str) -> str:
    """Add integrity checks"""
    
    anti_tamper = '''
# Anti-tamper protection
import sys, os, hashlib

def _verify_integrity():
    """Verify script hasn't been modified"""
    try:
        # Check for common tampering tools
        forbidden = ['pyinstxtractor', 'uncompyle6', 'decompyle3', 'pycdc']
        for tool in forbidden:
            if tool in str(sys.modules).lower():
                os._exit(1)
        
        # Check for debugger
        if hasattr(sys, 'gettrace') and sys.gettrace():
            os._exit(1)
            
    except:
        pass

_verify_integrity()
'''
    
    # Insert after imports
    import_end = source_code.find('# Try to import')
    if import_end == -1:
        import_end = source_code.find('import ')
        import_end = source_code.find('\n', import_end)
    
    return source_code[:import_end] + anti_tamper + source_code[import_end:]

def protect_file(input_path: str, output_path: str, obfuscate=True, anti_tamper=True):
    """Apply all protections to a file"""
    
    print(f"\nReading {input_path}...")
    with open(input_path, 'r', encoding='utf-8') as f:
        code = f.read()
    
    print("Applying protections...")
    
    if anti_tamper:
        code = add_anti_tamper(code)
        print("  + Anti-tamper checks")
    
    if obfuscate:
        code = obfuscate_code(code)
        print("  + Code obfuscation")
    
    print(f"Writing to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(code)
    
    print("\n" + "="*50)
    print("  PROTECTION COMPLETE!")
    print("="*50)
    print(f"\n  Original size:  {os.path.getsize(input_path):,} bytes")
    print(f"  Protected size: {os.path.getsize(output_path):,} bytes")
    print(f"\n  Output file: {output_path}")

def main():
    print("""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     █████─ ██ ─███─ ██ ████ ██ ████ ████ █──█ ████ ███ ████   ║
║     █───█ █ █ █──█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █      ║
║     █───█ ██ ████ █ █ █ ██ ████ ████ █─██ ████ ███ ███        ║
║     █───█ █ █ █──█ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █ █        ║
║     █───█ █ █ █──█ ██ ████ █ █ █ █ █ █ █ █ █ █ █ █ █ █        ║
║                                                                ║
║              ▶ C O D E   P R O T E C T O R ◀                   ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    # Get input file
    print("Enter the Python file to protect:")
    print("(default: trauma.py)")
    input_file = input("\n► ").strip()
    if not input_file:
        input_file = "trauma.py"
    
    # Check if file exists
    if not os.path.exists(input_file):
        print(f"\n✗ Error: File '{input_file}' not found!")
        input("\nPress Enter to exit...")
        return
    
    # Get output file
    print("\nEnter output filename:")
    print("(default: trauma_protected.py)")
    output_file = input("\n► ").strip()
    if not output_file:
        output_file = "trauma_protected.py"
    
    # Ask about obfuscation
    print("\nObfuscate code? (makes code unreadable)")
    print("[Y/n]: ", end="")
    obfuscate = input().strip().lower() != 'n'
    
    # Ask about anti-tamper
    print("\nAdd anti-tamper checks? (detects debugging/modification)")
    print("[Y/n]: ", end="")
    anti_tamper = input().strip().lower() != 'n'
    
    # Run protection
    try:
        protect_file(input_file, output_file, obfuscate, anti_tamper)
        
        print("\n" + "="*50)
        print("  NEXT STEPS:")
        print("="*50)
        print(f"""
  1. Test the protected file:
     python {output_file}

  2. Build to EXE:
     pyinstaller --onefile {output_file}

  3. Distribute the EXE from dist/ folder
""")
    except Exception as e:
        print(f"\n✗ Error: {e}")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
