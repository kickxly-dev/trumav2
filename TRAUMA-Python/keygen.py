#!/usr/bin/env python3
"""
TRAUMA License Key Generator
Generate license keys for your users
"""

import secrets
import string
import json
import hashlib
from datetime import datetime

def generate_key(prefix="TRAUMA", segments=8, segment_length=4):
    """Generate a license key"""
    parts = [prefix]
    for _ in range(segments):
        segment = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(segment_length))
        parts.append(segment)
    return '-'.join(parts)

def generate_batch(count=10):
    """Generate multiple keys"""
    keys = []
    for _ in range(count):
        key = generate_key()
        keys.append({
            "key": key,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": hashlib.sha256(key.encode()).hexdigest()[:16]
        })
    return keys

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
║          ▶ L I C E N S E   K E Y   G E N E R A T O R ◀         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    print("Options:")
    print("  [1] Generate single key")
    print("  [2] Generate batch of keys")
    print("  [3] Generate master key")
    print("  [4] Export keys to file")
    print()
    
    choice = input("Select: ").strip()
    
    if choice == "1":
        key = generate_key()
        print(f"\n✓ Generated Key:\n")
        print(f"  {key}")
        print()
        
    elif choice == "2":
        count = int(input("How many keys? (default 10): ") or "10")
        keys = generate_batch(count)
        
        print(f"\n✓ Generated {count} keys:\n")
        for i, k in enumerate(keys, 1):
            print(f"  {i}. {k['key']}")
        print()
        
        save = input("Save to file? (y/n): ").strip().lower()
        if save == 'y':
            filename = f"license_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(keys, f, indent=2)
            print(f"\n✓ Saved to {filename}")
            
    elif choice == "3":
        # Generate a special master key
        master = f"TRAUMA-MASTER-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}-FULL-ACCESS"
        print(f"\n✓ Master Key Generated:\n")
        print(f"  {master}")
        print(f"\n  WARNING: Keep this key secure!")
        print()
        
    elif choice == "4":
        count = int(input("How many keys to export? (default 100): ") or "100")
        keys = generate_batch(count)
        
        filename = f"license_keys_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(keys, f, indent=2)
        
        # Also create a simple text file
        txt_filename = filename.replace('.json', '.txt')
        with open(txt_filename, 'w') as f:
            for k in keys:
                f.write(k['key'] + '\n')
        
        print(f"\n✓ Exported {count} keys:")
        print(f"  JSON: {filename}")
        print(f"  TXT:  {txt_filename}")
        print()
    
    else:
        print("Invalid option")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
