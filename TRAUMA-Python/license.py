#!/usr/bin/env python3
"""
TRAUMA Unified License System
One license works across all TRAUMA tools: OSINT, Python, Browser, Web
"""

import os
import sys
import json
import hmac
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# Shared secret - SAME across all TRAUMA products
TRAUMA_SECRET = 'TRUMA-OSINT-SECRET-2024-SECURE-KEY-DO-NOT-SHARE'

def get_app_dir():
    """Get the application directory"""
    if getattr(sys, 'frozen', False):
        # Running as compiled exe
        return Path(sys.executable).parent
    else:
        return Path(__file__).parent

def get_license_file():
    """Get the license file path"""
    return get_app_dir() / 'license.key'

def get_licenses_dir():
    """Get the licenses directory"""
    lic_dir = get_app_dir() / 'licenses'
    lic_dir.mkdir(exist_ok=True)
    return lic_dir

def generate_license(user='User', expiry_days=365):
    """Generate a new TRAUMA license key"""
    timestamp = int(datetime.now().timestamp() * 1000)
    expiry = timestamp + (expiry_days * 24 * 60 * 60 * 1000)
    payload = f"{user}|{timestamp}|{expiry}"
    
    signature = hmac.new(
        TRAUMA_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()[:32].upper()
    
    key = f"TRUMA-{signature[0:4]}-{signature[4:8]}-{signature[8:12]}-{signature[12:16]}-{signature[16:20]}-{signature[20:24]}"
    
    license_data = {
        'key': key,
        'user': user,
        'created': datetime.fromtimestamp(timestamp/1000).isoformat(),
        'expires': datetime.fromtimestamp(expiry/1000).isoformat(),
        'payload': payload
    }
    
    # Save to licenses directory
    lic_file = get_licenses_dir() / f"{user}_{timestamp}.json"
    with open(lic_file, 'w') as f:
        json.dump(license_data, f, indent=2)
    
    return license_data

def verify_license_format(key):
    """Verify license key format"""
    if not key or not isinstance(key, str):
        return False
    
    key = key.upper().strip()
    parts = key.split('-')
    
    if len(parts) != 7:
        return False
    
    if parts[0] != 'TRUMA':
        return False
    
    # Check each group is 4 alphanumeric chars
    for i in range(1, 7):
        if len(parts[i]) != 4:
            return False
        if not parts[i].isalnum():
            return False
    
    return True

def check_license():
    """Check if a valid license is activated"""
    lic_file = get_license_file()
    
    if not lic_file.exists():
        return {
            'valid': False,
            'error': 'No license activated',
            'needs_activation': True
        }
    
    try:
        with open(lic_file, 'r') as f:
            data = json.load(f)
        
        if not verify_license_format(data.get('key', '')):
            return {
                'valid': False,
                'error': 'Invalid license format'
            }
        
        # Check expiry
        if 'expires' in data:
            expiry = datetime.fromisoformat(data['expires'].replace('Z', '+00:00').replace('+00:00', ''))
            if expiry < datetime.now():
                return {
                    'valid': False,
                    'error': 'License expired',
                    'expired': True,
                    'expires': data['expires']
                }
        
        return {
            'valid': True,
            'user': data.get('user', 'Licensed User'),
            'expires': data.get('expires'),
            'created': data.get('created')
        }
    except Exception as e:
        return {
            'valid': False,
            'error': f'License file error: {str(e)}'
        }

def activate_license(key):
    """Activate a license key"""
    if not verify_license_format(key):
        return {
            'success': False,
            'error': 'Invalid license format'
        }
    
    # Create license data
    now = datetime.now()
    expiry = now + timedelta(days=365)
    
    license_data = {
        'key': key.upper(),
        'user': 'Licensed User',
        'created': now.isoformat(),
        'expires': expiry.isoformat(),
        'activated': int(now.timestamp() * 1000)
    }
    
    lic_file = get_license_file()
    with open(lic_file, 'w') as f:
        json.dump(license_data, f, indent=2)
    
    return {
        'success': True,
        'message': 'License activated successfully',
        'user': license_data['user'],
        'expires': license_data['expires']
    }

def deactivate_license():
    """Deactivate/remove license"""
    lic_file = get_license_file()
    if lic_file.exists():
        lic_file.unlink()
        return {'success': True, 'message': 'License deactivated'}
    return {'success': False, 'error': 'No license to deactivate'}

def get_license_info():
    """Get license info for display"""
    lic_file = get_license_file()
    
    if not lic_file.exists():
        return None
    
    try:
        with open(lic_file, 'r') as f:
            return json.load(f)
    except:
        return None

# CLI interface
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='TRAUMA Unified License System')
    parser.add_argument('--generate', '-g', action='store_true', help='Generate a new license')
    parser.add_argument('--user', '-u', type=str, default='User', help='Username for license')
    parser.add_argument('--days', '-d', type=int, default=365, help='Expiry days')
    parser.add_argument('--check', '-c', action='store_true', help='Check license status')
    parser.add_argument('--activate', '-a', type=str, help='Activate a license key')
    parser.add_argument('--deactivate', action='store_true', help='Deactivate license')
    
    args = parser.parse_args()
    
    if args.generate:
        lic = generate_license(args.user, args.days)
        print(f"\n{'='*60}")
        print(f"  TRAUMA UNIFIED LICENSE GENERATOR")
        print(f"{'='*60}")
        print(f"  User: {lic['user']}")
        print(f"  Created: {lic['created']}")
        print(f"  Expires: {lic['expires']}")
        print(f"{'='*60}")
        print(f"  KEY: {lic['key']}")
        print(f"{'='*60}\n")
    
    elif args.check:
        result = check_license()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['valid'] else 1)
    
    elif args.activate:
        result = activate_license(args.activate)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['success'] else 1)
    
    elif args.deactivate:
        result = deactivate_license()
        print(json.dumps(result, indent=2))
    
    else:
        parser.print_help()
