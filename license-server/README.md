# TRAUMA License Server

Unified license management system for all TRAUMA tools.

## Features

- ✅ Remote license validation API
- ✅ Discord bot integration
- ✅ Analytics dashboard
- ✅ Hardware ID binding
- ✅ Referral system
- ✅ API key management
- ✅ Expiration warnings

## Quick Start

```bash
# Install dependencies
npm install

# Start the license server
npm start

# Start Discord bot (separate terminal)
npm run bot
```

## Environment Variables

Create a `.env` file:

```
LICENSE_PORT=3001
DISCORD_BOT_TOKEN=your_bot_token
ADMIN_IDS=user_id1,user_id2
ADMIN_API_KEY=your_admin_key
```

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/license/validate` | Validate a license key |
| POST | `/api/license/activate` | Activate license with hardware binding |
| POST | `/api/license/deactivate` | Deactivate license |
| GET | `/api/license/warning/:key` | Check expiry warning |
| POST | `/api/referral/use` | Use referral code |
| POST | `/api/breach/check` | Check email for breaches |

### Admin Endpoints (require API key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/admin/license/generate` | Generate new license |
| POST | `/api/admin/license/revoke` | Revoke a license |
| GET | `/api/admin/licenses` | List all licenses |
| POST | `/api/admin/apikey/generate` | Generate API key |
| GET | `/api/admin/analytics` | Get usage statistics |
| POST | `/api/referral/create` | Create referral code |

## Discord Bot Commands

| Command | Description | Permission |
|---------|-------------|------------|
| `/verify <key>` | Verify your license | Everyone |
| `/status` | Check license status | Everyone |
| `/extend <code> <key>` | Extend license with referral | Everyone |
| `/generate <user> [days]` | Generate license | Admin |
| `/revoke <key>` | Revoke license | Admin |
| `/list [limit]` | List licenses | Admin |
| `/stats` | Server statistics | Admin |
| `/referral <name> [bonus]` | Create referral | Admin |
| `/help` | Show help | Everyone |

## Integration

### JavaScript/Node.js

```javascript
const axios = require('axios');

async function validateLicense(key) {
    const response = await axios.post('http://localhost:3001/api/license/validate', {
        key,
        tool: 'osint',
        version: '2.0.0',
        hardwareId: getHardwareId() // optional
    });
    return response.data;
}
```

### Python

```python
import requests

def validate_license(key):
    response = requests.post('http://localhost:3001/api/license/validate', json={
        'key': key,
        'tool': 'python',
        'version': '2.0.0'
    })
    return response.json()
```

### Browser

```javascript
// In browser - uses localStorage for caching
async function checkLicense() {
    const key = localStorage.getItem('trauma_license');
    if (!key) return { valid: false };
    
    const response = await fetch('https://your-server.com/api/license/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key })
    });
    return response.json();
}
```

## Hardware ID Binding

Generate a unique hardware ID:

```javascript
const os = require('os');
const crypto = require('crypto');

function getHardwareId() {
    const info = [
        os.hostname(),
        os.platform(),
        os.cpus()[0]?.model || 'unknown',
        // Add more unique identifiers
    ].join('-');
    
    return crypto.createHash('sha256').update(info).digest('hex').substring(0, 32);
}
```

## Dashboard

Open `dashboard.html` in a browser to access the admin dashboard.

Features:
- View statistics
- Generate/revoke licenses
- Create referral codes
- View recent events
- Manage API keys

## Data Storage

Data is stored in JSON files in the `data/` directory:

- `licenses.json` - All licenses
- `analytics.json` - Event logs
- `api_keys.json` - API keys
- `referrals.json` - Referral codes

For production, consider migrating to a database like MongoDB or PostgreSQL.

## Security Notes

1. Keep `ADMIN_API_KEY` secure
2. Use HTTPS in production
3. Rate limit the API
4. Validate all inputs
5. Use environment variables for secrets

## License

MIT License - TRAUMA Suite
