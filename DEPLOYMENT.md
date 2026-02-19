# TRAUMA Suite - Deployment Guide

## GitHub Repository Setup

1. **Create GitHub Repository**
   ```bash
   git remote add origin https://github.com/yourusername/trauma-suite.git
   git branch -M main
   git push -u origin main
   ```

2. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial commit - TRAUMA Suite with backend APIs"
   git push origin main
   ```

## Render Deployment

### Step 1: Connect GitHub to Render
1. Go to [render.com](https://render.com)
2. Sign up/login to your account
3. Click "New +" → "Web Service"
4. Connect your GitHub account
5. Select the `trauma-suite` repository

### Step 2: Configure Web Service
- **Name**: `trauma-suite`
- **Environment**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Instance Type**: `Free` (or upgrade as needed)

### Step 3: Add PostgreSQL Database
1. Click "New +" → "PostgreSQL"
2. **Name**: `trauma-db`
3. **Database Name**: `trauma_suite`
4. **User**: `trauma_user`
5. **Instance Type**: `Free`

### Step 4: Environment Variables
Add these environment variables in your Render dashboard:

```bash
NODE_ENV=production
PORT=10000
DATABASE_URL=postgresql://trauma_user:password@host:5432/trauma_suite
```

### Step 5: Automatic Deployment
- Enable "Auto-Deploy" for automatic updates when you push to GitHub
- Render will automatically build and deploy your application

## Database Schema

The application automatically creates these tables:

### tool_usage
- Logs all tool usage for analytics
- Tracks IP addresses, timestamps, and parameters

### ip_lookups
- Caches IP lookup results
- Stores geolocation and ISP data

### ping_results
- Stores ping test results
- Tracks latency and packet loss statistics

## API Endpoints

### Network Tools
- `POST /api/ip-lookup` - IP geolocation lookup
- `POST /api/ping` - Network ping test
- `POST /api/dns-lookup` - DNS record queries
- `POST /api/whois` - WHOIS domain lookup

### Utilities
- `POST /api/hash` - Generate cryptographic hashes
- `POST /api/base64` - Base64 encode/decode
- `POST /api/json-format` - JSON formatting
- `POST /api/password-check` - Password strength analysis

### System
- `GET /api/system-info` - Basic system information
- `GET /api/health` - Health check endpoint

## Local Development

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Set Environment Variables**
   ```bash
   cp .env.example .env
   # Edit .env with your database URL
   ```

3. **Start Development Server**
   ```bash
   npm run dev
   ```

4. **Access Application**
   - Frontend: http://localhost:3000
   - API: http://localhost:3000/api

## Security Considerations

- All API requests are logged for security monitoring
- Database connections use SSL
- Input validation on all endpoints
- Rate limiting can be implemented as needed
- No sensitive data is stored in client-side code

## Monitoring

- Check `/api/health` for service status
- Monitor database usage in Render dashboard
- Review tool usage logs in the database
- Set up alerts for high traffic or errors

## Scaling

- Upgrade to paid Render plans for better performance
- Add Redis for caching frequently accessed data
- Implement rate limiting with Redis
- Consider CDN for static assets
- Database scaling as user base grows

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check DATABASE_URL environment variable
   - Verify database is running in Render dashboard
   - Check SSL configuration

2. **Build Failures**
   - Check package.json dependencies
   - Verify Node.js version compatibility
   - Review build logs in Render

3. **API Not Responding**
   - Check server logs in Render dashboard
   - Verify PORT environment variable
   - Test health endpoint

### Getting Help

- Check Render documentation: https://render.com/docs
- Review application logs in Render dashboard
- Test API endpoints manually before frontend integration
- Use browser developer tools for debugging frontend issues
