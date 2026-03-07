# TRAUMA License Manager Mobile App

React Native mobile app for managing TRAUMA licenses on the go.

## Features

- **Dashboard** - Quick stats and recent activity
- **Licenses** - Generate, view, and revoke licenses
- **Pools** - Create and manage license pools
- **Settings** - Configure server URL, export data

## Setup

1. Install dependencies:
```bash
cd mobile-app
npm install
```

2. Start the app:
```bash
npx expo start
```

3. Scan QR code with Expo Go app (iOS/Android) or press:
- `i` - Open in iOS simulator
- `a` - Open in Android emulator
- `w` - Open in web browser

## Configuration

1. Enter your license server URL (default: `http://localhost:3001`)
2. Enter your API key from `license-server/data/api_keys.json`

## Building for Production

### iOS
```bash
npx expo build:ios
```

### Android
```bash
npx expo build:android
```

## Requirements

- Node.js 18+
- Expo CLI
- Expo Go app (for testing)
