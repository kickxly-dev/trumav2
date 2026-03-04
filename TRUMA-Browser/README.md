# TRUMA Browser

A crimson red + black, privacy-first browser using DuckDuckGo with **zero persistence**.

## Zero-data behavior
- Uses an in-memory Electron session partition: `temp:truma`
- Stores Electron `userData` in a temporary folder and deletes it on exit (best-effort)
- Does not implement any history/bookmarks storage

## Requirements
- Node.js 18+

## Run (dev)
```bash
npm install
npm start
```

## Build Windows EXE
```bash
npm install
npm run dist:win
```

The built installer will be in:
- `TRUMA-Browser/dist/`

## Notes
- Downloads are allowed and will save to your normal Windows Downloads folder.
- "Zero data" means the app doesn’t keep browser state (history/cookies/cache) between runs. Files you download are still files on disk.
