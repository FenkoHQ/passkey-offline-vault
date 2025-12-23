# PassKey Vault

A browser extension for secure passkey (WebAuthn) storage and management. Intercepts WebAuthn API calls to manage passkeys internally without showing the browser's native UI. Supports **Chrome** (Manifest V3) and **Firefox** (Manifest V2).

## Features

- **WebAuthn Interception** - Automatically intercepts passkey creation and authentication
- **Local Storage** - Passkeys stored securely in browser local storage
- **Export/Import** - Full backup with encrypted private keys
- **Cross-Browser** - Works on Chrome and Firefox
- **Brutalist UI** - Clean, high-contrast interface

## Installation

### Prerequisites

- Node.js 18+
- Chrome 88+ or Firefox 109+

### Build from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/passkey-vault.git
cd passkey-vault

# Install dependencies
npm install

# Build for Chrome
npm run build

# Build for Firefox
npm run build:firefox

# Build for both
npm run build:all
```

### Load in Browser

**Chrome:**

1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `dist/` directory

**Firefox:**

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `dist-firefox/manifest.json`

## Usage

1. Navigate to any site that uses WebAuthn/passkeys
2. When prompted to create a passkey, PassKey Vault will intercept and store it
3. When signing in, PassKey Vault shows a selector if multiple passkeys exist
4. Click the extension icon to view, export, or delete stored passkeys

## Project Structure

```
passkey-vault/
├── src/
│   ├── background/       # Service worker (Chrome) / Background script (Firefox)
│   ├── content/          # Content scripts & WebAuthn injection
│   ├── crypto/           # Encryption utilities
│   ├── ui/               # Popup, import page, in-page UI
│   ├── manifest.json     # Chrome MV3 manifest
│   └── manifest.firefox.json  # Firefox MV2 manifest
├── dist/                 # Chrome build output
├── dist-firefox/         # Firefox build output
├── icon.png              # Extension icon (512x512)
└── build-extension.js    # Build script
```

## Scripts

```bash
npm run build          # Build for Chrome
npm run build:firefox  # Build for Firefox
npm run build:all      # Build for both browsers
npm run zip            # Create Chrome distribution ZIP
npm run zip:firefox    # Create Firefox distribution ZIP
npm run zip:all        # Create both ZIPs
npm run clean          # Remove build directories
npm run typecheck      # Type check without emitting
npm run lint           # Run ESLint
npm run test           # Run tests
```

## How It Works

1. **Content Script** injects a script that overrides `navigator.credentials.create()` and `navigator.credentials.get()`
2. **WebAuthn Interception** captures the credential options and forwards to the background script
3. **Background Script** generates ECDSA P-256 key pairs and creates proper WebAuthn responses
4. **Storage** persists passkeys in browser's local storage
5. **Authentication** signs challenges with stored private keys using proper CBOR/attestation encoding

## Security Notes

- Private keys are stored in browser local storage (not encrypted at rest by default)
- Export files contain private keys - handle with care
- This is a development/research tool - use at your own risk

## License

MIT
