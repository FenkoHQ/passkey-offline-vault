#!/usr/bin/env node

/**
 * Build script for PassKey Vault Extension
 * Supports both Chrome (Manifest V3) and Firefox (Manifest V2)
 *
 * Usage:
 *   npm run build          - Build for Chrome (default)
 *   npm run build:chrome   - Build for Chrome
 *   npm run build:firefox  - Build for Firefox
 *   npm run build:all      - Build for both browsers
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const zlib = require('zlib');

// Parse command line arguments
const args = process.argv.slice(2);
const targetArg = args.find((arg) => arg.startsWith('--target='));
const target = targetArg ? targetArg.split('=')[1] : 'chrome';

const validTargets = ['chrome', 'firefox', 'all'];
if (!validTargets.includes(target)) {
  console.error(`Invalid target: ${target}. Valid targets: ${validTargets.join(', ')}`);
  process.exit(1);
}

const targets = target === 'all' ? ['chrome', 'firefox'] : [target];

for (const browserTarget of targets) {
  buildForTarget(browserTarget);
}

function buildForTarget(browserTarget) {
  const isFirefox = browserTarget === 'firefox';
  const distDir = isFirefox ? 'dist-firefox' : 'dist';

  console.log(`\n🏗️  Building PassKey Vault for ${browserTarget.toUpperCase()}...\n`);

  // Clean dist directory
  console.log(`🧹 Cleaning ${distDir} directory...`);
  if (fs.existsSync(distDir)) {
    fs.rmSync(distDir, { recursive: true, force: true });
  }
  fs.mkdirSync(distDir, { recursive: true });

  // Run TypeScript compiler
  console.log('📦 Compiling TypeScript...');
  try {
    execSync('npx tsc', { stdio: 'inherit' });
    console.log('✅ TypeScript compilation successful');
  } catch (error) {
    console.error('❌ TypeScript compilation failed');
    process.exit(1);
  }

  // The tsc outputs to dist/ but preserves directory structure.
  // We need to flatten and rename files for the extension.
  console.log('📋 Organizing output files...');

  // Move files from subdirectories to target dist root
  const fileMoves = [
    { from: 'dist/background/background.js', to: `${distDir}/background.js` },
    { from: 'dist/content/content.js', to: `${distDir}/content.js` },
    { from: 'dist/content/webauthn-inject.js', to: `${distDir}/webauthn-inject.js` },
    { from: 'dist/ui/passkey-ui.js', to: `${distDir}/passkey-ui.js` },
    { from: 'dist/ui/emergency-ui.js', to: `${distDir}/emergency-ui.js` },
    { from: 'dist/ui/popup.js', to: `${distDir}/popup.js` },
    { from: 'dist/ui/import.js', to: `${distDir}/import.js` },
  ];

  for (const { from, to } of fileMoves) {
    if (fs.existsSync(from)) {
      fs.copyFileSync(from, to);
      console.log(`  ✅ ${path.basename(to)}`);
    }
  }

  // Content script needs passkey-ui.js to be concatenated since it can't use imports
  console.log('📦 Bundling content script with UI...');
  const passkeyUiJs = fs.readFileSync(`${distDir}/passkey-ui.js`, 'utf8');
  const contentJs = fs.readFileSync(`${distDir}/content.js`, 'utf8');
  fs.writeFileSync(`${distDir}/content.js`, passkeyUiJs + '\n' + contentJs);
  fs.unlinkSync(`${distDir}/passkey-ui.js`);
  console.log('  ✅ content.js (bundled with passkey-ui)');

  // Process manifest based on target
  console.log('📋 Processing manifest...');
  const manifestFile = isFirefox ? 'src/manifest.firefox.json' : 'src/manifest.json';
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));

  if (isFirefox) {
    // Firefox MV2 adjustments
    manifest.background.scripts = ['background.js'];
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources = ['webauthn-inject.js'];
  } else {
    // Chrome MV3 adjustments
    manifest.background.service_worker = 'background.js';
    manifest.content_scripts[0].js = ['content.js'];
    manifest.web_accessible_resources[0].resources = ['webauthn-inject.js'];
  }

  fs.writeFileSync(`${distDir}/manifest.json`, JSON.stringify(manifest, null, 2));
  console.log('  ✅ manifest.json');

  // Create icons directory and resize icon.png
  const iconsDir = path.join(distDir, 'icons');
  fs.mkdirSync(iconsDir, { recursive: true });

  console.log('🎨 Processing icons...');

  const sourceIcon = 'icon.png';
  const iconSizes = [16, 48, 128];

  if (fs.existsSync(sourceIcon)) {
    // Use ImageMagick to resize the icon
    try {
      for (const size of iconSizes) {
        const outputPath = path.join(iconsDir, `icon${size}.png`);
        execSync(`convert "${sourceIcon}" -resize ${size}x${size} "${outputPath}"`, {
          stdio: 'pipe',
        });
      }
      console.log('  ✅ Resized icons from icon.png');
    } catch (error) {
      console.warn('  ⚠️  ImageMagick not available, generating placeholder icons');
      generatePlaceholderIcons(iconsDir, iconSizes);
    }
  } else {
    console.warn('  ⚠️  icon.png not found, generating placeholder icons');
    generatePlaceholderIcons(iconsDir, iconSizes);
  }

  function generatePlaceholderIcons(dir, sizes) {
    for (const size of sizes) {
      const png = createMinimalPNG(size, 74, 144, 217);
      fs.writeFileSync(path.join(dir, `icon${size}.png`), png);
    }
  }

  function createMinimalPNG(size, r, g, b) {
    const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

    const ihdr = Buffer.alloc(25);
    ihdr.writeUInt32BE(13, 0);
    ihdr.write('IHDR', 4);
    ihdr.writeUInt32BE(size, 8);
    ihdr.writeUInt32BE(size, 12);
    ihdr.writeUInt8(8, 16);
    ihdr.writeUInt8(2, 17);
    ihdr.writeUInt8(0, 18);
    ihdr.writeUInt8(0, 19);
    ihdr.writeUInt8(0, 20);
    ihdr.writeUInt32BE(zlib.crc32(ihdr.subarray(4, 21)), 21);

    const rawData = Buffer.alloc(size * (1 + size * 3));
    for (let y = 0; y < size; y++) {
      rawData[y * (1 + size * 3)] = 0;
      for (let x = 0; x < size; x++) {
        const offset = y * (1 + size * 3) + 1 + x * 3;
        const cx = size / 2,
          cy = size / 2;
        const dist = Math.sqrt((x - cx) ** 2 + (y - cy) ** 2);
        if (dist < size * 0.4) {
          rawData[offset] = 255;
          rawData[offset + 1] = 255;
          rawData[offset + 2] = 255;
        } else {
          rawData[offset] = r;
          rawData[offset + 1] = g;
          rawData[offset + 2] = b;
        }
      }
    }

    const compressed = zlib.deflateSync(rawData);
    const idat = Buffer.alloc(compressed.length + 12);
    idat.writeUInt32BE(compressed.length, 0);
    idat.write('IDAT', 4);
    compressed.copy(idat, 8);
    idat.writeUInt32BE(
      zlib.crc32(Buffer.concat([Buffer.from('IDAT'), compressed])),
      compressed.length + 8
    );

    const iend = Buffer.from([
      0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
    ]);

    return Buffer.concat([signature, ihdr, idat, iend]);
  }

  // Copy static assets
  console.log('📄 Copying static assets...');

  if (fs.existsSync('src/ui/emergency.html')) {
    fs.copyFileSync('src/ui/emergency.html', `${distDir}/emergency.html`);
    console.log('  ✅ emergency.html');
  }

  if (fs.existsSync('src/ui/popup.html')) {
    fs.copyFileSync('src/ui/popup.html', `${distDir}/popup.html`);
    console.log('  ✅ popup.html');
  }

  if (fs.existsSync('src/ui/popup.css')) {
    fs.copyFileSync('src/ui/popup.css', `${distDir}/popup.css`);
    console.log('  ✅ popup.css');
  }

  if (fs.existsSync('src/ui/import.html')) {
    fs.copyFileSync('src/ui/import.html', `${distDir}/import.html`);
    console.log('  ✅ import.html');
  }

  // Calculate total size
  let totalSize = 0;
  const files = fs
    .readdirSync(distDir)
    .filter((f) => !fs.statSync(path.join(distDir, f)).isDirectory());
  for (const file of files) {
    totalSize += fs.statSync(path.join(distDir, file)).size;
  }
  // Add icons
  fs.readdirSync(iconsDir).forEach((file) => {
    totalSize += fs.statSync(path.join(iconsDir, file)).size;
  });

  // Final summary
  console.log(`\n🎉 ${browserTarget.toUpperCase()} Build Complete!`);
  console.log(`📦 Extension: ${manifest.name} v${manifest.version}`);
  console.log(`📁 Output: ${distDir}/`);
  console.log(`💾 Total size: ${(totalSize / 1024).toFixed(1)}KB`);

  if (isFirefox) {
    console.log(`
🦊 Ready to install in Firefox!

Installation (Temporary):
1. Open about:debugging#/runtime/this-firefox
2. Click "Load Temporary Add-on..."
3. Select the manifest.json file in the "${distDir}" directory

Installation (Permanent - requires signing):
1. Create a ZIP file of the "${distDir}" directory
2. Submit to addons.mozilla.org for signing
3. Or use web-ext: npx web-ext sign --source-dir ${distDir}
`);
  } else {
    console.log(`
🚀 Ready to install in Chrome!

Installation:
1. Open chrome://extensions/
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the "${distDir}" directory
`);
  }
}

// Clean up TypeScript output subdirectories from dist/
// (tsc outputs to dist/ with subdirectories, but we flatten them)
// Note: Don't remove dist/icons - that's created by our build
const tscOutputDirs = [
  'dist/background',
  'dist/content',
  'dist/ui',
  'dist/agents',
  'dist/crypto',
  'dist/types',
];

tscOutputDirs.forEach((dir) => {
  if (fs.existsSync(dir)) {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch (e) {
      // Ignore errors
    }
  }
});
