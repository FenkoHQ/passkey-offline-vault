const fs = require('fs');
const path = require('path');

// Create placeholder icon files if they don't exist
const iconsPath = path.join(__dirname, '..', 'src', 'icons');
const iconSizes = [16, 48, 128];

if (!fs.existsSync(iconsPath)) {
  fs.mkdirSync(iconsPath, { recursive: true });
}

// Create simple placeholder SVG icons
const createIconSvg = (size) => {
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
    <rect width="${size}" height="${size}" fill="#4a9eff"/>
    <text x="50%" y="50%" text-anchor="middle" dy=".3em" fill="white" font-family="Arial" font-size="${size/3}">🔐</text>
  </svg>`;
};

iconSizes.forEach(size => {
  const iconPath = path.join(iconsPath, `icon${size}.png`);
  if (!fs.existsSync(iconPath)) {
    // Create a simple placeholder file
    const placeholder = `// Placeholder for icon${size}.png
// Replace with actual icon file
// You can generate one from the SVG above:
${createIconSvg(size)}`;
    fs.writeFileSync(iconPath.replace('.png', '.txt'), placeholder);
    console.log(`Created placeholder for icon${size}.png`);
  }
});

console.log('Post-install setup completed');