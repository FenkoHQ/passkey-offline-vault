# Fenko Vault promo assets

- Banner: `promo-small.jpg`, 440 × 280, opaque JPEG.
- Banner master: `source/fenko-vault-banner.png`.
- Marquee: `promo-marquee.jpg`, 1400 × 560, opaque JPEG.
- Marquee master: `source/fenko-vault-marquee.png`.
- Video: `../video/fenko-vault-promo.mp4`, 1280 × 720, H.264, 30 fps.
- Review frames: `../video/review/`.

The video is silent with on-screen captions. It records the built extension
with sample accounts: vault browsing, search, credential details, adding a
2FA setup link, and exporting a password-protected backup. It does not
demonstrate signing in to a website. No real credentials are used.

Upload the MP4 to YouTube, then use its link in the Chrome Web Store video
field. Neither the video nor the banner has been published by this script.
See [Google's listing requirements](https://developer.chrome.com/docs/webstore/cws-dashboard-listing/).

Recreate the video:

```sh
npm run build:chrome
node scripts/capture-assets.js promo-video
```

Requires Playwright, Chromium and FFmpeg. Video files follow the repository's
existing `docs/video/` ignore rule. The capture uses a disposable browser
profile and adds presentation captions around the popup.

The banner uses the built-in image generation tool and the existing
`docs/brand/fenko-vault-logo.png` as its reference. Prompt:

> Create a new finished Chrome Web Store small promotional banner for Fenko
> Vault, aspect ratio 11:7, ideally 1320x840. Reference image is the existing
> Fenko Vault fox/shield logo: preserve its identity, use as a modest brand
> mark, do not redesign. Full bleed opaque charcoal #0D1117 background and
> warm amber #F5A623. Refined minimal editorial typography. Exact text only:
> "Fenko Vault" large, highly legible, and "Passkeys + 2FA. On your device."
> as a smaller readable two-line tagline. Left aligned typographic
> composition with ample breathing room, logo upper left, subtle fine amber
> graphic geometry on right suggesting a key and local vault, restrained
> flat design. No browser UI, no fake screenshots, no extra text, no gradients
> or glow, no rounded outer corners. Strong hierarchy and legibility at
> 440x280 pixels. This is a finished brand banner, not a mockup.

The generated master was resized to the store dimensions with ImageMagick.
`npm run capture:promo` also uses this master for the small tile.

The marquee uses the built-in image generation tool with the small banner
master as its reference. Prompt:

> Create the matching wide Chrome Web Store marquee promotional banner for
> the supplied Fenko Vault small promo image. Preserve its fox/shield logo
> identity, typography, charcoal background and amber line-art key and vault
> illustration. Recompose for a wide 5:2 aspect ratio, target 1400x560 pixels.
> Do not stretch the reference. Logo in upper left above the text, generous
> margins. Left portion: large white exact title "Fenko Vault". Below, amber
> exact tagline on two lines: "Passkeys + 2FA." and "On your device."
> Right portion: fine amber outline key and safe with shield keyhole and
> subtle dashed circular geometry. Opaque full bleed charcoal #0D1117,
> warm amber #F5A623. No UI screenshot, extra words, gradients, glow,
> mockup or rounded outer corners.

The marquee master was resized to 1400 × 560 with ImageMagick.
`npm run capture:promo` also uses this master for the marquee tile.
