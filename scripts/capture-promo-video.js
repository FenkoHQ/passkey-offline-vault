const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const FRAME = { width: 1280, height: 720 };
const HOLD_MS = 4200;

// Record the built popup with sample accounts and a separate caption area.
module.exports = async function capturePromo(api) {
  const { VIDEO_DIR, ROOT } = api;
  fs.mkdirSync(VIDEO_DIR, { recursive: true });
  const profileDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fenko-promo-'));
  const ctx = await api.launchWithExtension({
    profileDir,
    contextOpts: { viewport: FRAME, recordVideo: { dir: VIDEO_DIR, size: FRAME } },
  });
  const shots = path.join(VIDEO_DIR, 'review');
  fs.mkdirSync(shots, { recursive: true });
  let rawPath;
  let start;
  let length;
  try {
    const id = await api.getExtensionId(ctx);
    const opened = Date.now();
    const p = await api.extPage(ctx, id, 'popup.html');
    await api.injectPasskeys(p, api.MOCK_PASSKEYS);
    await api.injectTotp(p, api.MOCK_TOTP);
    await api.setTheme(p, 'dark');
    await p.evaluate(() => chrome.storage.local.set({ vault_warning_dismissed: true }));
    await p.reload();
    await api.waitReady(p);
    await p.locator('#vault-list').waitFor({ state: 'visible' });
    await p.addStyleTag({ content: `
      html, body { width:1280px!important; height:720px!important; max-height:none!important;
        overflow:hidden!important; background:#0d1117!important; }
      #main-container, .auth-screen { position:absolute!important; left:770px; top:62px;
        width:400px!important; height:580px!important; max-height:580px; overflow:auto;
        border:1px solid #30363d; border-radius:16px; box-shadow:0 28px 70px #0008; }
      .modal-overlay { left:730px!important; width:500px!important; }
      #promo-copy { position:absolute; left:76px; top:64px; width:590px; color:#e6edf3;
        font-family:'Saira',sans-serif; }
      #promo-brand { display:flex; gap:16px; align-items:center; font-size:25px; font-weight:600; }
      #promo-brand img { width:44px; height:55px; object-fit:contain; }
      #promo-step { margin-top:94px; color:#f5a623; font-size:15px; letter-spacing:3px; }
      #promo-title { font:normal 66px/1.06 Georgia,serif; margin:22px 0; letter-spacing:-2px; }
      #promo-text { font-size:24px; line-height:1.5; color:#aeb8c4; max-width:540px; }
      #promo-footer { position:absolute; left:76px; bottom:46px; color:#77828f;
        font:15px 'Saira',sans-serif; letter-spacing:1px; }
      #promo-line { position:absolute; left:76px; top:610px; width:60px; height:3px; background:#f5a623; }
    ` });
    const logo = fs.readFileSync(path.join(ROOT, 'docs/brand/fenko-vault-logo.png')).toString('base64');
    await p.evaluate((logoData) => {
      const copy = document.createElement('section');
      copy.id = 'promo-copy';
      copy.innerHTML = `<div id="promo-brand"><img alt="" src="data:image/png;base64,${logoData}">Fenko Vault</div>
        <div id="promo-step"></div><h1 id="promo-title"></h1><p id="promo-text"></p>`;
      document.body.append(copy);
      const footer = document.createElement('div');
      footer.id = 'promo-footer';
      footer.textContent = 'CHROME EXTENSION  /  DEMO ACCOUNTS';
      document.body.append(footer);
      const line = document.createElement('div');
      line.id = 'promo-line';
      document.body.append(line);
    }, logo);

    const caption = async (step, title, text) => {
      await p.evaluate((data) => {
        document.getElementById('promo-step').textContent = data.step;
        document.getElementById('promo-title').textContent = data.title;
        document.getElementById('promo-text').textContent = data.text;
      }, { step, title, text });
      console.log(`  ${step}: ${title}`);
    };
    const hold = () => p.waitForTimeout(HOLD_MS);
    const shot = (name) => p.screenshot({ path: path.join(shots, `${name}.png`) });

    await caption('01 / YOUR VAULT', 'Passkeys + 2FA. On your device.',
      'Keep your passkeys and authenticator codes in one searchable vault.');
    start = (Date.now() - opened) / 1000;
    const began = Date.now();
    await shot('01-vault');
    await hold();

    await caption('02 / FIND AN ACCOUNT', 'Search once. Find both.',
      'Search for a site to see its saved passkeys and 2FA codes together.');
    await p.locator('#search-input').pressSequentially('git', { delay: 220 });
    await hold();
    await shot('02-search');
    await p.locator('.passkey-item .expand-btn').first().click();
    await p.waitForTimeout(1600);
    await p.locator('.passkey-item .expand-btn').first().click();

    await caption('03 / TWO-FACTOR CODES', 'Your next code is right here.',
      'Generate codes locally. Use the copy button when a site asks for 2FA.');
    await p.locator('.totp-item .expand-btn').first().click();
    await hold();
    await shot('03-codes');
    await p.locator('.totp-item .expand-btn').first().click();
    await p.fill('#search-input', '');

    await caption('04 / ADD AN AUTHENTICATOR', 'Bring your 2FA with you.',
      'Paste a setup link, paste a QR screenshot, or choose a QR image.');
    await p.click('#add-totp-btn');
    await p.waitForTimeout(1200);
    await p.fill('#totp-uri-input',
      'otpauth://totp/Example:demo@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example');
    await hold();
    await shot('04-add-code');
    await p.click('#totp-add-save');
    await p.locator('#totp-uri-input').waitFor({ state: 'detached' });
    await p.fill('#search-input', 'demo@example.com');
    await p.locator('.totp-item').filter({ hasText: 'demo@example.com' }).waitFor({ state: 'visible' });
    await p.waitForTimeout(2500);

    await caption('05 / KEEP A BACKUP', 'Export. Keep it offline.',
      'Protect your backup with a password, then store the file somewhere safe.');
    await p.fill('#search-input', '');
    const downloadEvent = p.waitForEvent('download');
    await p.click('#export-full-btn');
    await p.fill('#prompt-password', 'Demo-backup-only-2026');
    await p.fill('#prompt-password-confirm', 'Demo-backup-only-2026');
    await hold();
    await shot('05-backup');
    await p.click('#prompt-ok');
    const download = await downloadEvent;
    if (await download.failure()) {
      throw new Error('Demo backup download failed');
    }
    await hold();

    await caption('FENKO VAULT', 'Keep your keys close.',
      'Get Fenko Vault from the Chrome Web Store.');
    await hold();
    await shot('06-end');
    length = (Date.now() - began) / 1000;
    rawPath = await p.video().path();
  } finally {
    await ctx.close();
  }

  const output = path.join(VIDEO_DIR, 'fenko-vault-promo.mp4');
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', String(start), '-i', rawPath,
    '-t', String(length), '-vf', 'fps=30,format=yuv420p', '-c:v', 'libx264',
    '-preset', 'medium', '-crf', '18', '-movflags', '+faststart', output], { stdio: 'inherit' });
  fs.unlinkSync(rawPath);
  console.log(`  Saved ${output}`);
};
