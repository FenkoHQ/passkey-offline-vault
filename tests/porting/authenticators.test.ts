import { parseImport } from '../../src/porting/import';
import { base32Encode } from '../../src/crypto/totp';
import { arrayBufferToBase64URL } from '../../src/utils/base64';

const SECRET_B32 = 'JBSWY3DPEHPK3PXP';

function secretsOf(text: string, name = 'export.json'): string[] {
  return parseImport(name, text).otp.map((entry) => base32Encode(entry.secret));
}

describe('authenticator app imports', () => {
  it('reads a plain otpauth:// list', () => {
    const text = [
      '# exported by Ente Auth',
      `otpauth://totp/GitHub:ali%40example.com?secret=${SECRET_B32}&issuer=GitHub`,
      `otpauth://hotp/Bank:ali?secret=${SECRET_B32}&counter=7&digits=8`,
    ].join('\n');

    const parsed = parseImport('ente.txt', text);
    expect(parsed.format).toBe('otpauth-text');
    expect(parsed.otp).toHaveLength(2);
    expect(parsed.otp[0]).toMatchObject({ issuer: 'GitHub', account: 'ali@example.com' });
    expect(parsed.otp[1]).toMatchObject({ type: 'hotp', counter: 7, digits: 8 });
  });

  it('reads an Aegis vault', () => {
    const text = JSON.stringify({
      version: 1,
      header: { slots: null, params: null },
      db: {
        version: 3,
        entries: [
          {
            type: 'totp',
            uuid: 'a',
            name: 'ali@example.com',
            issuer: 'GitHub',
            info: { secret: SECRET_B32, algo: 'SHA256', digits: 8, period: 60 },
          },
        ],
      },
    });

    const parsed = parseImport('aegis.json', text);
    expect(parsed.format).toBe('aegis');
    expect(parsed.otp[0]).toMatchObject({
      issuer: 'GitHub',
      account: 'ali@example.com',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
    });
  });

  it('refuses an encrypted Aegis vault with a fixable message', () => {
    const text = JSON.stringify({ version: 1, header: { slots: [{}] }, db: 'BASE64CIPHERTEXT' });
    expect(() => parseImport('aegis.json', text)).toThrow(/encrypted/i);
  });

  it('reads a 2FAS backup', () => {
    const text = JSON.stringify({
      schemaVersion: 4,
      services: [
        {
          name: 'GitHub',
          secret: SECRET_B32,
          otp: { account: 'ali', issuer: 'GitHub', digits: 6, period: 30, tokenType: 'TOTP' },
        },
      ],
    });

    const parsed = parseImport('backup.2fas', text);
    expect(parsed.format).toBe('2fas');
    expect(parsed.otp[0]).toMatchObject({ issuer: 'GitHub', account: 'ali' });
  });

  it('refuses a password-protected 2FAS backup', () => {
    const text = JSON.stringify({ schemaVersion: 4, servicesEncrypted: 'abc:def:ghi' });
    expect(() => parseImport('backup.2fas', text)).toThrow(/password-protected/i);
  });

  it('reads andOTP', () => {
    const text = JSON.stringify([
      {
        secret: SECRET_B32,
        label: 'ali@example.com',
        issuer: 'GitHub',
        digits: 6,
        type: 'TOTP',
        algorithm: 'SHA1',
        period: 30,
      },
    ]);
    expect(secretsOf(text)).toEqual([SECRET_B32]);
    expect(parseImport('andotp.json', text).format).toBe('andotp');
  });

  it('reads FreeOTP+ signed byte secrets', () => {
    const text = JSON.stringify({
      tokens: [
        {
          algo: 'SHA1',
          counter: 0,
          digits: 6,
          issuerExt: 'GitHub',
          label: 'ali',
          period: 30,
          secret: [72, 101, 108, 108, 111, -34, -83, -66, -17],
          type: 'TOTP',
        },
      ],
    });

    const parsed = parseImport('freeotp.json', text);
    expect(parsed.format).toBe('freeotp');
    expect(Array.from(parsed.otp[0].secret.slice(5))).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it('reads Raivo OTP', () => {
    const text = JSON.stringify([
      {
        issuer: 'GitHub',
        account: 'ali',
        secret: SECRET_B32,
        algorithm: 'SHA1',
        digits: '6',
        timer: '30',
        kind: 'TOTP',
      },
    ]);
    expect(parseImport('raivo.json', text).format).toBe('raivo');
    expect(secretsOf(text)).toEqual([SECRET_B32]);
  });

  it('reads LastPass Authenticator', () => {
    const text = JSON.stringify({
      version: 3,
      deviceName: 'phone',
      accounts: [
        {
          issuerName: 'GitHub',
          userName: 'ali',
          secret: SECRET_B32,
          algorithm: 'SHA1',
          digits: 6,
          timeStep: 30,
        },
      ],
    });
    expect(parseImport('lastpass-auth.json', text).format).toBe('lastpass-authenticator');
    expect(secretsOf(text)).toEqual([SECRET_B32]);
  });

  it('falls back to the generic OTP array shape', () => {
    const text = JSON.stringify([{ secret: SECRET_B32, account: 'ali', issuer: 'Fastmail' }]);
    const parsed = parseImport('unknown-app.json', text);
    expect(parsed.format).toBe('generic-otp-json');
    expect(parsed.otp[0]).toMatchObject({ issuer: 'Fastmail', account: 'ali' });
  });

  it('keeps going when one entry is broken', () => {
    const text = JSON.stringify([
      { secret: '!!!not base32!!!', label: 'broken', issuer: 'X' },
      { secret: SECRET_B32, label: 'ali', issuer: 'GitHub' },
    ]);
    const parsed = parseImport('andotp.json', text);
    expect(parsed.otp).toHaveLength(1);
    expect(parsed.warnings[0]).toMatch(/Entry 1/);
  });
});

// ==================== Google Authenticator ====================

function varint(value: number): number[] {
  const out: number[] = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining >>>= 7;
    if (remaining > 0) byte |= 0x80;
    out.push(byte);
  } while (remaining > 0);
  return out;
}

function lengthField(fieldNumber: number, payload: number[]): number[] {
  return [...varint((fieldNumber << 3) | 2), ...varint(payload.length), ...payload];
}

function varintField(fieldNumber: number, value: number): number[] {
  return [...varint(fieldNumber << 3), ...varint(value)];
}

function migrationUri(): string {
  const secret = [0x48, 0x65, 0x6c, 0x6c, 0x6f];
  const name = Array.from(new TextEncoder().encode('GitHub:ali@example.com'));
  const issuer = Array.from(new TextEncoder().encode('GitHub'));

  const parameters = [
    ...lengthField(1, secret),
    ...lengthField(2, name),
    ...lengthField(3, issuer),
    ...varintField(4, 2), // SHA256
    ...varintField(5, 2), // eight digits
    ...varintField(6, 2), // TOTP
  ];

  const payload = new Uint8Array([...lengthField(1, parameters), ...varintField(2, 1)]);
  const data = arrayBufferToBase64URL(payload.buffer);
  return `otpauth-migration://offline?data=${encodeURIComponent(data)}`;
}

describe('Google Authenticator migration payloads', () => {
  it('expands every account in the QR payload', () => {
    const parsed = parseImport('google.txt', migrationUri());

    expect(parsed.otp).toHaveLength(1);
    expect(parsed.otp[0]).toMatchObject({
      type: 'totp',
      issuer: 'GitHub',
      account: 'ali@example.com',
      algorithm: 'SHA256',
      digits: 8,
    });
    expect(new TextDecoder().decode(parsed.otp[0].secret)).toBe('Hello');
  });
});
