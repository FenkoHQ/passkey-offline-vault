import { parseImport } from '../../src/porting/import';
import { buildExport } from '../../src/porting/export';
import { base32Encode } from '../../src/crypto/totp';
import { arrayBufferToBase64, arrayBufferToBase64URL } from '../../src/utils/base64';

const SECRET_B32 = 'JBSWY3DPEHPK3PXP';

let pkcs8 = '';
let pkcs8Url = '';

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  pkcs8 = arrayBufferToBase64(exported);
  pkcs8Url = arrayBufferToBase64URL(exported);
});

function cxfDocument(): string {
  return JSON.stringify({
    version: { major: 0, minor: 0 },
    exporterRpId: 'icloud.com',
    exporterDisplayName: 'iCloud Passwords',
    timestamp: 1750000000,
    accounts: [
      {
        id: 'acct',
        userName: 'ali',
        email: 'ali@example.com',
        collections: [],
        items: [
          {
            id: 'item-1',
            creationAt: 1750000000,
            modifiedAt: 1750000000,
            type: 'login',
            title: 'GitHub',
            credentials: [
              {
                type: 'passkey',
                credentialId: 'Y3JlZC1pZA',
                rpId: 'github.com',
                userName: 'ali@example.com',
                userDisplayName: 'Ali',
                userHandle: 'dXNlci1oYW5kbGU',
                key: pkcs8Url,
                fido2Extensions: {},
              },
              {
                type: 'totp',
                secret: arrayBufferToBase64URL(new Uint8Array([1, 2, 3, 4, 5]).buffer),
                period: 30,
                digits: 6,
                username: 'ali@example.com',
                algorithm: 'sha256',
                issuer: 'GitHub',
              },
            ],
          },
        ],
      },
    ],
  });
}

describe('Credential Exchange Format', () => {
  it('reads passkeys and MFA out of a CXF document', () => {
    const parsed = parseImport('cxf.json', cxfDocument());

    expect(parsed.format).toBe('cxf');
    expect(parsed.passkeys[0]).toMatchObject({
      rpId: 'github.com',
      credentialId: 'Y3JlZC1pZA',
      userDisplayName: 'Ali',
    });
    expect(parsed.otp[0]).toMatchObject({ issuer: 'GitHub', algorithm: 'SHA256' });
    expect(Array.from(parsed.otp[0].secret)).toEqual([1, 2, 3, 4, 5]);
  });

  it('round-trips our own CXF export back through the importer', () => {
    const file = buildExport('cxf', {
      passkeys: [
        {
          id: 'Y3JlZC1pZA',
          credentialId: 'Y3JlZC1pZA',
          type: 'public-key',
          rpId: 'github.com',
          origin: 'https://github.com',
          user: { id: 'dXNlci1oYW5kbGU', name: 'ali', displayName: 'Ali' },
          privateKey: pkcs8,
          publicKey: 'ignored',
          createdAt: 1750000000000,
          counter: 0,
        },
      ],
      totpEntries: [
        {
          id: 'totp-1',
          type: 'totp',
          issuer: 'GitHub',
          account: 'ali',
          secretB64: arrayBufferToBase64(new Uint8Array([72, 101, 108, 108, 111]).buffer),
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
          counter: 0,
          createdAt: 1750000000000,
        },
      ],
    });

    expect(file.fileName).toMatch(/^fenko-vault-cxf-\d{4}-\d{2}-\d{2}\.json$/);

    const parsed = parseImport(file.fileName, file.content);
    expect(parsed.format).toBe('cxf');
    expect(parsed.passkeys[0].rpId).toBe('github.com');
    expect(parsed.otp[0].issuer).toBe('GitHub');
    expect(base32Encode(parsed.otp[0].secret)).toBe(base32Encode(new Uint8Array([72, 101, 108, 108, 111])));
  });

  it('exports MFA as otpauth URIs an authenticator can read back', () => {
    const file = buildExport('otpauth-txt', {
      passkeys: [],
      totpEntries: [
        {
          id: 'totp-1',
          type: 'totp',
          issuer: 'GitHub',
          account: 'ali@example.com',
          secretB64: arrayBufferToBase64(new Uint8Array([72, 101, 108, 108, 111]).buffer),
          algorithm: 'SHA512',
          digits: 8,
          period: 60,
          counter: 0,
          createdAt: 1,
        },
      ],
    });

    expect(file.content).toContain('otpauth://totp/');
    const parsed = parseImport('mfa.txt', file.content);
    expect(parsed.otp[0]).toMatchObject({
      issuer: 'GitHub',
      account: 'ali@example.com',
      algorithm: 'SHA512',
      digits: 8,
      period: 60,
    });
    expect(SECRET_B32).toBeTruthy();
  });
});
