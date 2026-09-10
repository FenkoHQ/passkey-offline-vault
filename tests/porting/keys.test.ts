import { derivePublicKeyBase64, toPkcs8Base64 } from '../../src/porting/keys';
import { arrayBufferToBase64, arrayBufferToBase64URL } from '../../src/utils/base64';

async function makeKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
}

describe('passkey key normalisation', () => {
  it('accepts base64, base64url and PEM PKCS#8', async () => {
    const pair = await makeKeyPair();
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
    const base64 = arrayBufferToBase64(pkcs8);
    const base64url = arrayBufferToBase64URL(pkcs8);
    const pem = `-----BEGIN PRIVATE KEY-----\n${base64.replace(/(.{64})/g, '$1\n')}\n-----END PRIVATE KEY-----`;

    expect(await toPkcs8Base64(base64)).toBe(base64);
    expect(await toPkcs8Base64(base64url)).toBe(base64);
    expect(await toPkcs8Base64(pem)).toBe(base64);
  });

  it('accepts a JWK object and a JWK squeezed into a string', async () => {
    const pair = await makeKeyPair();
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const expected = arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));

    expect(await toPkcs8Base64(jwk)).toBe(expected);
    expect(await toPkcs8Base64(JSON.stringify(jwk))).toBe(expected);
  });

  it('derives the same raw public key the vault stores', async () => {
    const pair = await makeKeyPair();
    const pkcs8 = arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
    const expected = arrayBufferToBase64(await crypto.subtle.exportKey('raw', pair.publicKey));

    expect(await derivePublicKeyBase64(pkcs8)).toBe(expected);
  });

  it('rebuilds PKCS#8 from a bare 32-byte scalar', async () => {
    const pair = await makeKeyPair();
    const jwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as { d: string };
    const expected = arrayBufferToBase64(await crypto.subtle.exportKey('raw', pair.publicKey));

    const pkcs8 = await toPkcs8Base64(jwk.d);
    expect(await derivePublicKeyBase64(pkcs8)).toBe(expected);
  });

  it('rejects junk', async () => {
    await expect(toPkcs8Base64('')).rejects.toThrow(/Missing private key/);
    await expect(toPkcs8Base64('AAAA')).rejects.toThrow(/Unrecognised/);
  });
});
