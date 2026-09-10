/**
 * Passkey key-material plumbing for imports.
 *
 * Vendors hand us the same P-256 private key in four different wrappings:
 * base64 or base64url PKCS#8, PEM, a JWK object, or the bare 32-byte scalar.
 * Everything here funnels those into the one shape the vault stores:
 * standard base64 PKCS#8, plus the raw (uncompressed point) public key.
 */

import { arrayBufferToBase64, decodeBase64Flexible } from '../utils/base64';

const P256_SCALAR_BYTES = 32;

// PKCS#8 wrapper for a bare P-256 scalar: SEQUENCE { 0, AlgId(ecPublicKey,
// prime256v1), OCTET STRING { SEQUENCE { 1, OCTET STRING <32-byte key> } } }.
// Fixed-length, so the prefix is a constant and the scalar is appended.
const P256_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
  0x01, 0x04, 0x20,
]);

const PEM_BODY = /-----BEGIN [^-]+-----([\s\S]+?)-----END [^-]+-----/;

export interface JwkLike {
  kty?: string;
  crv?: string;
  d?: string;
  x?: string;
  y?: string;
}

function bytesToBase64(bytes: Uint8Array): string {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return arrayBufferToBase64(copy.buffer);
}

function looksLikePkcs8(bytes: Uint8Array): boolean {
  return bytes.length > 40 && bytes[0] === 0x30;
}

function pkcs8FromScalar(scalar: Uint8Array): Uint8Array {
  const out = new Uint8Array(P256_PKCS8_PREFIX.length + P256_SCALAR_BYTES);
  out.set(P256_PKCS8_PREFIX, 0);
  out.set(scalar, P256_PKCS8_PREFIX.length);
  return out;
}

async function pkcs8FromJwk(jwk: JwkLike): Promise<string> {
  const key = await crypto.subtle.importKey(
    'jwk',
    { ...jwk, kty: 'EC', crv: jwk.crv || 'P-256', ext: true },
    { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' },
    true,
    ['sign']
  );
  return arrayBufferToBase64(await crypto.subtle.exportKey('pkcs8', key));
}

/**
 * Accept whatever a vendor exported and return standard base64 PKCS#8.
 * Throws when the value carries no usable private key.
 */
export async function toPkcs8Base64(value: unknown): Promise<string> {
  if (value && typeof value === 'object' && !ArrayBuffer.isView(value)) {
    const jwk = value as JwkLike;
    if (!jwk.d) throw new Error('JWK has no private component');
    return pkcs8FromJwk(jwk);
  }

  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error('Missing private key');
  }

  const trimmed = value.trim();

  // A PEM block, or a JSON-encoded JWK squeezed into a CSV cell.
  if (trimmed.startsWith('{')) {
    return toPkcs8Base64(JSON.parse(trimmed) as JwkLike);
  }
  const pem = PEM_BODY.exec(trimmed);
  const body = pem ? pem[1].replace(/\s+/g, '') : trimmed;

  const bytes = new Uint8Array(decodeBase64Flexible(body));
  if (looksLikePkcs8(bytes)) return bytesToBase64(bytes);
  if (bytes.length === P256_SCALAR_BYTES) return bytesToBase64(pkcs8FromScalar(bytes));

  throw new Error('Unrecognised private key encoding');
}

/**
 * Derive the raw uncompressed public point (0x04 || X || Y) from a PKCS#8
 * private key. WebCrypto does the curve maths for us: exporting the private
 * key as JWK yields X and Y even when the DER carried only the scalar.
 */
export async function derivePublicKeyBase64(pkcs8Base64: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'pkcs8',
    decodeBase64Flexible(pkcs8Base64),
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign']
  );
  const jwk = (await crypto.subtle.exportKey('jwk', key)) as JwkLike;
  if (!jwk.x || !jwk.y) throw new Error('Private key did not yield a public point');

  const x = new Uint8Array(decodeBase64Flexible(jwk.x));
  const y = new Uint8Array(decodeBase64Flexible(jwk.y));
  const raw = new Uint8Array(1 + x.length + y.length);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 1 + x.length);
  return bytesToBase64(raw);
}
