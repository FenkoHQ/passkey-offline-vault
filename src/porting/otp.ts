/**
 * Vendor-neutral helpers for turning loose OTP fields into a PortableOtp.
 *
 * Every authenticator app spells the same five parameters differently
 * ("timeStep" vs "period", "SHA-1" vs "sha1", digits as an enum). This is the
 * one place that mess is normalised.
 */

import { base32Decode, parseOtpauth } from '../crypto/totp';
import { decodeBase64Flexible } from '../utils/base64';
import { DEFAULT_DIGITS, DEFAULT_PERIOD, OtpAlgorithm, OtpType, PortableOtp } from './types';

export type SecretEncoding = 'base32' | 'base64' | 'hex';

export interface LooseOtpFields {
  type?: unknown;
  issuer?: unknown;
  account?: unknown;
  label?: unknown;
  secret: unknown;
  secretEncoding?: SecretEncoding;
  algorithm?: unknown;
  digits?: unknown;
  period?: unknown;
  counter?: unknown;
}

const MIN_DIGITS = 6;
const MAX_DIGITS = 10;

export function normalizeAlgorithm(value: unknown): OtpAlgorithm {
  const raw = String(value ?? '')
    .toUpperCase()
    .replace(/[\s_-]/g, '');
  if (raw === 'SHA256' || raw === '2') return 'SHA256';
  if (raw === 'SHA512' || raw === '3') return 'SHA512';
  return 'SHA1';
}

export function normalizeType(value: unknown): OtpType {
  const raw = String(value ?? '').toLowerCase();
  return raw.includes('hotp') || raw === '1' ? 'hotp' : 'totp';
}

function toInt(value: unknown, fallback: number): number {
  const parsed = parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function hexDecode(input: string): Uint8Array {
  const clean = input.replace(/[\s:-]/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex secret');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Decode a secret. Defaults to base32 (what every authenticator QR uses);
 * FreeOTP+ and a few JSON exports store raw bytes or hex instead.
 */
export function decodeSecret(value: unknown, encoding: SecretEncoding = 'base32'): Uint8Array {
  if (value instanceof Uint8Array) return value;

  // FreeOTP+ writes secrets as an array of signed Java bytes.
  if (Array.isArray(value)) {
    return new Uint8Array(value.map((byte) => Number(byte) & 0xff));
  }

  const raw = String(value ?? '').trim();
  if (!raw) throw new Error('Missing OTP secret');

  if (encoding === 'hex') return hexDecode(raw);
  if (encoding === 'base64') return new Uint8Array(decodeBase64Flexible(raw));
  return base32Decode(raw.replace(/[\s-]/g, ''));
}

/**
 * Split a "Issuer:account" or "Issuer (account)" label the way otpauth does.
 */
export function splitLabel(label: string, issuerHint = ''): { issuer: string; account: string } {
  const text = label.trim();
  if (!text) return { issuer: issuerHint.trim(), account: '' };

  const colon = text.indexOf(':');
  if (colon > 0) {
    const issuer = issuerHint.trim() || text.slice(0, colon).trim();
    return { issuer, account: text.slice(colon + 1).trim() };
  }
  return { issuer: issuerHint.trim(), account: text };
}

export function makeOtp(fields: LooseOtpFields): PortableOtp {
  const secret = decodeSecret(fields.secret, fields.secretEncoding);
  if (secret.length === 0) throw new Error('Empty OTP secret');

  const label = String(fields.label ?? fields.account ?? '');
  const { issuer, account } = splitLabel(label, String(fields.issuer ?? ''));

  const digits = toInt(fields.digits, DEFAULT_DIGITS);

  return {
    type: normalizeType(fields.type),
    issuer,
    account,
    secret,
    algorithm: normalizeAlgorithm(fields.algorithm),
    digits: digits < MIN_DIGITS || digits > MAX_DIGITS ? DEFAULT_DIGITS : digits,
    period: toInt(fields.period, DEFAULT_PERIOD),
    counter: Math.max(0, parseInt(String(fields.counter ?? '0'), 10) || 0),
  };
}

/** Parse an otpauth:// URI into a PortableOtp. */
export function otpFromUri(uri: string): PortableOtp {
  const parsed = parseOtpauth(uri);
  return {
    type: parsed.type,
    issuer: parsed.issuer,
    account: parsed.account,
    secret: parsed.secret,
    algorithm: parsed.algorithm,
    digits: parsed.digits,
    period: parsed.period,
    counter: parsed.counter,
  };
}

/**
 * Many password managers store the TOTP column as either a full otpauth URI
 * or a naked base32 secret. Accept both.
 */
export function otpFromManagerField(
  field: string,
  issuer: string,
  account: string
): PortableOtp | null {
  const value = field.trim();
  if (!value) return null;

  if (value.toLowerCase().startsWith('otpauth://')) {
    const otp = otpFromUri(value);
    return {
      ...otp,
      issuer: otp.issuer || issuer,
      account: otp.account || account,
    };
  }

  if (value.toLowerCase().startsWith('otpauth-migration://')) return null;

  return makeOtp({ secret: value, issuer, account });
}
