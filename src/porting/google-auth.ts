/**
 * Google Authenticator "export accounts" payloads.
 *
 * The export QR encodes `otpauth-migration://offline?data=<base64 protobuf>`.
 * Rather than pull in a protobuf runtime we read the handful of wire fields
 * the MigrationPayload uses:
 *
 *   MigrationPayload { repeated OtpParameters otp_parameters = 1 }
 *   OtpParameters { bytes secret=1, string name=2, string issuer=3,
 *                   enum algorithm=4, enum digits=5, enum type=6,
 *                   int64 counter=7 }
 */

import { decodeBase64Flexible } from '../utils/base64';
import { OtpAlgorithm, OtpType, PortableOtp, DEFAULT_PERIOD } from './types';
import { splitLabel } from './otp';

const WIRE_VARINT = 0;
const WIRE_64BIT = 1;
const WIRE_LENGTH = 2;
const WIRE_32BIT = 5;

const FIELD_OTP_PARAMETERS = 1;
const FIELD_SECRET = 1;
const FIELD_NAME = 2;
const FIELD_ISSUER = 3;
const FIELD_ALGORITHM = 4;
const FIELD_DIGITS = 5;
const FIELD_TYPE = 6;
const FIELD_COUNTER = 7;

const ALGORITHMS: Record<number, OtpAlgorithm> = { 1: 'SHA1', 2: 'SHA256', 3: 'SHA512' };
const DIGIT_COUNTS: Record<number, number> = { 1: 6, 2: 8 };

interface Field {
  number: number;
  wireType: number;
  varint: number;
  bytes: Uint8Array;
}

class Reader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  get done(): boolean {
    return this.offset >= this.bytes.length;
  }

  private varint(): number {
    let result = 0;
    let shift = 0;
    while (this.offset < this.bytes.length) {
      const byte = this.bytes[this.offset++];
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
    }
    throw new Error('Truncated varint');
  }

  next(): Field {
    const key = this.varint();
    const number = key >>> 3;
    const wireType = key & 0x07;

    if (wireType === WIRE_VARINT) {
      return { number, wireType, varint: this.varint(), bytes: new Uint8Array(0) };
    }
    if (wireType === WIRE_LENGTH) {
      const length = this.varint();
      const bytes = this.bytes.subarray(this.offset, this.offset + length);
      this.offset += length;
      return { number, wireType, varint: 0, bytes };
    }
    if (wireType === WIRE_64BIT || wireType === WIRE_32BIT) {
      this.offset += wireType === WIRE_64BIT ? 8 : 4;
      return { number, wireType, varint: 0, bytes: new Uint8Array(0) };
    }
    throw new Error(`Unsupported protobuf wire type: ${wireType}`);
  }
}

function decodeParameters(bytes: Uint8Array): PortableOtp | null {
  const reader = new Reader(bytes);
  const decoder = new TextDecoder();

  let secret = new Uint8Array(0);
  let name = '';
  let issuerField = '';
  let algorithm: OtpAlgorithm = 'SHA1';
  let digits = 6;
  let type: OtpType = 'totp';
  let counter = 0;

  while (!reader.done) {
    const field = reader.next();
    switch (field.number) {
      case FIELD_SECRET:
        secret = new Uint8Array(field.bytes);
        break;
      case FIELD_NAME:
        name = decoder.decode(field.bytes);
        break;
      case FIELD_ISSUER:
        issuerField = decoder.decode(field.bytes);
        break;
      case FIELD_ALGORITHM:
        algorithm = ALGORITHMS[field.varint] || 'SHA1';
        break;
      case FIELD_DIGITS:
        digits = DIGIT_COUNTS[field.varint] || 6;
        break;
      case FIELD_TYPE:
        type = field.varint === 1 ? 'hotp' : 'totp';
        break;
      case FIELD_COUNTER:
        counter = field.varint;
        break;
    }
  }

  if (secret.length === 0) return null;

  const { issuer, account } = splitLabel(name, issuerField);

  return { type, issuer, account, secret, algorithm, digits, period: DEFAULT_PERIOD, counter };
}

export function isMigrationUri(value: string): boolean {
  return value.trim().toLowerCase().startsWith('otpauth-migration://');
}

/** Decode one otpauth-migration:// URI into its accounts. */
export function parseMigrationUri(uri: string): PortableOtp[] {
  const query = uri.slice(uri.indexOf('?') + 1);
  const data = new URLSearchParams(query).get('data');
  if (!data) throw new Error('Migration URI has no data parameter');

  const reader = new Reader(new Uint8Array(decodeBase64Flexible(data)));
  const entries: PortableOtp[] = [];

  while (!reader.done) {
    const field = reader.next();
    if (field.number !== FIELD_OTP_PARAMETERS || field.wireType !== WIRE_LENGTH) continue;
    const entry = decodeParameters(field.bytes);
    if (entry) entries.push(entry);
  }

  return entries;
}
