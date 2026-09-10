/**
 * otpauth:// URI writer for the portable OTP shape.
 *
 * `crypto/totp.ts` owns the parser and the low-level builder; this wraps the
 * builder so export paths do not have to unpack a PortableOtp by hand.
 */

import { buildOtpauth } from '../crypto/totp';
import { PortableOtp } from './types';

export function buildOtpauthUri(entry: PortableOtp): string {
  return buildOtpauth({
    type: entry.type,
    issuer: entry.issuer,
    account: entry.account,
    secret: entry.secret,
    algorithm: entry.algorithm,
    digits: entry.digits,
    period: entry.period,
    counter: entry.counter,
  });
}
