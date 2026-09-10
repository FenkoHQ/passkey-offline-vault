/**
 * FIDO Alliance Credential Exchange Format (CXF).
 *
 * The one format built for this job: Apple, Google, 1Password, Bitwarden and
 * Dashlane all move passkeys through it, so it is both our best import source
 * and the format we export when the destination is another provider.
 *
 * Shape: accounts[] -> items[] -> credentials[], where a credential is tagged
 * `passkey` or `totp`. Byte fields (credentialId, userHandle, key, secret) are
 * base64url.
 */

import { FormatParser, ParsedImport, PortableOtp, PortablePasskey, emptyImport } from '../types';
import { arrayBufferToBase64URL, decodeBase64Flexible } from '../../utils/base64';
import { base32Encode } from '../../crypto/totp';
import { makeOtp, otpFromUri } from '../otp';

type Json = Record<string, unknown>;

const CXF_VERSION = { major: 0, minor: 0 };
const PASSKEY_TYPE = 'passkey';
const TOTP_TYPE = 'totp';

function asObject(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function str(value: unknown): string {
  return value == null ? '' : String(value);
}

/** Items live under accounts[].items or, in flatter exports, at the root. */
function collectItems(json: Json): Json[] {
  const items: Json[] = [];

  for (const account of asArray(json.accounts)) {
    const record = asObject(account);
    if (!record) continue;
    items.push(...(asArray(record.items).map(asObject).filter(Boolean) as Json[]));
    for (const collection of asArray(record.collections)) {
      items.push(...(asArray(asObject(collection)?.items).map(asObject).filter(Boolean) as Json[]));
    }
  }

  items.push(...(asArray(json.items).map(asObject).filter(Boolean) as Json[]));
  return items;
}

function credentialsOf(item: Json): Json[] {
  return asArray(item.credentials).map(asObject).filter(Boolean) as Json[];
}

function toOtp(credential: Json, title: string): PortableOtp {
  // Early drafts carried a whole otpauth:// URI; the ratified shape carries
  // the raw secret bytes as base64url.
  const uri = str(credential.uri || credential.otpauth);
  if (uri) return otpFromUri(uri);

  // The spec carries raw secret bytes as base64url — not base32 — so decode
  // strictly. Base32 would silently decode too and corrupt every seed.
  const secret = new Uint8Array(decodeBase64Flexible(credential.secret));

  return makeOtp({
    type: TOTP_TYPE,
    issuer: credential.issuer || title,
    account: credential.username || credential.userName,
    secret,
    algorithm: credential.algorithm,
    digits: credential.digits,
    period: credential.period,
  });
}

function toPasskey(credential: Json, item: Json): PortablePasskey {
  return {
    credentialId: str(credential.credentialId),
    rpId: str(credential.rpId),
    userName: str(credential.userName),
    userDisplayName: str(credential.userDisplayName) || str(credential.userName),
    userHandle: credential.userHandle == null ? null : str(credential.userHandle),
    privateKey: credential.key,
    counter: Number(credential.signCount) || 0,
    createdAt: Number(item.creationAt) * 1000 || Number(credential.createdAt) || Date.now(),
  };
}

export const cxf: FormatParser = {
  id: 'cxf',
  label: 'Credential Exchange Format (Apple, Google, 1Password, Bitwarden, Dashlane)',
  extensions: ['.json', '.cxf'],

  detect(input) {
    const json = asObject(input.json);
    if (!json) return false;
    if ('exporterRpId' in json || 'exporterDisplayName' in json) return true;
    return collectItems(json).some((item) =>
      credentialsOf(item).some((credential) => {
        const type = str(credential.type).toLowerCase();
        return type === PASSKEY_TYPE || type === TOTP_TYPE;
      })
    );
  },

  parse(input) {
    const result = emptyImport(cxf.id, cxf.label);
    const json = asObject(input.json) as Json;

    for (const item of collectItems(json)) {
      const title = str(item.title);
      for (const credential of credentialsOf(item)) {
        const type = str(credential.type).toLowerCase();
        try {
          if (type === PASSKEY_TYPE && credential.key) {
            result.passkeys.push(toPasskey(credential, item));
          } else if (type === TOTP_TYPE) {
            result.otp.push(toOtp(credential, title));
          }
        } catch (error) {
          result.warnings.push(`${title || 'Item'}: ${(error as Error).message}`);
        }
      }
    }

    return result;
  },
};

export interface CxfSource {
  passkeys: PortablePasskey[];
  otp: PortableOtp[];
  exporterRpId: string;
  exporterDisplayName: string;
}

/** Build a CXF document another provider can import. */
export function buildCxf(source: CxfSource): Json {
  const timestamp = Math.floor(Date.now() / 1000);

  const passkeyItems = source.passkeys.map((passkey) => ({
    id: passkey.credentialId,
    creationAt: Math.floor(passkey.createdAt / 1000),
    modifiedAt: timestamp,
    type: 'login',
    title: passkey.rpId,
    credentials: [
      {
        type: PASSKEY_TYPE,
        credentialId: passkey.credentialId,
        rpId: passkey.rpId,
        userName: passkey.userName,
        userDisplayName: passkey.userDisplayName,
        userHandle: passkey.userHandle || '',
        key: str(passkey.privateKey),
        fido2Extensions: {},
      },
    ],
  }));

  const otpItems = source.otp.map((entry, index) => ({
    id: `totp-${index + 1}`,
    creationAt: timestamp,
    modifiedAt: timestamp,
    type: 'login',
    title: entry.issuer || entry.account,
    credentials: [
      {
        type: TOTP_TYPE,
        secret: arrayBufferToBase64URL(bytesBuffer(entry.secret)),
        // Kept alongside the raw secret so importers that only understand the
        // otpauth form still work.
        uri: `otpauth://${entry.type}/${encodeURIComponent(
          entry.issuer ? `${entry.issuer}:${entry.account}` : entry.account
        )}?secret=${base32Encode(entry.secret)}`,
        period: entry.period,
        digits: entry.digits,
        username: entry.account,
        algorithm: entry.algorithm.toLowerCase(),
        issuer: entry.issuer,
      },
    ],
  }));

  return {
    version: CXF_VERSION,
    exporterRpId: source.exporterRpId,
    exporterDisplayName: source.exporterDisplayName,
    timestamp,
    accounts: [
      {
        id: 'fenko-vault',
        userName: '',
        email: '',
        collections: [],
        items: [...passkeyItems, ...otpItems],
      },
    ],
  };
}

function bytesBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer;
}
