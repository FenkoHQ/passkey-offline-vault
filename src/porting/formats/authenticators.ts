/**
 * Importers for the standalone authenticator apps.
 *
 * Every app here exports MFA seeds only — no passkeys. Where an app can emit
 * an encrypted export we detect it and say so rather than failing silently.
 */

import { FormatParser, ImportInput, ParsedImport, PortableOtp, emptyImport } from '../types';
import { makeOtp, otpFromUri } from '../otp';
import { isMigrationUri, parseMigrationUri } from '../google-auth';

type Json = Record<string, unknown>;

function asObject(value: unknown): Json | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Json) : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/** Collect entries, turning a single bad record into a warning not a failure. */
function collect(
  result: ParsedImport,
  items: unknown[],
  toOtp: (item: Json, index: number) => PortableOtp | null
): ParsedImport {
  items.forEach((raw, index) => {
    const item = asObject(raw);
    if (!item) return;
    try {
      const otp = toOtp(item, index);
      if (otp) result.otp.push(otp);
    } catch (error) {
      result.warnings.push(`Entry ${index + 1}: ${(error as Error).message}`);
    }
  });
  return result;
}

/**
 * Plain-text lists of otpauth:// URIs — Ente Auth, Aegis "export as plain
 * text", Bitwarden Authenticator, and anything pasted out of a QR reader.
 * Google Authenticator's otpauth-migration:// payloads are expanded too.
 */
export const otpauthText: FormatParser = {
  id: 'otpauth-text',
  label: 'otpauth:// URI list (Ente Auth, Google Authenticator QR, generic)',
  extensions: ['.txt', '.uri'],

  detect(input) {
    return /(^|\n)\s*otpauth(-migration)?:\/\//i.test(input.text);
  },

  parse(input) {
    const result = emptyImport(otpauthText.id, otpauthText.label);
    const lines = input.text
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#'));

    lines.forEach((line, index) => {
      try {
        if (isMigrationUri(line)) {
          result.otp.push(...parseMigrationUri(line));
          return;
        }
        if (/^otpauth:\/\//i.test(line)) {
          result.otp.push(otpFromUri(line));
        }
      } catch (error) {
        result.warnings.push(`Line ${index + 1}: ${(error as Error).message}`);
      }
    });

    return result;
  },
};

/** Aegis Authenticator JSON (`db.entries`). Encrypted vaults are rejected. */
export const aegis: FormatParser = {
  id: 'aegis',
  label: 'Aegis Authenticator (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    if (!json) return false;
    if (typeof json.db === 'string') return true;
    const db = asObject(json.db);
    return Boolean(db && Array.isArray(db.entries));
  },

  parse(input) {
    const result = emptyImport(aegis.id, aegis.label);
    const json = asObject(input.json) as Json;

    if (typeof json.db === 'string') {
      throw new Error('This Aegis vault is encrypted. Re-export it with "Encrypt the vault" off.');
    }

    const entries = asArray((asObject(json.db) as Json).entries);
    return collect(result, entries, (entry) => {
      const info = asObject(entry.info) || {};
      return makeOtp({
        type: entry.type,
        issuer: entry.issuer,
        account: entry.name,
        secret: info.secret,
        algorithm: info.algo,
        digits: info.digits,
        period: info.period,
        counter: info.counter,
      });
    });
  },
};

/** 2FAS Auth JSON (`services`). */
export const twofas: FormatParser = {
  id: '2fas',
  label: '2FAS Auth (JSON)',
  extensions: ['.2fas', '.json'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && (Array.isArray(json.services) || json.servicesEncrypted));
  },

  parse(input) {
    const result = emptyImport(twofas.id, twofas.label);
    const json = asObject(input.json) as Json;

    if (typeof json.servicesEncrypted === 'string' && !Array.isArray(json.services)) {
      throw new Error('This 2FAS backup is password-protected. Re-export it without a password.');
    }

    return collect(result, asArray(json.services), (service) => {
      const otp = asObject(service.otp) || {};
      return makeOtp({
        type: otp.tokenType,
        issuer: otp.issuer || service.name,
        account: otp.account || otp.label,
        secret: service.secret,
        algorithm: otp.algorithm,
        digits: otp.digits,
        period: otp.period,
        counter: otp.counter,
      });
    });
  },
};

/** andOTP JSON — a bare array of accounts. */
export const andotp: FormatParser = {
  id: 'andotp',
  label: 'andOTP (JSON)',
  extensions: ['.json'],

  detect(input) {
    const items = asArray(input.json);
    if (items.length === 0) return false;
    const first = asObject(items[0]);
    return Boolean(first && typeof first.secret === 'string' && 'label' in first);
  },

  parse(input) {
    const result = emptyImport(andotp.id, andotp.label);
    return collect(result, asArray(input.json), (entry) =>
      makeOtp({
        type: entry.type,
        issuer: entry.issuer,
        account: entry.label,
        secret: entry.secret,
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        counter: entry.counter,
      })
    );
  },
};

/** FreeOTP+ JSON — secrets are arrays of signed Java bytes. */
export const freeotp: FormatParser = {
  id: 'freeotp',
  label: 'FreeOTP+ (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    return Boolean(json && Array.isArray(json.tokens));
  },

  parse(input) {
    const result = emptyImport(freeotp.id, freeotp.label);
    const tokens = asArray((asObject(input.json) as Json).tokens);
    return collect(result, tokens, (token) =>
      makeOtp({
        type: token.type,
        issuer: token.issuerExt || token.issuerInt,
        account: token.label,
        secret: token.secret,
        algorithm: token.algo,
        digits: token.digits,
        period: token.period,
        counter: token.counter,
      })
    );
  },
};

/** Raivo OTP JSON — a bare array using `timer` for the period. */
export const raivo: FormatParser = {
  id: 'raivo',
  label: 'Raivo OTP (JSON)',
  extensions: ['.json'],

  detect(input) {
    const items = asArray(input.json);
    if (items.length === 0) return false;
    const first = asObject(items[0]);
    return Boolean(first && 'secret' in first && ('timer' in first || 'kind' in first));
  },

  parse(input) {
    const result = emptyImport(raivo.id, raivo.label);
    return collect(result, asArray(input.json), (entry) =>
      makeOtp({
        type: entry.kind,
        issuer: entry.issuer,
        account: entry.account,
        secret: entry.secret,
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.timer,
        counter: entry.counter,
      })
    );
  },
};

/** LastPass Authenticator JSON export (`accounts`). */
export const lastpassAuth: FormatParser = {
  id: 'lastpass-authenticator',
  label: 'LastPass Authenticator (JSON)',
  extensions: ['.json'],

  detect(input) {
    const json = asObject(input.json);
    if (!json || !Array.isArray(json.accounts)) return false;
    const first = asObject(json.accounts[0]);
    return Boolean(first && ('issuerName' in first || 'userName' in first));
  },

  parse(input) {
    const result = emptyImport(lastpassAuth.id, lastpassAuth.label);
    const accounts = asArray((asObject(input.json) as Json).accounts);
    return collect(result, accounts, (account) =>
      makeOtp({
        type: 'totp',
        issuer: account.issuerName,
        account: account.userName,
        secret: account.secret,
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.timeStep,
      })
    );
  },
};

/**
 * Last-resort JSON shape: an array (or `{tokens|entries|items}`) of objects
 * carrying a `secret`. Covers the Authenticator browser extension, Step Two,
 * OTP Auth and the long tail of small apps.
 */
export const genericOtpJson: FormatParser = {
  id: 'generic-otp-json',
  label: 'Generic authenticator export (JSON)',
  extensions: ['.json'],

  detect(input) {
    return listOtpCandidates(input).length > 0;
  },

  parse(input) {
    const result = emptyImport(genericOtpJson.id, genericOtpJson.label);
    return collect(result, listOtpCandidates(input), (entry) =>
      makeOtp({
        type: entry.type || entry.kind || entry.tokenType,
        issuer: entry.issuer || entry.issuerExt || entry.issuerName || entry.service,
        account: entry.account || entry.label || entry.name || entry.username,
        secret: entry.secret || entry.secretKey,
        algorithm: entry.algorithm || entry.algo,
        digits: entry.digits,
        period: entry.period || entry.timer || entry.timeStep,
        counter: entry.counter,
      })
    );
  },
};

function listOtpCandidates(input: ImportInput): Json[] {
  const json = input.json;
  const pools: unknown[] = [json];

  const wrapper = asObject(json);
  if (wrapper) {
    pools.push(wrapper.tokens, wrapper.entries, wrapper.items, wrapper.data, wrapper.accounts);
  }

  for (const pool of pools) {
    const items = asArray(pool).map(asObject).filter(Boolean) as Json[];
    const usable = items.filter((item) => item.secret || item.secretKey);
    if (usable.length > 0) return usable;
  }
  return [];
}

export const AUTHENTICATOR_PARSERS: FormatParser[] = [
  otpauthText,
  aegis,
  twofas,
  freeotp,
  lastpassAuth,
  raivo,
  andotp,
  genericOtpJson,
];
