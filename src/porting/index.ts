/**
 * Credential porting: read other providers' exports, write formats they read.
 */

export * from './types';
export {
  parseImport,
  detectFormat,
  buildInput,
  materialize,
  acceptedExtensions,
  IMPORT_PARSERS,
  describeOtp,
} from './import';
export type { MaterializedImport, ExistingVault, StoredPasskeyRecord } from './import';
export { buildExport, EXPORT_FORMATS, otpauthFor, base32For } from './export';
export type { ExportFormat, ExportFile, ExportFormatInfo, VaultSnapshot } from './export';
export { totpCsvTemplate, passkeyCsvTemplate } from './formats/fenko';
export { buildOtpauthUri } from './otpauth';
