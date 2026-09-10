/**
 * Minimal RFC 4180 CSV reader/writer.
 *
 * Every password manager that exports CSV quotes fields containing commas,
 * quotes or newlines, and doubles embedded quotes — that is the whole spec
 * we need. No dependency, no streaming, files are small.
 */

const BOM = '\uFEFF';

export type CsvRow = Record<string, string>;

/** Split CSV text into raw cells, honouring quotes and embedded newlines. */
export function parseCsvGrid(text: string): string[][] {
  const input = text.startsWith(BOM) ? text.slice(1) : text;
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let i = 0;

  while (i < input.length) {
    const ch = input[i];

    if (quoted) {
      if (ch === '"') {
        // A doubled quote inside a quoted field is a literal quote.
        if (input[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }

    if (ch === '"' && field === '') {
      quoted = true;
      i += 1;
      continue;
    }

    if (ch === ',') {
      row.push(field);
      field = '';
      i += 1;
      continue;
    }

    if (ch === '\r') {
      i += 1;
      continue;
    }

    if (ch === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      i += 1;
      continue;
    }

    field += ch;
    i += 1;
  }

  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows.filter((cells) => cells.some((cell) => cell.trim() !== ''));
}

/**
 * Parse CSV into objects keyed by the header row. Header names are
 * lower-cased and stripped of spaces/underscores so `Login URI`, `login_uri`
 * and `loginuri` all land on the same key.
 */
export function parseCsv(text: string): CsvRow[] {
  const grid = parseCsvGrid(text);
  if (grid.length < 2) return [];

  const headers = grid[0].map(normalizeHeader);

  return grid.slice(1).map((cells) => {
    const row: CsvRow = {};
    headers.forEach((header, index) => {
      if (!header) return;
      row[header] = (cells[index] ?? '').trim();
    });
    return row;
  });
}

export function normalizeHeader(header: string): string {
  return header
    .replace(/^\uFEFF/, '')
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, '');
}

/** Read the header row without parsing the body — used for format detection. */
export function csvHeaders(text: string): string[] {
  const grid = parseCsvGrid(text);
  return grid.length > 0 ? grid[0].map(normalizeHeader) : [];
}

function escapeCell(value: string): string {
  if (!/[",\r\n]/.test(value)) return value;
  return `"${value.replace(/"/g, '""')}"`;
}

export function toCsv(headers: string[], rows: Array<Array<string | number>>): string {
  const lines = [headers.map(escapeCell).join(',')];
  for (const row of rows) {
    lines.push(row.map((cell) => escapeCell(String(cell ?? ''))).join(','));
  }
  return lines.join('\n') + '\n';
}
