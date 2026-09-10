import { csvHeaders, parseCsv, parseCsvGrid, toCsv } from '../../src/porting/csv';

describe('CSV reader', () => {
  it('honours quotes, doubled quotes and embedded newlines', () => {
    const text = 'name,notes\n"Acme, Inc.","line one\nline ""two"""\n';
    expect(parseCsvGrid(text)).toEqual([
      ['name', 'notes'],
      ['Acme, Inc.', 'line one\nline "two"'],
    ]);
  });

  it('normalises header names', () => {
    const rows = parseCsv('Login URI,login_username,LOGIN TOTP\nhttps://a,ali,JBSWY3DPEHPK3PXP\n');
    expect(rows[0]).toEqual({
      loginuri: 'https://a',
      loginusername: 'ali',
      logintotp: 'JBSWY3DPEHPK3PXP',
    });
  });

  it('drops blank rows and strips the BOM', () => {
    expect(csvHeaders('﻿a,b\n\n1,2\n')).toEqual(['a', 'b']);
    expect(parseCsv('﻿a,b\n\n1,2\n')).toHaveLength(1);
  });

  it('round-trips through the writer', () => {
    const csv = toCsv(['a', 'b'], [['x,y', 'he said "hi"']]);
    expect(parseCsv(csv)).toEqual([{ a: 'x,y', b: 'he said "hi"' }]);
  });
});
