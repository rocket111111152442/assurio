const SHEET_NAME = 'Leads';
const SECRET_PROPERTY = 'LEADS_STORE_SECRET';
const HEADERS = [
  'id',
  'created_at',
  'type',
  'prenom',
  'nom',
  'dob',
  'age',
  'adresse',
  'ville',
  'cp',
  'email',
  'tel',
];

function doPost(e) {
  try {
    const body = JSON.parse((e.postData && e.postData.contents) || '{}');
    const expectedSecret = PropertiesService.getScriptProperties().getProperty(SECRET_PROPERTY);
    if (!expectedSecret || body.secret !== expectedSecret) {
      return json_({ ok: false, error: 'unauthorized' });
    }

    if (body.action === 'insert') return insertLead_(body.lead || {});
    if (body.action === 'list') return listLeads_(body.limit || 500);
    if (body.action === 'delete') return deleteLead_(String(body.id || ''));
    if (body.action === 'stats') return stats_(String(body.email || ''), String(body.since || ''));

    return json_({ ok: false, error: 'unknown_action' });
  } catch (err) {
    return json_({
      ok: false,
      error: 'server_error',
      message: String((err && err.message) || err),
    });
  }
}

function insertLead_(lead) {
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const sheet = getSheet_();
    const id = Utilities.getUuid();
    const now = new Date().toISOString();
    sheet.appendRow(HEADERS.map((key) => {
      if (key === 'id') return id;
      if (key === 'created_at') return now;
      return clean_(lead[key]);
    }));
    return json_({ ok: true, id: id });
  } finally {
    lock.releaseLock();
  }
}

function listLeads_(limit) {
  const rows = readRows_();
  const max = Math.max(1, Math.min(Number(limit) || 500, 500));
  const leads = rows
    .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
    .slice(0, max);
  return json_({ ok: true, leads: leads });
}

function deleteLead_(id) {
  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(id)) return json_({ ok: false, error: 'invalid_id' });

  const lock = LockService.getScriptLock();
  lock.waitLock(10000);
  try {
    const sheet = getSheet_();
    const lastRow = sheet.getLastRow();
    if (lastRow < 2) return json_({ ok: true, deleted: false });

    const ids = sheet.getRange(2, 1, lastRow - 1, 1).getValues();
    for (let i = 0; i < ids.length; i += 1) {
      if (String(ids[i][0]) === id) {
        sheet.deleteRow(i + 2);
        return json_({ ok: true, deleted: true });
      }
    }
    return json_({ ok: true, deleted: false });
  } finally {
    lock.releaseLock();
  }
}

function stats_(email, since) {
  const rows = readRows_();
  const sinceMs = Date.parse(since);
  const normalizedEmail = email.trim().toLowerCase();
  let byEmail = 0;
  let global = 0;

  rows.forEach((row) => {
    const createdAt = Date.parse(row.created_at);
    if (!Number.isFinite(createdAt) || createdAt < sinceMs) return;
    global += 1;
    if (String(row.email || '').trim().toLowerCase() === normalizedEmail) byEmail += 1;
  });

  return json_({ ok: true, byEmail: byEmail, global: global });
}

function readRows_() {
  const sheet = getSheet_();
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return [];
  return sheet
    .getRange(2, 1, lastRow - 1, HEADERS.length)
    .getValues()
    .map((row) => {
      const lead = {};
      HEADERS.forEach((key, index) => {
        lead[key] = row[index] == null ? '' : String(row[index]);
      });
      return lead;
    });
}

function getSheet_() {
  const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = spreadsheet.getSheetByName(SHEET_NAME);
  if (!sheet) sheet = spreadsheet.insertSheet(SHEET_NAME);

  const currentHeaders = sheet.getRange(1, 1, 1, HEADERS.length).getValues()[0];
  const missingHeaders = HEADERS.some((header, index) => currentHeaders[index] !== header);
  if (missingHeaders) {
    sheet.getRange(1, 1, 1, HEADERS.length).setValues([HEADERS]);
    sheet.setFrozenRows(1);
  }

  return sheet;
}

function clean_(value) {
  return String(value == null ? '' : value)
    .replace(/[<>\u0000-\u001F\u007F]/g, '')
    .trim()
    .slice(0, 500);
}

function json_(payload) {
  return ContentService
    .createTextOutput(JSON.stringify(payload))
    .setMimeType(ContentService.MimeType.JSON);
}
