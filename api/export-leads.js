// Export mensuel automatique des leads non exportés.
//
// Appelé par Vercel Cron le 15 du mois. La route :
// - lit les leads Google Sheets sans `exported_at`
// - génère un fichier Excel .xls
// - envoie le fichier par e-mail
// - marque les lignes comme exportées uniquement après envoi réussi

import nodemailer from 'nodemailer';

function env(name) {
  return String(process.env[name] ?? '').trim().replace(/^['"]|['"]$/g, '');
}

function normalizeSheetsUrl(value) {
  const clean = String(value || '').trim().replace(/^['"]|['"]$/g, '');
  if (!clean) return '';
  return clean.replace(/\/dev(?:[?#].*)?$/i, '/exec');
}

function codedError(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

const SHEETS_WEBAPP_URL = normalizeSheetsUrl(
  env('LEADS_SHEETS_WEBAPP_URL') ||
  env('GOOGLE_SHEETS_WEBAPP_URL') ||
  env('SHEETS_WEBAPP_URL')
);
const LEADS_STORE_SECRET =
  env('LEADS_STORE_SECRET') ||
  env('GOOGLE_SHEETS_SECRET') ||
  env('SHEETS_WEBAPP_SECRET');
const CRON_SECRET = env('CRON_SECRET');

const EXPORT_MAIL_USER = env('EXPORT_EMAIL_USER') || env('NOTIFY_EMAIL_USER');
const EXPORT_MAIL_PASS = env('EXPORT_EMAIL_PASS') || env('NOTIFY_EMAIL_PASS');
const EXPORT_MAIL_TO = env('LEADS_EXPORT_EMAIL_TO') || 'loryance@contact.fr';

const HAS_SHEETS_STORE = Boolean(SHEETS_WEBAPP_URL && LEADS_STORE_SECRET);

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function fmtDate(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString('fr-CH', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Paris',
  });
}

function excelWorkbook(leads, generatedAt) {
  const columns = [
    ['Date de demande', (l) => fmtDate(l.created_at)],
    ['Assurance', (l) => l.type],
    ['Prénom', (l) => l.prenom],
    ['Nom', (l) => l.nom],
    ['Nom complet', (l) => `${l.prenom || ''} ${l.nom || ''}`.trim()],
    ['E-mail', (l) => l.email],
    ['Téléphone', (l) => l.tel],
    ['Date de naissance', (l) => l.dob],
    ['Âge', (l) => l.age],
    ['Adresse', (l) => l.adresse],
    ['Code postal', (l) => l.cp],
    ['Ville', (l) => l.ville],
    ['Identifiant', (l) => l.id],
  ];
  const rows = leads
    .map((lead) => `<tr>${columns.map(([, get]) => `<td class="text">${esc(get(lead))}</td>`).join('')}</tr>`)
    .join('');

  return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body{font-family:Arial,sans-serif;color:#211A1B;}
    h2{margin:0 0 8px;color:#7E0E2B;}
    .meta{margin:0 0 14px;color:#666;font-size:12px;}
    table{border-collapse:collapse;}
    th{background:#7E0E2B;color:#fff;font-weight:700;}
    th,td{border:1px solid #d9d9d9;padding:8px 10px;font-size:12px;vertical-align:top;}
    .text{mso-number-format:"\\@";}
  </style>
</head>
<body>
  <h2>Demandes Loryance non exportées</h2>
  <p class="meta">Export généré le ${esc(fmtDate(generatedAt))} · ${leads.length} demande(s)</p>
  <table>
    <thead><tr>${columns.map(([label]) => `<th>${esc(label)}</th>`).join('')}</tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}

async function sheetsRequest(action, payload = {}) {
  if (!HAS_SHEETS_STORE) throw codedError('sheets_config_missing');

  let response;
  try {
    response = await fetch(SHEETS_WEBAPP_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: LEADS_STORE_SECRET,
        action,
        ...payload,
      }),
    });
  } catch (e) {
    console.error('[export-leads] Google Sheets fetch failed', {
      name: e?.name,
      message: e?.message,
    });
    throw codedError('database_network_failed');
  }

  const text = await response.text().catch(() => '');
  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    const body = text.slice(0, 500);
    console.error('[export-leads] Google Sheets invalid JSON', {
      status: response.status,
      body,
    });
    throw codedError(/<html|<!doctype/i.test(body) ? 'database_webapp_not_public_or_wrong_url' : 'database_invalid_response');
  }

  if (!response.ok || data.ok === false) {
    console.error('[export-leads] Google Sheets action failed', {
      action,
      status: response.status,
      error: data.error,
      message: data.message,
    });
    throw codedError(data.error === 'unauthorized' ? 'database_unauthorized' : 'database_request_failed');
  }

  return data;
}

async function loadUnexportedLeads() {
  const data = await sheetsRequest('unexported', { limit: 5000 });
  return Array.isArray(data.leads) ? data.leads : [];
}

async function markExported(leads, batchId, exportedAt) {
  const ids = leads.map((lead) => String(lead.id || '')).filter(Boolean);
  if (!ids.length) return { marked: 0 };
  return await sheetsRequest('markExported', { ids, batchId, exportedAt });
}

async function sendExportEmail(leads, generatedAt) {
  if (!EXPORT_MAIL_USER || !EXPORT_MAIL_PASS) {
    throw codedError('email_config_missing');
  }

  const dateStamp = generatedAt.toISOString().slice(0, 10);
  const workbook = excelWorkbook(leads, generatedAt);
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: { user: EXPORT_MAIL_USER, pass: EXPORT_MAIL_PASS },
  });

  await transporter.sendMail({
    from: `"Loryance - Export leads" <${EXPORT_MAIL_USER}>`,
    to: EXPORT_MAIL_TO,
    subject: `Export mensuel Loryance - ${dateStamp} - ${leads.length} lead(s)`,
    html: `
      <div style="font-family:Arial,sans-serif;color:#211A1B;max-width:560px">
        <h2 style="color:#7E0E2B;margin:0 0 8px">Export mensuel des leads Loryance</h2>
        <p style="margin:0 0 12px">Bonjour,</p>
        <p style="margin:0 0 12px">Vous trouverez en pièce jointe les ${leads.length} lead(s) non encore exporté(s).</p>
        <p style="margin:0;color:#6E645F;font-size:13px">Export généré automatiquement le ${esc(fmtDate(generatedAt))}.</p>
      </div>`,
    attachments: [
      {
        filename: `loryance-leads-non-exportes-${dateStamp}.xls`,
        content: Buffer.from('\ufeff' + workbook, 'utf8'),
        contentType: 'application/vnd.ms-excel; charset=utf-8',
      },
    ],
  });
}

function isAuthorized(req) {
  const header = String(req.headers.authorization || req.headers.Authorization || '');
  return Boolean(CRON_SECRET && header === `Bearer ${CRON_SECRET}`);
}

function errorResponse(res, status, error, code) {
  return res.status(status).json({ error, code });
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return errorResponse(res, 405, 'Méthode non autorisée.', 'method_not_allowed');
  }

  if (!isAuthorized(req)) {
    return errorResponse(res, 401, 'Non autorisé.', 'unauthorized');
  }

  if (!HAS_SHEETS_STORE) {
    return errorResponse(res, 500, 'Configuration Google Sheets manquante.', 'sheets_config_missing');
  }

  try {
    const generatedAt = new Date();
    const batchId = `loryance-export-${generatedAt.toISOString()}`;
    const leads = await loadUnexportedLeads();

    if (!leads.length) {
      return res.status(200).json({ ok: true, exported: 0, emailed: false });
    }

    await sendExportEmail(leads, generatedAt);
    const marked = await markExported(leads, batchId, generatedAt.toISOString());

    return res.status(200).json({
      ok: true,
      exported: leads.length,
      marked: Number(marked.marked || 0),
      emailed: true,
      to: EXPORT_MAIL_TO,
      batchId,
    });
  } catch (e) {
    console.error('[export-leads] Export failed', {
      name: e?.name,
      message: e?.message,
      code: e?.code,
    });

    if (e?.code === 'email_config_missing') {
      return errorResponse(res, 500, 'Configuration e-mail manquante.', 'email_config_missing');
    }
    if (e?.code === 'database_webapp_not_public_or_wrong_url') {
      return errorResponse(res, 502, 'URL Apps Script incorrecte ou accès non public.', 'database_webapp_not_public_or_wrong_url');
    }
    if (e?.code === 'database_unauthorized') {
      return errorResponse(res, 502, 'Accès base de données refusé.', 'database_unauthorized');
    }
    if (e?.code === 'database_network_failed') {
      return errorResponse(res, 502, 'Base de données indisponible.', 'database_network_failed');
    }
    if (e?.code === 'database_invalid_response' || e?.code === 'database_request_failed') {
      return errorResponse(res, 502, 'Base de données indisponible.', e.code);
    }

    return errorResponse(res, 500, 'Erreur serveur.', 'server_error');
  }
}
