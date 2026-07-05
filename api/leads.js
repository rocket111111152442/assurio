// Fonction serverless Vercel — gestion des demandes (leads) Loryance.
//
// - POST   : enregistre une nouvelle demande (public, depuis le formulaire).
// - GET    : liste les demandes (protégé par mot de passe conseiller).
// - DELETE : supprime une demande (protégé par mot de passe conseiller).
//
// Sécurité :
// - La clé secrète Supabase reste côté serveur (variables d'environnement Vercel).
// - Mot de passe conseiller : header uniquement (jamais en URL), comparaison timing-safe,
//   délai aléatoire en cas d'échec (frein au brute-force).
// - Validation stricte de tous les champs côté serveur + liste blanche.
// - Honeypot anti-bot + limitation de fréquence (par e-mail et globale).
// - Contrôle de l'en-tête Origin sur les requêtes qui modifient des données.

import { createHash, timingSafeEqual, randomInt } from 'node:crypto';
import nodemailer from 'nodemailer';

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET = process.env.SUPABASE_SECRET_KEY;
const MOD_PASS = process.env.MODERATOR_PASSWORD;

// Notification e-mail (facultative : ne s'active que si les variables sont présentes).
const MAIL_USER = process.env.NOTIFY_EMAIL_USER;   // compte Gmail expéditeur
const MAIL_PASS = process.env.NOTIFY_EMAIL_PASS;   // mot de passe d'application Gmail
const MAIL_TO = process.env.NOTIFY_EMAIL_TO || MAIL_USER; // destinataire (par défaut = expéditeur)

// Échappe le texte inséré dans l'e-mail HTML.
function esc(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

// Envoie l'e-mail de notification. Ne lève jamais : un échec e-mail ne doit pas
// empêcher l'enregistrement du lead.
async function notifyByEmail(lead) {
  if (!MAIL_USER || !MAIL_PASS) return; // non configuré : on ignore silencieusement
  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user: MAIL_USER, pass: MAIL_PASS },
    });
    const l = (k) => esc(lead[k]);
    const html = `
      <div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;color:#211A1B">
        <h2 style="color:#7E0E2B;margin:0 0 4px">Nouvelle demande de comparatif</h2>
        <p style="color:#8A7F79;margin:0 0 20px">Reçue via loryance.ch</p>
        <table style="width:100%;border-collapse:collapse;font-size:14px">
          <tr><td style="padding:8px 0;color:#8A7F79;width:150px">Type</td><td style="padding:8px 0;font-weight:600">${l('type')}</td></tr>
          <tr><td style="padding:8px 0;color:#8A7F79">Nom</td><td style="padding:8px 0;font-weight:600">${l('prenom')} ${l('nom')}</td></tr>
          <tr><td style="padding:8px 0;color:#8A7F79">Âge</td><td style="padding:8px 0">${l('age')} ans (né(e) le ${l('dob')})</td></tr>
          <tr><td style="padding:8px 0;color:#8A7F79">Téléphone</td><td style="padding:8px 0;font-weight:600">${l('tel')}</td></tr>
          <tr><td style="padding:8px 0;color:#8A7F79">E-mail</td><td style="padding:8px 0">${l('email')}</td></tr>
          <tr><td style="padding:8px 0;color:#8A7F79">Adresse</td><td style="padding:8px 0">${l('adresse')}, ${l('cp')} ${l('ville')}</td></tr>
        </table>
        <p style="margin:24px 0 0"><a href="https://www.loryance.ch/moderateur" style="background:#7E0E2B;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;font-size:14px">Ouvrir l'espace conseiller</a></p>
      </div>`;
    await transporter.sendMail({
      from: `"Loryance — Nouveau lead" <${MAIL_USER}>`,
      to: MAIL_TO,
      replyTo: lead.email,
      subject: `Nouveau lead : ${lead.prenom} ${lead.nom} — ${lead.type}`,
      html,
    });
  } catch (e) {
    // On avale l'erreur : le lead est déjà enregistré, l'e-mail est un bonus.
  }
}

const REST = () => `${SUPABASE_URL}/rest/v1/leads`;
const authHeaders = () => ({
  apikey: SUPABASE_SECRET,
  Authorization: `Bearer ${SUPABASE_SECRET}`,
  'Content-Type': 'application/json',
});

// Types d'assurance autorisés (liste blanche).
const TYPES = new Set(['Assurance maladie', 'Auto & moto', 'Ménage & RC', 'Vie & 3e pilier']);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Comparaison timing-safe (hash pour égaliser les longueurs).
function safeEqual(a, b) {
  const ha = createHash('sha256').update(String(a)).digest();
  const hb = createHash('sha256').update(String(b)).digest();
  return timingSafeEqual(ha, hb);
}

// Nettoie une valeur : texte brut, sans chevrons ni caractères de contrôle.
function clean(v, max) {
  const noCtrl = String(v ?? "")
    .split("")
    .filter((ch) => { const c = ch.charCodeAt(0); return c >= 32 && c !== 127 && ch !== "<" && ch !== ">"; })
    .join("");
  return noCtrl.replace(/ +/g, " ").trim().slice(0, max);
}

function ageFromDob(dob) {
  const d = new Date(dob + 'T00:00:00Z');
  if (isNaN(d.getTime())) return null;
  const t = new Date();
  let a = t.getUTCFullYear() - d.getUTCFullYear();
  const m = t.getUTCMonth() - d.getUTCMonth();
  if (m < 0 || (m === 0 && t.getUTCDate() < d.getUTCDate())) a--;
  return a;
}

// Vérifie que l'origine (si présente) appartient bien au site.
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true; // requêtes sans Origin (navigation, outils internes)
  try {
    const { protocol, hostname } = new URL(origin);
    if (protocol !== 'https:' && hostname !== 'localhost') return false;
    return (
      hostname === 'loryance.ch' ||
      hostname.endsWith('.loryance.ch') ||
      hostname.endsWith('.vercel.app') ||
      hostname === 'localhost'
    );
  } catch {
    return false;
  }
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (!SUPABASE_URL || !SUPABASE_SECRET) {
    return res.status(500).json({ error: 'Configuration serveur manquante.' });
  }
  if (!originAllowed(req)) {
    return res.status(403).json({ error: 'Origine non autorisée.' });
  }

  try {
    // ---- POST : enregistrer une nouvelle demande (public) ----
    if (req.method === 'POST') {
      const raw = typeof req.body === 'string' ? req.body : JSON.stringify(req.body || {});
      if (raw.length > 10000) return res.status(413).json({ error: 'Requête trop volumineuse.' });
      let body;
      try { body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {}); }
      catch { return res.status(400).json({ error: 'Corps invalide.' }); }

      // Honeypot : si le champ invisible est rempli, c'est un bot.
      // On répond "succès" sans rien enregistrer pour ne pas l'alerter.
      if (clean(body.website, 50)) return res.status(201).json({ ok: true });

      const lead = {
        type: clean(body.type, 40),
        prenom: clean(body.prenom, 80),
        nom: clean(body.nom, 80),
        dob: clean(body.dob, 10),
        adresse: clean(body.adresse, 200),
        ville: clean(body.ville, 80),
        cp: clean(body.cp, 5),
        email: clean(body.email, 160).toLowerCase(),
        tel: clean(body.tel, 25),
      };

      // Validation stricte (miroir du formulaire, appliquée côté serveur).
      const telDigits = lead.tel.replace(/\D/g, '');
      const errors =
        !lead.prenom || !lead.nom ? 'identite' :
        !TYPES.has(lead.type) ? 'type' :
        !/^\d{4}-\d{2}-\d{2}$/.test(lead.dob) ? 'dob' :
        !/^\d{4,5}$/.test(lead.cp) ? 'cp' :
        !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(lead.email) ? 'email' :
        telDigits.length < 9 || telDigits.length > 15 ? 'tel' :
        !lead.adresse || !lead.ville ? 'adresse' : null;
      if (errors) return res.status(400).json({ error: 'Données invalides.' });

      const age = ageFromDob(lead.dob);
      if (age == null || age < 18 || age > 120) return res.status(400).json({ error: 'Données invalides.' });
      lead.age = String(age);

      // Limitation de fréquence : max 3 demandes/heure par e-mail, 30/heure au total.
      const since = new Date(Date.now() - 3600_000).toISOString();
      const [byEmail, global] = await Promise.all([
        fetch(`${REST()}?select=id&email=eq.${encodeURIComponent(lead.email)}&created_at=gte.${since}&limit=3`, { headers: authHeaders() }),
        fetch(`${REST()}?select=id&created_at=gte.${since}&limit=30`, { headers: authHeaders() }),
      ]);
      if (byEmail.ok && (await byEmail.json()).length >= 3) return res.status(429).json({ error: 'Trop de demandes. Réessayez plus tard.' });
      if (global.ok && (await global.json()).length >= 30) return res.status(429).json({ error: 'Service momentanément saturé. Réessayez plus tard.' });

      const r = await fetch(REST(), {
        method: 'POST',
        headers: { ...authHeaders(), Prefer: 'return=minimal' },
        body: JSON.stringify(lead),
      });
      if (!r.ok) return res.status(502).json({ error: 'Enregistrement impossible.' });
      // Notification e-mail (attendue avant la réponse : sur Vercel, le travail
      // asynchrone est gelé une fois la réponse envoyée). Un échec est ignoré.
      await notifyByEmail(lead);
      return res.status(201).json({ ok: true });
    }

    // ---- Méthodes protégées : mot de passe conseiller (header uniquement) ----
    const pass = String(req.headers['x-mod-pass'] || '');
    if (!MOD_PASS || !pass || !safeEqual(pass, MOD_PASS)) {
      await sleep(randomInt(300, 900)); // frein au brute-force
      return res.status(401).json({ error: 'Non autorisé.' });
    }

    // ---- GET : lister les demandes ----
    if (req.method === 'GET') {
      const r = await fetch(`${REST()}?select=*&order=created_at.desc&limit=500`, { headers: authHeaders() });
      if (!r.ok) return res.status(502).json({ error: 'Lecture impossible.' });
      return res.status(200).json(await r.json());
    }

    // ---- DELETE : supprimer une demande ----
    if (req.method === 'DELETE') {
      const id = String((req.query && req.query.id) || '');
      if (!/^\d{1,12}$/.test(id)) return res.status(400).json({ error: 'Identifiant invalide.' });
      const r = await fetch(`${REST()}?id=eq.${id}`, { method: 'DELETE', headers: authHeaders() });
      if (!r.ok) return res.status(502).json({ error: 'Suppression impossible.' });
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST, DELETE');
    return res.status(405).json({ error: 'Méthode non autorisée.' });
  } catch {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
}
