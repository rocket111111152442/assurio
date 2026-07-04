// Fonction serverless Vercel — gestion des demandes (leads) Loryance.
//
// - POST   : enregistre une nouvelle demande (public, depuis le formulaire).
// - GET    : liste les demandes (protégé par mot de passe conseiller).
// - DELETE : supprime une demande (protégé par mot de passe conseiller).
//
// La clé secrète Supabase reste cote serveur (variables d'environnement Vercel)
// et n'apparait jamais dans le code envoye au navigateur.

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET = process.env.SUPABASE_SECRET_KEY;
const MOD_PASS = process.env.MODERATOR_PASSWORD;

const REST = () => `${SUPABASE_URL}/rest/v1/leads`;
const authHeaders = () => ({
  apikey: SUPABASE_SECRET,
  Authorization: `Bearer ${SUPABASE_SECRET}`,
  'Content-Type': 'application/json',
});

// Champs autorises (on ignore tout le reste envoye par le client).
const FIELDS = ['type', 'prenom', 'nom', 'dob', 'age', 'adresse', 'ville', 'cp', 'email', 'tel'];

export default async function handler(req, res) {
  if (!SUPABASE_URL || !SUPABASE_SECRET) {
    return res.status(500).json({ error: 'Configuration serveur manquante (Supabase).' });
  }

  try {
    // ---- POST : enregistrer une nouvelle demande (public) ----
    if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      const lead = {};
      for (const f of FIELDS) {
        lead[f] = (body[f] == null ? '' : String(body[f])).slice(0, 300);
      }
      if (!lead.email || !lead.nom || !lead.prenom) {
        return res.status(400).json({ error: 'Champs requis manquants.' });
      }
      const r = await fetch(REST(), {
        method: 'POST',
        headers: { ...authHeaders(), Prefer: 'return=minimal' },
        body: JSON.stringify(lead),
      });
      if (!r.ok) return res.status(502).json({ error: "Enregistrement impossible." });
      return res.status(201).json({ ok: true });
    }

    // ---- Methodes protegees : verifier le mot de passe conseiller ----
    const pass = req.headers['x-mod-pass'] || (req.query && req.query.pass) || '';
    if (!MOD_PASS || pass !== MOD_PASS) {
      return res.status(401).json({ error: 'Non autorise.' });
    }

    // ---- GET : lister les demandes ----
    if (req.method === 'GET') {
      const r = await fetch(`${REST()}?select=*&order=created_at.desc`, { headers: authHeaders() });
      if (!r.ok) return res.status(502).json({ error: 'Lecture impossible.' });
      const data = await r.json();
      return res.status(200).json(data);
    }

    // ---- DELETE : supprimer une demande ----
    if (req.method === 'DELETE') {
      const id = (req.query && req.query.id) || '';
      if (!id) return res.status(400).json({ error: 'Identifiant requis.' });
      const r = await fetch(`${REST()}?id=eq.${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: authHeaders(),
      });
      if (!r.ok) return res.status(502).json({ error: 'Suppression impossible.' });
      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: 'Methode non autorisee.' });
  } catch (e) {
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
}
