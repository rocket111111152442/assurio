# Assurio / Loryance

Site statique prêt pour Vercel, basé sur le prototype Loryance de comparaison d'assurances.

## Déploiement Vercel

Le dépôt est configuré en framework `Other`, avec la racine du projet comme dossier de sortie.

- Build command: `npm run build`
- Output directory: `.`
- Entry point: `index.html`

## Vérification locale

```bash
npm run build
```

Le script vérifie que les fichiers locaux référencés par la page existent avant le déploiement.

## Base de données gratuite avec Google Sheets

Le site peut enregistrer les demandes dans un Google Sheet via Apps Script, sans base payante.

1. Créer un Google Sheet.
2. Ouvrir `Extensions` > `Apps Script`.
3. Mettre le contenu de `scripts/google-sheets-leads.gs` dans le projet Apps Script.
4. Dans `Project Settings` > `Script properties`, ajouter :
   - `LEADS_STORE_SECRET` : une longue phrase secrète inventée.
5. Déployer en `Web app` :
   - `Execute as` : `Me`
   - `Who has access` : `Anyone`
6. Dans Vercel, ajouter ces variables d'environnement :
   - `LEADS_SHEETS_WEBAPP_URL` : l'URL du Web app Apps Script qui finit par `/exec` (pas `/dev`, pas une URL d'édition).
   - `LEADS_STORE_SECRET` : la même phrase secrète.
   - `MODERATOR_PASSWORD` : le code de l'espace conseiller.
7. Redéployer le site.

Si `LEADS_SHEETS_WEBAPP_URL` et `LEADS_STORE_SECRET` sont présents, l'API utilise Google Sheets. Sinon, elle garde l'ancien mode Supabase.

## Export mensuel automatique des leads

Vercel appelle automatiquement `/api/export-leads` le 15 de chaque mois à 07:00 UTC. La route exporte uniquement les lignes Google Sheets qui n'ont pas encore de valeur `exported_at`, envoie un fichier Excel à `loryance@contact.fr`, puis marque ces lignes comme exportées.

Variables d'environnement Vercel nécessaires :

- `CRON_SECRET` : phrase secrète longue utilisée par Vercel Cron pour sécuriser la route.
- `EXPORT_EMAIL_USER` : adresse Gmail utilisée comme expéditeur SMTP.
- `EXPORT_EMAIL_PASS` : mot de passe d'application Gmail de l'expéditeur.

Si `EXPORT_EMAIL_USER` et `EXPORT_EMAIL_PASS` ne sont pas renseignés, l'export réutilise `NOTIFY_EMAIL_USER` et `NOTIFY_EMAIL_PASS`.

Après modification de `scripts/google-sheets-leads.gs`, il faut aussi remplacer le code dans Apps Script puis redéployer le Web App Google.
