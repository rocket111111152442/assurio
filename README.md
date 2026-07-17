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
