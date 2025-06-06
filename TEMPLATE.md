# TP - Rapport de Recherche de Vulnérabilités et Remédiations

## 1. Informations Générales
- **Nom / Binôme :**
- **Date :**Add commentMore actions

---

## 2. Méthodologie
- **Analyse statique :**
  - Lecture rapide du code backend (TypeScript) et frontend (Vue).
  - Repérage des zones sensibles (concatenation SQL, routes sans validation, gestion des sessions, etc.).
  - ...
- **Tests dynamiques :**
  - Requêtes manuelles avec cURL / Postman / navigateur / Burp Suite.
  - Tentatives d’injection (SQL, paramètre URL, ...) avec quels outils (ex: sqlmap)
  - Contrôle d'accès avec simulation de rôles (admin vs user).
  - Vérification des en-têtes (cookies, CORS).
  - ...

---

## 3. Vulnérabilités Identifiées

### 3.1. Injection SQL dans la route `GET /api/exemple/:birthday`
- **Localisation :** `controllers/example.ts`, ligne n°`X` : `db.get('SELECT * FROM exemple WHERE birthday = ${birthday}')`.
- **Preuve de concept :**
  1. Envoyer `GET /api/articles/1 OR 1=1`.
  2. Le serveur renvoie **tout** au lieu d’un seul item.
- **Cause :**
  - Usage de concaténation directe de `req.params.birthday` dans la requête SQL.
- **Remédiation :**
  - Passer à une requête préparée :
    ```ts
    const rawBirthday = req.params.birthday;
    const birthday = validateAndCast(birthday);
    const exemple = await db.get(
      'SELECT * FROM exemple WHERE birthday = ?',
      birthday
    );
    ```
  - Valider que `birthday` soit bien une date au format dd/mm/YYY.

---