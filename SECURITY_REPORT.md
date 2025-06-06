# TP - Rapport de Recherche de Vulnérabilités et Remédiations

## 1. Informations Générales

- **Nom / Binôme : Pierre LE POTTIER & Olivier FALAHI**
- **Date: 6 juin 2025**

---

## 2. Méthodologie

- **Analyse statique :**
    - Lecture rapide du code backend (TypeScript) et frontend (Vue).
    - Repérage des routes critiques et de la configuration Express.
    - Inspection de la gestion des sessions, des accès, des requêtes SQL et des composants Vue (v-html, etc.).
- **Tests dynamiques :**
    - Lancement local de l’application (npm run setup puis npm run dev).
    - Utilisation de Postman pour s’authentifier (POST /api/auth/login) et rejouer les requêtes.
    - Modifications d’URL et de paramètres pour vérifier les contrôles d’accès et tenter des injections.
    - Observation des cookies et des en‑têtes via les outils de développement du navigateur.

---

## 3. Vulnérabilités Identifiées

### 3.1. Injection SQL

- **Localisation** : `backend/src/controllers/articles.ts` dans la fonction `get` :

```ts
const articleId = req.params.id;
const userId = req.session.user!.id;
const article = await db.get(`SELECT * FROM articles WHERE id='${articleId}' AND authorId=${userId}`);
```

- **Preuve de concept :**

1. Se connecter via Postman :
   ```http
   POST http://localhost:3000/api/auth/login
   { "username": "bob", "password": "123456" }
   ```
2. Envoyer ensuite :

```http
   GET http://localhost:3000/api/articles/0' UNION ALL SELECT group_concat(username || ':' || password, ' | '), NULL, NULL, NULL FROM users --
   ```

3. On récupère des informations sensibles comme les identifiants des utilisateurs :

![injection_sql.png](screenshots/injection_sql.png)

- **Cause :**

L'identifiant d'article est inséré tel quel dans la requête donc on peut injecter du SQL.

- **Remédiation :**
  Utiliser des requêtes paramétrées :

```ts
const article = await db.get(
  'SELECT * FROM articles WHERE id = ? AND authorId = ?',
  articleId,
  userId
);
```

---

### 3.2. Broken Authentication

- **Localisation :** configuration de session dans `backend/src/index.ts` et contrôleur `auth.ts`
  ```ts
    app.use(cors({
    origin: process.env.NODE_ENV === 'production'
    ? `https://localhost:${httpsPort}`
    : `http://localhost:8080`,
    credentials: true
    }));
    
    app.use(session({
    store: new SQLiteStore({
    db: 'sessions.db',
    dir: './data',
    expires: 1 * 60 * 60, // 1 heure
    }),
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
    name: 'session',
    }));
  ```

  ```ts
    // Inscription
    export async function register(req: Request, res: Response): Promise<any> {
    const { username, password } = req.body;
    await db.run(
    `INSERT INTO users (username, password, role) VALUES (?, ?, 'user')`,
    username, password
    );
    res.status(201).json({ message: 'User registered' });
    }
    
    // Connexion
    export async function login(req: Request, res: Response): Promise<any> {
    const { username, password } = req.body;
    const user = await db.get(`SELECT * FROM users WHERE username = ?`, username);
    if (!user) return res.status(401).json({ error: 'User not exist' });
    if (user.password !== password) return res.status(401).json({ error: 'Invalid password' });
    req.session.user = { id: user.id, role: user.role };
    res.json(user);
    }
    
    // Déconnexion
    export async function logout(_req: Request, res: Response): Promise<any> {
    res.clearCookie('session').json({ message: 'Logged out' });
    }
  ```
- **Preuve de concept :**
    1. Fixation de session : se connecter une première fois et noter la valeur du cookie session. Se reconnecter : la
       valeur est identique.
    2. Absence de sécurité : le cookie n’ayant pas le flag secure, il transite en clair en HTTP (mode dev).

![cookie-no-change-and-no-secure.png](screenshoots/cookie-no-change-and-no-secure.png)

- **Cause :**
    - Le secret de session est codé en dur et aucune option de cookie
    - Aucune régénération de session après connexion ; aucune destruction de session lors du logout

- **Remédiation :**
    - Lire le secret depuis `process.env.SESSION_SECRET`
    - Configurer les cookies :
      ```ts
      cookie: { httpOnly: true, secure: true, sameSite: 'strict' }
      ```
    - Utiliser `req.session.regenerate()` après authentification et `req.session.destroy()` au logout

---

### 3.3. Sensitive Data Exposure

- **Localisation :** mots de passe en clair dans `backend/src/database/seed.ts` et donc pas de hash + les routes login
  et me renvoient également ce champ + les messages d'erreurs lors du login trop précis dans contrôleur `auth.ts`
  ```ts
    const usersData = [
    { username: 'alice',  password: 'N15J9VLiyTmL', role: 'user'  },
    { username: 'bob',    password: '123456',      role: 'user'  },
    { username: 'admin',  password: 'H3qWu6w1Nzkm', role: 'admin' },
  ```

![mot-de-passe-no-hash.png](screenshoots/mot-de-passe-no-hash.png)

  ```ts
  if (!user) return res.status(401).json({error: 'User not exist'});
if (user.password !== password) return res.status(401).json({error: 'Invalid password'});
  ```

![erreurs-explicites.png](screenshoots/erreurs-explicites.png)

- **Preuve de concept :**
    1. Lancer npm run setup puis ouvrir data/database.db : la table users contient des mots de passe en clair.
    2. Appeler GET http://localhost:3000/api/auth/me : le mot de passe est présent dans la réponse.

- **Cause :**
    - Pas de hash du mot de passe
    - Renvoi du mot de passe lors du login
    - Renvoi d'une erreur trop explicite

- **Remédiation :**
    - Stocker un hash bcrypt au lieu du mot de passe
    ```ts
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    ```
    - Comparer via `bcrypt.compare` à la connexion et ne jamais renvoyer ce champ
    - Ne pas différencier un username invalide d'un mot de passe invalide dans la gestion des erreurs renvoyées

---

### 3.4. Broken Access Control

- **Localisation** :

```ts
export async function listAll(_req: Request, res: Response): Promise<any> {
  const articles = await db.all('SELECT articles.*, users.username FROM articles LEFT JOIN users ON (articles.authorId = users.id)');
  res.json(articles);
}
```

```ts
export async function remove(req: Request, res: Response): Promise<any> {
  const articleId = req.params.id;
  await db.run(
          'DELETE FROM articles WHERE id=?',
          articleId
  );
  res.json({ message: 'Deleted' });
}
```

- **Preuve de concept :**
1. Se connecter avec `bob`.
2. Appeler `GET http://localhost:3000/api/articles/all` : tous les articles sont listés.

![broken_acces_control_all.png](screenshots/broken_acces_control_all.png)

3. Envoyer `DELETE http://localhost:3000/api/articles/4` pour supprimer un article qui ne lui appartient pas.

![broken_acces_control_delete.png](screenshots/broken_acces_control_delete.png)

- **Cause :**
- `GET /api/articles/all` accessible à tout utilisateur authentifié.
- `PUT` et `DELETE /api/articles/:id` ne vérifient pas l'auteur.

**Correctifs**
- Restreindre `/all` aux administrateurs en ajoutant le middleware `roleRequired`:
```ts
  router.get('/all', roleRequired('admin'), listAll);
   ```
- Vérifier `authorId` avant modification ou suppression.

```ts
export async function remove(req: Request, res: Response): Promise<any> {
const userId = req.session.user!.id;
const articleId = req.params.id;
const result = await db.run(
'DELETE FROM articles WHERE id=? AND authorId=?',
articleId,
userId
);

if (result.changes === 0) {
return res.status(403).json({ error: 'Something went wrong' });
}
res.json({ message: 'Deleted' });
}
```

---

### 3.5. Security Misconfiguration

- **Localisation :** cors et autres dans `backend/src/index.ts`
  ```ts
  app.use(cors({
  origin: process.env.NODE_ENV === 'production'
  ? `https://localhost:${httpsPort}`
  : `http://localhost:8080`,
  credentials: true
  }));
  ```

  ```ts
  if (process.env.NODE_ENV !== 'production') {
  http.createServer(app).listen(devPort, () => console.log(`🔓 HTTP Server (dev) on http://localhost:${devPort}`));
   ```

- **Cause :**
    - L’origine est fixée à http://localhost:8080 sans contrôle supplémentaire
    - La ligne http.createServer permet un downgrade en HTTP ; aucun en‑tête HSTS ne force le HTTPS
    - Pas de middleware helmet : les en‑têtes de sécurité par défaut sont absents

- **Remédiation :**
    - Restreindre CORS via une whitelist
    ```ts
  const whitelist = process.env.CORS_WHITELIST ? process.env.CORS_WHITELIST.split(',') : [];

  app.use(cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (whitelist.indexOf(origin) !== -1) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  }));
    ```
    - Activer HSTS en production
    ```ts
  if (process.env.NODE_ENV !== 'production') {
    http.createServer(app).listen(devPort, () => console.log(`🔓 HTTP Server (dev) on http://localhost:${devPort}`));
  } else {
    app.use((req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      next();
    });
   ```
    - Installer helmet
    ```ts
      app.use(helmet());
    ```
  
---

### 3.6. Cross-Site Scripting (XSS)

- **Localisation** :

`frontend/src/views/Home.vue` et `frontend/src/views/Article.vue`

- **Preuve de concept :**
- Si on visite `http://localhost:8080/?search=<img src=x onerror=alert(1)>`, l'image est chargée et le script s'exécute.

![xss_reflected.png](screenshots/xss_reflected.png)

- Si on crée un article avec `<img src="x" onerror="alert('XSS')">`, le script s'exécute lors de la visualisation de l'article.

![xss_stored.png](screenshots/xss_stored.png)

- **Cause :**
- Résultats de la recherche `Home.vue` utilise `v-html` sur les paramètres de la recherche, authorisant le XSS à la volée.
- Le contenu de l'article est rendu avec `v-html`, authorisant le XSS stocké.

**Correctifs**
- Utiliser une bibliothèque comme `DOMPurify` pour nettoyer le contenu avant de l'afficher.

- Exemple de correction dans `Home.vue` :
```ts
const searchQueryRaw = computed(() => {
  const s = route.query.search
  return typeof s === 'string' ? DOMPurify.sanitize(s) : ''
})
```
- Exemple de correction dans `Article.vue` :
```ts
safeContent = DOMPurify.sanitize(article.value.content)
```
```html
    <p v-html="safeContent"></p>
```

---

### 3.7. Cross-Site Request Forgery (CSRF)

- **Localisation :** le middleware de session dans `backend/src/index.ts`
    ```ts
  app.use(session({
  store: new SQLiteStore({
  db: 'sessions.db',
  dir: './data',
  expires: 1 * 60 * 60, // 1 heure
  }),
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
  name: 'session',
  }));
   ```

- **Preuve de concept :**
    1. Démarrer l’application : npm run setup puis npm run dev.
    2. Lancer le fichier [evil.html](evil.html) sur le navigateur (CORS allégés avec le bon port qui va bien)
    3. On observe que le script s'exécute bien et fait un POST avec un cookie qui n'est pas strict.

![cookie-samesite-no.png](screenshoots/cookie-samesite-no.png)

- **Cause :**
    - Pas de flag SameSite ni mécanisme de jeton CSRF. Aucune route ne vérifie de token CSRF. Ainsi, une requête
      POST/PUT/DELETE envoyée par un autre site utilise automatiquement le cookie de session de l’utilisateur connecté.

- **Remédiation :**
    - Ajouter un middleware CSRF (ex. csurf) et passer le cookie en sameSite strict :
  ```ts
  app.use(csurf({
  cookie: {
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
  httpOnly: true
  }
  }));

  app.use((req, res, next) => {
  res.cookie('XSRF-TOKEN', req.csrfToken(), {
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
  httpOnly: false
  });
  next();
  });
   ```
---

### 3.8. Server‑Side Request Forgery (SSRF)

### 3.9. Force Brute

- **Localisation :**
- Le router `auth.ts` sur la route login : `router.post('/login', login);`

- **Preuve de concept :**
    1. Lancer Postman et envoyer plusieurs requêtes avec des identifiants incorrects.
    2. L’application ne limite pas le nombre de tentatives de connexion.

- **Cause :**
- Aucune limitation du nombre de tentatives de connexion, permettant une attaque par force brute.

- **Remédiation :**
    - Ajouter un middleware pour limiter les tentatives de connexion, par exemple avec `express-rate-limit` :
```ts
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // max 5 tentatives par IP
    message: {
        error: 'Trop de tentatives. Réessayez dans 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});
router.post('/login', loginLimiter, login);
```