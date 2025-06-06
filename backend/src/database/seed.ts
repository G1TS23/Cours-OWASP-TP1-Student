import { initDb, db } from '@/database';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

const usersData = [
  { username: 'alice',  password: 'N15J9VLiyTmL', role: 'user'  },
  { username: 'bob',    password: '123456',      role: 'user'  },
  { username: 'admin',  password: 'H3qWu6w1Nzkm', role: 'admin' },
];

const articlesData = [
  {
    username: 'bob',
    title: "Comment j'ai découvert Node.js",
    content: `Lorsque j'ai commencé le développement web, je n'avais jamais utilisé JavaScript côté serveur. 
En explorant Node.js, j'ai été frappé par sa simplicité d'installation et son écosystème de modules. 
Dans cet article, je vous raconte mon parcours d'apprentissage et mes premières réussites.`
  },
  {
    username: 'bob',
    title: 'Comprendre async/await en profondeur',
    content: `Les callbacks peuvent vite devenir ingérables, et les Promises ne sont pas toujours intuitives. 
async/await apporte une syntaxe synchrone au code asynchrone. 
Je vous explique comment l'utiliser correctement et éviter les pièges courants.`
  },
  {
    username: 'bob',
    title: 'Bonnes pratiques pour SQLite en production',
    content: `SQLite est souvent vu comme une base de données embarquée, mais elle peut convenir en production pour des petits projets. 
Je partage ici la configuration, la gestion des migrations et les optimisations de performance que j'ai mises en place.`
  },
  {
    username: 'admin',
    title: 'Bienvenue sur la plateforme Secure Blog',
    content: `Nous sommes ravis de vous accueillir sur notre plateforme de blogging sécurisé. 
N'hésitez pas à créer un compte, publier vos premiers articles et explorer les fonctionnalités offertes.`
  },
  {
    username: 'admin',
    title: 'Maintenance programmée le 1er juin',
    content: `Chers utilisateurs,  
Un arrêt planifié aura lieu le 1er juin de 02:00 à 04:00 UTC pour la mise à jour de sécurité.  
La plateforme sera indisponible pendant cette fenêtre. Merci de votre compréhension.`
  }
];

async function seed() {
  await initDb();

  for (const { username, password, role } of usersData) {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await db.run(
      `INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?);`,
      username, hashedPassword, role
    );
  }
  console.log('✅ Users seeded');

  for (const { username, title, content } of articlesData) {
    const user = await db.get<{ id: number }>(
      `SELECT id FROM users WHERE username = ?;`,
      username
    );
    if (!user) {
      console.warn(`⚠️  Impossible de seed l'article "${title}" pour "${username}" (utilisateur non trouvé)`);
      continue;
    }

    const exists = await db.get(
      `SELECT 1 FROM articles WHERE authorId = ? AND title = ?;`,
      user.id, title
    );
    if (exists) continue;
    await db.run(
      `INSERT INTO articles (authorId, title, content) VALUES (?, ?, ?);`,
      user.id, title, content
    );
  }
  console.log('✅ Articles seeded');

  process.exit(0);
}

seed().catch(err => {
  console.error('❌ Seed failed:', err);
  process.exit(1);
});
