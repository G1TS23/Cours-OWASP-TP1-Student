import 'dotenv/config'
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path'
import express from 'express';
import session, { Store } from 'express-session';
import SQLiteStoreFactory from 'connect-sqlite3';
import cors from 'cors'
import helmet from 'helmet';
import csurf from 'csurf';
import { initDb } from '@/database';
import authRoutes from '@/routes/auth';
import articleRoutes from '@/routes/articles';
import notFound from '@/middlewares/notFound';
import serveFrontend from '@/middlewares/serveFrontend';
import errorHandler from '@/middlewares/errorHandler';



async function main() {
  const devPort = process.env.DEV_PORT;
  const httpsPort = process.env.HTTPS_PORT;

  await initDb();
  const SQLiteStore = SQLiteStoreFactory(session) as (new (opts: any) => Store); // Problème de typage connect-sqlite

  const app = express();

  app.use(helmet());

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
    cookie: {
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true
    }
  }));

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

  app.use(express.json());
  app.use('/api/auth', authRoutes);
  app.use('/api/articles', articleRoutes);

  // en production, servir le build Vue
  if (process.env.NODE_ENV === 'production') {
    const clientDist = path.join(__dirname, '../public')
    app.use(express.static(clientDist));
    app.use(serveFrontend(clientDist))
  }

  app.use(notFound)
  app.use(errorHandler)

  const certDir = path.resolve(__dirname, '..', 'certs');
  const options = {
    key: fs.readFileSync(path.join(certDir, 'key.pem')),
    cert: fs.readFileSync(path.join(certDir, 'cert.pem'))
  };

  if (process.env.NODE_ENV !== 'production') {
    http.createServer(app).listen(devPort, () => console.log(`🔓 HTTP Server (dev) on http://localhost:${devPort}`));
  } else {
    app.use((req, res, next) => {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      next();
    });

    https.createServer(options, app).listen(httpsPort, () => console.log(`🔒 HTTPS Server listening on port ${httpsPort}`));
  }

}

main().catch(console.error);
