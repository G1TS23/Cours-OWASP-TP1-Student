# Consignes du TP

## 1. Objectifs

- Identifier les vulnérabilités du code fourni (backend + frontend).
- Exploiter ces vulnérabilités pour en démontrer l’impact (PoC).
- Corriger le code (remédiations) pour rendre l’application sécurisée selon les notions abordées en cours

---

## 2. Vulnérabilités à rechercher (non-exhaustif)

- Injection SQL
- Absence de validation/sanitization des paramètres
- Broken Access Control
- XSS
- Gestion des données
- CORS / CSRF
- Exposition excessive d’informations
- ...

---

## 3. Conseils

Consacrez du temps pour prendre en main le frontend ET le backend :

1. Naviguer dans chaque page dans un premier temps (login, register, liste d’articles, création, ...).
2. Lire rapidement le code (les fichiers dans src/routes, src/controllers et src/middlewares notamment).

Il est conseillé d'utiliser des outils comme BurpSuite, Postman et le Devtool pour faciliter l'exploration. Surtout, gardez une trace de ce que vous faites pour éviter de vous perdre et allez-y méthodiquement, fonction par fonction.

---

## 4. Installation

```
npm run setup
npm run dev
```