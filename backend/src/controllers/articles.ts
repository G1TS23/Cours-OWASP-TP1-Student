import {Request, Response} from 'express';
import {db} from '@/database';

// Liste les articles d'un utilisateur
export async function list(req: Request, res: Response): Promise<any> {
    const userId = req.session.user!.id;
    let articles = await db.all('SELECT * FROM articles WHERE authorId = ?', userId);
    articles = articles.map(article => ({
        id: article.id,
        title: article.title
    }))
    res.json(articles);
}

// Permet à l'admin de lister tous les articles de tout le monde
export async function listAll(_req: Request, res: Response): Promise<any> {
    const articles = await db.all('SELECT articles.*, users.username FROM articles LEFT JOIN users ON (articles.authorId = users.id)');
    res.json(articles);
}

// Créer un article
export async function create(req: Request, res: Response): Promise<any> {
    const userId = req.session.user!.id;
    const {title, content} = req.body;
    const result = await db.run(
        'INSERT INTO articles (authorId, title, content) VALUES (?, ?, ?)',
        userId, title, content
    );
    res.status(201).json({id: result.lastID});
}

// Récupérer les informations d'un articles
export async function get(req: Request, res: Response): Promise<any> {
    const articleId = req.params.id;
    const userId = req.session.user!.id;
    const article = await db.get(
        'SELECT * FROM articles WHERE id = ? AND authorId = ?',
        articleId,
        userId
    );
    if (!article) return res.sendStatus(404)
    res.json(article);
}

// Modifier un article
export async function modify(req: Request, res: Response): Promise<any> {
    const articleId = req.params.id;
    const {title, content} = req.body;
    await db.run(
        `UPDATE articles
         SET title=?,
             content=?
         WHERE id = ?`,
        title, content, articleId
    );
    res.json({message: 'Updated'});
}

// Supprimer un article
export async function remove(req: Request, res: Response): Promise<any> {
    const userId = req.session.user!.id;
    const articleId = req.params.id;
    const result = await db.run(
        'DELETE FROM articles WHERE id=? AND authorId=?',
        articleId,
        userId
    );

    if (result.changes === 0) {
        return res.status(403).json({error: 'Something went wrong'});
    }
    res.json({message: 'Deleted'});
}

// Exporter les données vers un service tiers (RGPD)
export async function exportData(req: Request, res: Response): Promise<any> {
    let sendTo: string
    try {
        sendTo = (new URL(req.query.to as string)).toString()
    } catch (error) {
        return res.sendStatus(400)
    }

    const allowedHosts = ['https://mon-service.com'];
    if (!allowedHosts.some(h => sendTo.startsWith(h))) {
        return res.status(400).json({ error: 'Forbidden target' });
    }


    const userId = req.session.user!.id;
    let articles = await db.all('SELECT * FROM articles WHERE authorId = ?', userId);
    articles = articles.map(article => ({
        id: article.id,
        title: article.title
    }))

    await fetch(sendTo, {
        method: 'POST',
        body: JSON.stringify(articles),
        headers: {
            'Content-Type': 'application/json'
        }
    })

    res.sendStatus(200)
}
