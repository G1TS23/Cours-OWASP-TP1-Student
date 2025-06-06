import { Router } from 'express';
import authMiddleware from '@/middlewares/auth';
import { login, logout, me, register } from '@/controllers/auth';
import rateLimit from 'express-rate-limit';

const router = Router();

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // max 5 tentatives par IP
    message: {
        error: 'Trop de tentatives. Réessayez dans 15 minutes.'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

router.post('/register', register);
router.post('/login', loginLimiter, login);
router.post('/logout', authMiddleware, logout);
router.get('/me', authMiddleware, me);


export default router;
