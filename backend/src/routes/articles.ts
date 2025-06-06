import { Router } from 'express';
import authMiddleware from '@/middlewares/auth';
import roleRequired from '@/middlewares/role';
import { list, listAll, create, get, modify, remove, exportData } from '@/controllers/articles';

const router = Router();

router.get('/', authMiddleware, list);
router.get('/all', roleRequired('admin'), listAll);
router.get('/export', authMiddleware, exportData);
router.post('/', authMiddleware, create);
router.get('/:id', authMiddleware, get);
router.put('/:id', authMiddleware, modify);
router.delete('/:id', authMiddleware, remove);

export default router;
