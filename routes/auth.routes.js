import { Router } from 'express';
import passport from 'passport';

import { login, logout, refresh, signup, getMe } from '../controller/auth.controller.js';

const router = Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/refresh', passport.authenticate('refresh-jwt', { session: false }), refresh);
router.post('/logout', logout);

router.get('/getme', passport.authenticate('jwt-access', { session: false }), getMe);

export default router;
