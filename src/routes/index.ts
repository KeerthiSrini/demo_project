import express, { Router } from "express";
import { userList, userLogin, userSignUp } from './usersRoute';

const router: Router = express.Router();

router.post('/signUp', userSignUp);
router.post('/login', userLogin);
router.get('/list', userList);

export default router;
