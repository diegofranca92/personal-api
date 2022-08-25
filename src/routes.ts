import {Router} from 'express';
import { AuthController } from './controller/AuthController';
import { UserController } from './controller/UserController';
import { AuthMiddleware } from './middleware/auth';

export const routes = Router()

const userController = new UserController()

const authController = new AuthController()

routes.post('/user', userController.store)

routes.get('/user', AuthMiddleware, userController.index)

routes.post('/auth', authController.authenticate)