import { Request, Response, NextFunction } from 'express';
import { verify } from 'jsonwebtoken';

type TokenPayload = {
  id: string;
  iat: number;
  exp: number;
}

export function AuthMiddleware(req: Request, res: Response, next: NextFunction) { 
  // quando o usuario tem token, é fornecido um cabecario com o authorization
  const { authorization } = req.headers;

  if (!authorization) {
    return res.status(401).json({error: 'Token not provided'});
  }

  // Onde vai ser fornecido o Bearer e o token
  const [, token] = authorization.split(' ');

  try {
    const decoded = verify(token, 'secret');
    const { id } = decoded as TokenPayload;

    req.userId = id;

    next();

  } catch (error) {
    return res.status(401).json({ error: 'Token not valid' });
  }
}