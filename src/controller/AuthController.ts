import { compare } from "bcryptjs";
import { Request, Response } from "express";
import { sign } from "jsonwebtoken";
import { prismaClient } from "../utils/prismaClient";

export class AuthController {
  async authenticate(req: Request, res: Response){
    const { email, password } = req.body;

    // Valida se o usuario é cadastrado
    const user: any = await prismaClient.user.findUnique({ where: { email} })

    if(!user) res.json({error: "User not found"});

    // ver se ele tem uma senha valida
    const validPassword = await compare(password, user?.password)

    if(!validPassword) res.json({error: "Invalid password"});

    // retorna um token JWT pra ele poder consultar as informações
    const token = sign(
      {id: user?.id},
      "secret",
      {expiresIn: "1d"}
    )

    const {id} = user
    return res.json({user: { id, email}, token});
  }
  
}