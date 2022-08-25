import { hash } from "bcryptjs";
import { Request, Response } from "express";
import { prismaClient } from "../utils/prismaClient";

export class UserController {
  async store(req: Request, res: Response){
    const {name, email, password } = req.body;
    const hashPassword = await hash(password, 8)
    // Valida se o usuario é cadastrado
    const userExists = await prismaClient.user.findUnique({ where: { email} })

    if(userExists) res.json({error: "User exists"});
    
    const user = await prismaClient.user.create({
      data: {
        name, 
        email, 
        password: hashPassword
      }
    })

    return res.json({user});
  }
  
  async index(req: Request, res: Response) {
    const users = await prismaClient.user.findMany()

    return res.json({users});
  }
}