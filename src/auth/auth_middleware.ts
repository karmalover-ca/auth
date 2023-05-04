import {Response, NextFunction} from "express";
import { ERequest } from "..";
import { getAccessToken, getUserByToken } from "../database";
import * as Errors from "../errors";

export const userMiddleware = async (req: ERequest, res: Response, next: NextFunction) => {
    const auth = req.header("Authorization");
    if(!auth) return next();
    const split = auth.split(" ");
    if(split.length != 2) return res.status(400).send(Errors.INVALID_TOKEN);
    if(split[0] != "Bearer") return res.status(400).send(Errors.INVALID_TOKEN);
    if(split[1].length != 32) return res.status(400).send(Errors.INVALID_TOKEN);

    const token = await getAccessToken(split[1]);
    if(!token) return res.status(400).send(Errors.INVALID_TOKEN);

    const user = await getUserByToken(token);
    if(!user) return res.status(400).send(Errors.INVALID_TOKEN);

    req.user = user;
    req.token = token;
    next();
};

export interface User {
    scopes: Scope[];
    username: string;
    name: string;
    password_hash: string;
}

export interface AuthToken {
    access_token: string;
    user: string;
    created_at: number;
}

const scopes = ["users.create" , "users.list" , "users.edit" , "users.delete" , "users.delete.all" , "users.edit.all", "users.default"] as const;

export type Scope = typeof scopes[number];

const ScopesRaw = scopes.map(v => v);
export { ScopesRaw };