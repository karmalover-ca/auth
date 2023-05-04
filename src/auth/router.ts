import { Router } from "express";
import { createHmac, randomBytes } from "crypto";
import * as Errors from "../errors";
import { addAccessToken, addUser, deleteUser, getUserByName, purgeAccessTokens, removeAccessToken, updateUser, listUsers, usersCollection } from "../database";
import { AuthToken, User, ScopesRaw } from "./auth_middleware";
import { ERequest } from "..";
import { LOGGER } from "../constants";

const router = Router();

router.post("/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if(!username || !password) return res.status(400).send(Errors.MALFORMED_LOGIN_REQUEST);

    const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");

    const hash = hmac.update(password).digest("hex");

    const user = await getUserByName(username);
    if(!user) return res.status(401).send(Errors.INCORRECT_USER_CREDENTIALS);
    if(user.password_hash != hash) return res.status(401).send(Errors.INCORRECT_USER_CREDENTIALS);

    const token = await generateToken(user) as any;
    
    res.status(200).send(token);
});

router.post("/create", async (req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);
    if(!req.user.scopes.includes("users.create")) return res.status(403).send(Errors.MISSING_PERMISSIONS);

    const body = req.body;

    if(!body.username || !body.password || !body.scopes) return res.status(400).send(Errors.MALFORMED_LOGIN_REQUEST);
    if(!includesAll(req.user.scopes, body.scopes)) return res.status(403).send(Errors.MISSING_PERMISSIONS);

    if(await getUserByName(body.username) != null) return res.status(409).send(Errors.USER_EXISTS);

    const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");

    const newUser: User = {
        username: body.username,
        password_hash: hmac.update(body.password).digest("hex"),
        scopes: body.scopes,
        name: body.name || ""
    };

    if(await addUser(newUser)) return res.status(201).send({username: newUser.username});
    return res.status(500).send(Errors.ADD_USER_FAILED);
});

router.post("/signup", async (req: ERequest, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const name = req.body.name;

    if(!username || !password || !name) return res.status(400).send(Errors.MALFORMED_SIGNUP_REQUEST);
    if(await getUserByName(username) != null) return res.status(409).send(Errors.USER_EXISTS);

    const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");

    const newUser: User = {
        username: username,
        password_hash: hmac.update(password).digest("hex"),
        scopes: [ "users.default" ],
        name: name
    }

    if(await addUser(newUser)) return res.status(201).send({username: newUser.username});
    return res.status(500).send(Errors.ADD_USER_FAILED);
})

router.post("/delete", async(req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);
    if(!req.user.scopes.includes("users.delete")) return res.status(403).send(Errors.MISSING_PERMISSIONS);
    if(!req.body.username) return res.status(400).send(Errors.MISSING_USERNAME);

    const user = await getUserByName(req.body.username);
    if(!user) return res.status(404).send(Errors.USER_NOT_EXISTS);
    const canDelete = user.name == req.user.name && user.username != "admin";

    if(!canDelete) return res.status(403).send(Errors.MISSING_PERMISSIONS);

    await purgeAccessTokens(user);
    const r2 = await deleteUser(user);

    if(!r2) return res.status(500).send(Errors.DELETE_USER_FAILED);
    return res.status(200).send();
});

router.post("/change_password", async (req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);
    
    const password = req.body.password;
    if(!password) return res.status(400).send(Errors.MALFORMED_PASSWORD_CHANGE);

    const newUser = req.user;
    const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");
    newUser.password_hash = hmac.update(password).digest("hex");

    const r = await updateUser(newUser);
    if(!r) return res.status(500).send(Errors.PASSWORD_CHANGE_FAILED);

    await purgeAccessTokens(newUser);

    res.status(200).send();
});

router.post("/purge", async (req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);

    const r = await purgeAccessTokens(req.user);
    if(!r) return res.status(500).send(Errors.PURGE_TOKENS_FAILED);

    res.status(200).send();
});

router.post("/logout", async (req: ERequest, res) => {
    if(!req.user || !req.token) return res.status(401).send(Errors.MISSING_TOKEN);
    
    const r = await removeAccessToken(req.token);
    
    if(!r) return res.status(500).send(Errors.LOGOUT_FAILED);

    res.status(200).send();
});

router.post("/identify", async(req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);

    const u = req.user as any;

    u.password_hash = undefined;
    u._id = undefined;
    
    res.status(200).send(u);
})

router.post("/users",async (req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);
    if(!req.user.scopes.includes("users.list")) return res.status(403).send(Errors.MISSING_PERMISSIONS)
    
    const l = await listUsers();
    if(l === null) return res.send(500).send(Errors.LIST_USERS_FAILED)

    res.status(200).send(l);
})

router.patch("/edit", async (req: ERequest, res) => {
    if(!req.user) return res.status(401).send(Errors.MISSING_TOKEN);
    if(!req.user.scopes.includes("users.edit")) return res.status(403).send(Errors.MISSING_PERMISSIONS);
    if(!req.body.username) return res.status(400).send(Errors.MISSING_USERNAME);

    const user = await getUserByName(req.body.username);
    if(!user) return res.status(404).send(Errors.USER_NOT_EXISTS);
    const canEdit = (req.user.scopes.includes("users.edit.all") || req.user == req.body.username) && user.username != "karma";
    if(!canEdit) return res.status(403).send(Errors.MISSING_PERMISSIONS);
    
    const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");

    if(req.body.password) user.password_hash = hmac.update(req.body.password).digest("hex"); await purgeAccessTokens(user);
    if(req.body.scopes) {
        if(!includesAll(req.user.scopes, req.body.scopes)) return res.status(403).send(Errors.MISSING_PERMISSIONS);
        user.scopes = req.body.scopes;
    }
    if(req.body.name) user.name = req.body.name;

    if(await updateUser(user)) return res.status(201).send({username: user.username});
    return res.status(500).send(Errors.EDIT_USER_FAILED);
})

async function generateToken(user: User): Promise<AuthToken> {
    const token: AuthToken = {
        access_token: randomString(),
        created_at: Date.now(),
        user: user.username,
    };

    const result = await addAccessToken(token);
    if(!result) return await generateToken(user);
    return token;
}

function randomString(size: number = 32): string {
    return randomBytes(size * 2).toString("hex").slice(0, size);
}

function includesAll(array: any[], items: any[]) {
    let contains = true;
    for (const item of items) {
        contains = contains && array.includes(item);
    }
    return contains;
}

export default router;