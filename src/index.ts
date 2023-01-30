import express from "express";
import auth from "./auth/router";
import { userMiddleware, User, AuthToken, ScopesRaw } from "./auth/auth_middleware";
import bodyParser from "body-parser";
import { addUser, usersCollection } from "./database";
import cors from "cors";
import { createHmac, randomBytes } from "crypto";
import { LOGGER, VERSION } from "./constants";

const port = process.env.PORT || 5050;

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(userMiddleware);
app.use("/auth", auth);

app.get("/", async (req, res) => {
    res.status(200).send(`Version: ${VERSION}`);
});

app.listen(port , async () => {
    LOGGER.info("server listening");
    const collection = await usersCollection();

    let karma: User = await collection.findOne({username: "karma"}) as any;
    
    
    if (karma == null) {
        const hmac = createHmac("sha256", process.env.PASSWORD_SALT || "");

        karma = {
            username: "karma",
            password_hash: hmac.update("ThisIsAPassword456").digest("hex"),
            scopes: ScopesRaw,
            name: "KarmaLover",
            creator: "system",
            email: "karma@karmalover.ca"
        };

        await addUser(karma).catch(LOGGER.error);
        LOGGER.info("Created user karma with password ThisIsAPassword456")
    }

    karma.scopes = ScopesRaw;

    collection.replaceOne({username: "karma"}, karma);
});

export interface ERequest extends express.Request {
    user?: User;
    token?: AuthToken;
}