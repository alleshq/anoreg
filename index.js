const jwt = require("jsonwebtoken");
const fs = require("fs");
const User = require("./db");
const randomString = require("randomstring").generate;

// Express
const express = require("express");
const app = express();
app.use(require("cookie-parser")());
app.listen(8080);

// QuickAuth
const quickauth = require("@alleshq/quickauth");
const quickauthUrl = quickauth.url(process.env.QUICKAUTH_URL);
app.get("/account/quickauth", (req, res) => {
    if (typeof req.query.token !== "string")
        return res.status(400).json({err: "badRequest"});

    quickauth(req.query.token, process.env.QUICKAUTH_URL)
        .then(id => {
            res.cookie(
                "token",
                jwt.sign({id}, process.env.JWT_SECRET, {expiresIn: "1 day"}),
                {
                    maxAge: 900000,
                    httpOnly: true
                }
            );
            res.redirect("/account");
        })
        .catch(() => res.status(401).json({err: "badAuthorization"}));
});

// Auth Middleware
const auth = async (req, _res, next) => {
    if (typeof req.cookies.token !== "string") return next();
    try {
        const id = (await jwt.verify(req.cookies.token, process.env.JWT_SECRET)).id;
        req.user = await User.findOne({
            where: {
                id
            }
        });
        if (!req.user) req.user = await User.create({
            id,
            secret: randomString(128),
            groups: "users"
        });
    } catch (err) {}
    next();
};

// Account Page
const page = fs.readFileSync(`${__dirname}/index.html`, "utf8").split("*");
app.get("/account", auth, (req, res) => {
    if (!req.user) return res.redirect(quickauthUrl);
    res.send(
        page[0] +
        req.user.id +
        page[1] +
        req.user.secret +
        page[2] +
        req.user.groups +
        page[3]
    );
});

// 404
app.use((_req, res) => res.status(404).json({err: "notFound"}));