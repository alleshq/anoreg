const jwt = require("jsonwebtoken");

// Express
const express = require("express");
const app = express();
app.use(require("cookie-parser")());
app.listen(8080);

// QuickAuth
const quickauth = require("@alleshq/quickauth");
app.get("/account/quickauth", (_req, res) => res.redirect(quickauth.url(process.env.QUICKAUTH_URL)));
app.get("/account/quickauth/callback", (req, res) => {
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
const auth = async (req, res, next) => {
    if (typeof req.cookies.token !== "string") return res.status(401).json({err: "badAuthorization"});
    try {
        req.user = (await jwt.verify(req.cookies.token, process.env.JWT_SECRET)).id;
    } catch (err) {
        return res.status(401).json({err: "badAuthorization"});
    }
    next();
};

// Account Page
app.get("/account", auth, (req, res) => {
    res.send(`Hello, user ${req.user}`);
});

// 404
app.use((_req, res) => res.status(404).json({err: "notFound"}));