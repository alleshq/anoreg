const jwt = require("jsonwebtoken");
const fs = require("fs");
const User = require("./db");
const randomString = require("randomstring").generate;
const axios = require("axios");

// Express
const express = require("express");
const app = express();
app.use(require("cookie-parser")());
app.use(require("body-parser").json());
app.use((err, req, res, next) => res.status(500).json({err: "internalError"}));
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
            res.redirect("/account/auth");
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
            groups: ""
        });
    } catch (err) {}
    next();
};

// Account Page
const page = fs.readFileSync(`${__dirname}/index.html`, "utf8").split("*");
app.get("/account", auth, (req, res) => {
    if (!req.user) return res.redirect(quickauthUrl);
    const groups = req.user.groups.split(" ").filter(group => !!group);
    res.send(
        page[0] +
        req.user.id +
        page[1] +
        req.user.secret +
        page[2] +
        (groups.length > 0 ? groups.join(", ") : "<i>None</i>") +
        page[3]
    );
});

// Regenerate Secret
app.post("/account", auth, async (req, res) => {
    if (!req.user) return res.status(401).json({err: "badAuthorization"});
    await req.user.update({
        secret: randomString(128)
    });
    res.json({secret: req.user.secret});
});

// Sign out
app.get("/account/signout", (req, res) => {
    res.clearCookie("token");
    res.send("<script>localStorage.removeItem('token'); localStorage.removeItem('username');</script><p>You're signed out!</p>")
});

// Get Verdaccio Token
const getToken = async (username, password) => (
    await axios.post(process.env.VERDACCIO_LOGIN, {username, password}) 
).data.token;

// Sign in to Verdaccio
app.get("/account/auth", auth, (req, res) => {
    if (!req.user) return res.redirect(quickauthUrl);
    getToken(req.user.id, req.user.secret)
        .then(token => res.send(`<p>Signing you in...</p><script>localStorage.setItem("token", "${token}"); localStorage.setItem("username", "${req.user.id}"); location.href = localStorage.getItem("redirect") ? localStorage.getItem("redirect") : "/";</script>`))
        .catch(() => res.status(500).json({err: "internalError"}));
});

// API: Authenticate
app.post("/account/api/authenticate", async (req, res) => {
    if (
        typeof req.body.username !== "string" ||
        typeof req.body.password !== "string"
    ) return res.status(400).json({err: "badRequest"});

    const user = await User.findOne({
        where: {
            id: req.body.username
        }
    });
    if (!user || user.secret !== req.body.password)
        return res.status(400).json({err: "user.signIn.credentials"});
    
    res.json(user.groups.split(" ").filter(group => !!group).concat("all"));
});

// 404
app.use((_req, res) => res.status(404).json({err: "notFound"}));