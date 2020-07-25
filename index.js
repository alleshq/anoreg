// Express
const express = require("express");
const app = express();
app.listen(8080);

// QuickAuth
const quickauth = require("@alleshq/quickauth");
app.get("/account/quickauth", (_req, res) =>
    res.redirect(quickauth.url(process.env.QUICKAUTH_URL))
);
app.get("/account/quickauth/callback", (req, res) => {
    if (typeof req.query.token !== "string")
        return res.status(400).json({err: "badRequest"});
    
    // Get user id
    quickauth(req.query.token, process.env.QUICKAUTH_URL)
        .then(id => res.send(id))
        .catch(() => res.status(401).json({err: "badAuthorization"}));
});

// 404
app.use((_req, res) => res.status(404).json({err: "notFound"}));