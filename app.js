const express = require('express');
const bodyParser = require('body-parser');
// const bcrypt = require('bcrypt');
const bcrypt = require('bcryptjs');
const ejs = require("ejs");
const session = require("express-session");
const mongoose = require("mongoose");

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: "yourSecretKey",
    resave: false,
    saveUninitialized: false
}));

// Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/secretsDB", { useNewUrlParser: true, useUnifiedTopology: true });

// User Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

// Secret Schema (Now Includes User Reference)
const secretSchema = new mongoose.Schema({
    content: String,
    userId: mongoose.Schema.Types.ObjectId
});

const Secret = mongoose.model("Secret", secretSchema);

// Routes
app.get("/", function (req, res) {
    res.render("home");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/login", function (req, res) {
    res.render("login");
});

// Register Route
app.post("/register", async function (req, res) {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({
            email: req.body.username,
            password: hashedPassword
        });

        await newUser.save();
        req.session.user = newUser;
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.send("An error occurred.");
    }
});

// Login Route
app.post("/login", async function (req, res) {
    try {
        const foundUser = await User.findOne({ email: req.body.username });

        if (foundUser) {
            const passwordMatch = await bcrypt.compare(req.body.password, foundUser.password);

            if (passwordMatch) {
                req.session.user = foundUser;
                res.redirect("/secrets");
            } else {
                res.send("Incorrect password. Please try again.");
            }
        } else {
            res.send("User not found. Please register first.");
        }
    } catch (err) {
        console.log(err);
        res.send("An error occurred.");
    }
});

// Submit a Secret Route (Now Saves with User ID)
app.post("/submit", async function (req, res) {
    if (req.session.user) {
        try {
            const newSecret = new Secret({
                content: req.body.secret,
                userId: req.session.user._id
            });

            await newSecret.save();
            res.redirect("/secrets");
        } catch (err) {
            console.log(err);
            res.send("An error occurred.");
        }
    } else {
        res.redirect("/login");
    }
});

// View Secrets Route (Now Shows Only User’s Secrets)
app.get("/secrets", async function (req, res) {
    if (req.session.user) {
        try {
            const secretsList = await Secret.find({ userId: req.session.user._id });
            res.render("secrets", { secrets: secretsList });
        } catch (err) {
            console.log(err);
            res.send("An error occurred.");
        }
    } else {
        res.redirect("/login");
    }
});

// Logout Route
app.get("/logout", function (req, res) {
    req.session.destroy((err) => {
        if (err) {
            console.log(err);
            res.send("Error logging out.");
        } else {
            res.redirect("/");
        }
    });
});

// Submit Page
app.get("/submit", function (req, res) {
    if (req.session.user) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.listen(5000, function () {
    console.log("Server Started on Port 5000");
});
