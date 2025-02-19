const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const ejs = require("ejs");
const session = require("express-session");
const mongoose = require("mongoose");
const MongoStore = require('connect-mongo');

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Connect to MongoDB
const MONGO_URL = "mongodb://localhost:27017/secretsDB"; // Change for deployment
mongoose.connect(MONGO_URL)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.log("MongoDB Connection Error:", err));

// Session Configuration (Using MongoDB Store)
app.use(session({
    secret: "yourSecretKey",
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URL }),
    cookie: { secure: false } // Set to true if using HTTPS
}));

// User Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

// Secret Schema
const secretSchema = new mongoose.Schema({
    content: String,
    userId: mongoose.Schema.Types.ObjectId
});

const Secret = mongoose.model("Secret", secretSchema);

// Routes
app.get("/", (req, res) => res.render("home"));
app.get("/register", (req, res) => res.render("register"));
app.get("/login", (req, res) => res.render("login"));
app.get("/submit", (req, res) => req.session.user ? res.render("submit") : res.redirect("/login"));

// Register Route
app.post("/register", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const newUser = new User({ email: req.body.username, password: hashedPassword });

        await newUser.save();
        req.session.user = newUser;
        res.redirect("/secrets");
    } catch (err) {
        console.error("Registration Error:", err);
        res.status(500).send("An error occurred.");
    }
});

// Login Route
app.post("/login", async (req, res) => {
    try {
        const foundUser = await User.findOne({ email: req.body.username });

        if (foundUser && await bcrypt.compare(req.body.password, foundUser.password)) {
            req.session.user = foundUser;
            res.redirect("/secrets");
        } else {
            res.status(401).send("Invalid credentials. Please try again.");
        }
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).send("An error occurred.");
    }
});

// Submit a Secret
app.post("/submit", async (req, res) => {
    if (req.session.user) {
        try {
            await new Secret({ content: req.body.secret, userId: req.session.user._id }).save();
            res.redirect("/secrets");
        } catch (err) {
            console.error("Secret Submission Error:", err);
            res.status(500).send("An error occurred.");
        }
    } else {
        res.redirect("/login");
    }
});

// View Secrets (Only User's Secrets)
app.get("/secrets", async (req, res) => {
    if (req.session.user) {
        try {
            const secretsList = await Secret.find({ userId: req.session.user._id });
            res.render("secrets", { secrets: secretsList });
        } catch (err) {
            console.error("Fetching Secrets Error:", err);
            res.status(500).send("An error occurred.");
        }
    } else {
        res.redirect("/login");
    }
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Logout Error:", err);
            res.status(500).send("Error logging out.");
        } else {
            res.redirect("/");
        }
    });
});

// Start Server (Render-compatible Port)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server Started on Port ${PORT}`));
