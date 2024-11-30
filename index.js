const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
    session({
        secret: "replace_this_with_a_secure_key",
        resave: false,
        saveUninitialized: true,
    })
);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const USERS = [
    {
        id: 1,
        username: "AdminUser",
        email: "admin@example.com",
        password: bcrypt.hashSync("admin123", SALT_ROUNDS),
        role: "admin",
    },
    {
        id: 2,
        username: "RegularUser",
        email: "user@example.com",
        password: bcrypt.hashSync("user123", SALT_ROUNDS),
        role: "user",
    },
];

// Middleware to check if user is authenticated
const isAuthenticated = (request, response, next) => {
    if (request.session.user) {
        next();
    } else {
        response.redirect("/login");
    }
};

// Middleware to check if user is admin
const isAdmin = (request, response, next) => {
    if (request.session.user && request.session.user.role === "admin") {
        next();
    } else {
        response.status(403).send("Access Denied");
    }
};

// GET /login - Render login form
app.get("/login", (request, response) => {
    response.render("login", { error: null });
});

// POST /login - Allows a user to login
app.post("/login", (request, response) => {
    const user = USERS.find(user => user.email === request.body.email);
    if (user && bcrypt.compareSync(request.body.password, user.password)) {
        request.session.user = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role
        };
        response.redirect("/landing");
    } else {
        response.render("login", { error: "Invalid Credentials" });
    }
});

// GET /signup - Render signup form
app.get("/signup", (request, response) => {
    response.render("signup", { error: null });
});

// POST /signup - Allows a user to signup
app.post("/signup", (request, response) => {
    const { username, email, password } = request.body;

    // Check if user already exists
    const existingUser = USERS.find(user => user.email === email);
    if (existingUser) {
        return response.render("signup", { error: "Email already in use" });
    }

    // Validate input
    if (!username || !email || !password) {
        return response.render("signup", { error: "All fields are required" });
    }

    // Hash the password
    const hashedPassword = bcrypt.hashSync(password, SALT_ROUNDS);

    // Create new user
    const newUser = {
        id: USERS.length + 1,
        username,
        email,
        password: hashedPassword,
        role: "user" // Default role for new users
    };

    // Add user to USERS array
    USERS.push(newUser);

    // Automatically log in the new user
    request.session.user = {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
    };

    response.redirect("/landing");
});

// GET / - Render index page or redirect to landing if logged in
app.get("/", (request, response) => {
    if (request.session.user) {
        return response.redirect("/landing");
    }
    response.render("index");
});

// GET /landing - Shows a welcome page for users, shows the names of all users if an admin
app.get("/landing", isAuthenticated, (request, response) => {
    const user = request.session.user;

    if (user.role === "admin") {
        // For admin, show all users
        response.render("landing", { 
            username: user.username, 
            role: user.role, 
            users: USERS 
        });
    } else {
        // For regular users, just show their own info
        response.render("landing", { 
            username: user.username, 
            role: user.role 
        });
    }
});

// GET /logout - Destroy session and redirect to home
app.get("/logout", (request, response) => {
    request.session.destroy((err) => {
        if (err) {
            return response.status(500).send("Could not log out");
        }
        response.redirect("/");
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});