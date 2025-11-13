import express from "express";
import morgan from "morgan";
import { sql } from "./db.js";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config(); // ensure env vars are loaded before use

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

async function initDB() {
  try {
    // Create items table used on the index page
    await sql`
      CREATE TABLE IF NOT EXISTS items (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL
      )
    `;

    // Create users table if it does not exist (useful for local testing)
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `;
  } catch (error) {
    console.log("Error initDB", error);
  }
}
initDB();

app.get("/", async (req, res) => {
  try {
    const result = await sql`SELECT * FROM items ORDER BY id ASC`;
    const items = Array.isArray(result) ? result : result.rows ?? [];
    res.render("index.ejs", {
      listItems: items,
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

app.get("/about", (req, res) => {
  res.render("about.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    // pass user to template if needed
    return res.render("dashboard.ejs", { user: req.user });
  } else {
    return res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "consent",
  })
);

app.post("/signup", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // Basic validation
  if (!email || !password || !username) {
    return res.status(400).send("Missing username, email or password");
  }

  try {
    // @neondatabase/serverless returns an ARRAY of rows (not an object with .rows)
    const checkResult = await sql`SELECT id FROM users WHERE email = ${email}`;

    // treat checkResult as an array
    if (checkResult && checkResult.length > 0) {
      return res.status(409).send("Email already exists. Try logging in.");
    }

    // Use promise-style bcrypt hashing (await)
    const hash = await bcrypt.hash(password, saltRounds);

    // Insert user and return new row(s)
    const insertResult = await sql`
      INSERT INTO users (email, password, username)
      VALUES (${email}, ${hash}, ${username})
      RETURNING id, email, username
    `;

    // Handle both result shapes: array of rows OR { rows: [...] }
    const user =
      Array.isArray(insertResult) && insertResult.length > 0
        ? insertResult[0]
        : insertResult && insertResult.rows
        ? insertResult.rows[0]
        : null;

    if (!user) {
      console.error("Insert did not return a user:", insertResult);
      return res.status(500).send("Failed to create user");
    }

    // Log the user in and redirect to dashboard
    req.login(user, (err) => {
      if (err) {
        console.error("req.login error:", err);
        return res.status(500).send("Login error after signup");
      }
      return res.redirect("/dashboard");
    });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).send("Server error");
  }
});

// Configure passport-local to use 'email' as the usernameField
passport.use(
  "local",
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async function verify(email, password, cb) {
      if (!email || !password) {
        // For authentication callbacks, call cb with (null, false, info)
        return cb(null, false, { message: "Missing email or password" });
      }

      try {
        // IMPORTANT: sql`` returns an array of row objects (NOT { rows: [...] })
        const rows = await sql`SELECT id, username, password, email FROM users WHERE email = ${email}`;

        if (!rows || rows.length === 0) {
          return cb(null, false, { message: "User not found" });
        }

        const user = rows[0];
        const storedHashedPassword = user.password;

        // Use promise-style compare
        const match = await bcrypt.compare(password, storedHashedPassword);
        if (match) {
          // Don't include password in the session object
          const safeUser = { id: user.id, username: user.username, email: user.email };
          return cb(null, safeUser);
        } else {
          return cb(null, false, { message: "Incorrect password" });
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Use an env var for callback, and default to localhost for local dev
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/auth/google/prowessityvlms";

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: GOOGLE_CALLBACK_URL,
      // passport-google-oauth20 already fetches profile including emails with the profile scope
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        // Extract email correctly from profile
        const email = profile.emails?.[0]?.value;
        const usernameFromProfile = profile.displayName ?? profile.username ?? "GoogleUser";

        if (!email) {
          return cb(new Error("No email found in Google profile"));
        }

        // Query using the tagged template literal and embedded value
        const result = await sql`SELECT id, username, email FROM users WHERE email = ${email}`;

        // Handle result shapes (array or { rows })
        const existingUser =
          Array.isArray(result) && result.length
            ? result[0]
            : result && result.rows && result.rows.length
            ? result.rows[0]
            : null;

        if (!existingUser) {
          // Insert a new user. Provide a placeholder password string for OAuth users.
          const insert = await sql`
            INSERT INTO users (email, username, password)
            VALUES (${email}, ${usernameFromProfile}, ${"google"})
            RETURNING id, email, username
          `;

          const newUser =
            Array.isArray(insert) && insert.length
              ? insert[0]
              : insert && insert.rows
              ? insert.rows[0]
              : null;

          if (!newUser) {
            return cb(new Error("Failed to create user from Google profile"));
          }

          // Return safe user object
          return cb(null, { id: newUser.id, email: newUser.email, username: newUser.username });
        } else {
          return cb(null, { id: existingUser.id, email: existingUser.email, username: existingUser.username });
        }
      } catch (error) {
        console.error("Google strategy error:", error);
        return cb(error);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  // store only the user id in the session
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const rows = await sql`SELECT id, username, email FROM users WHERE id = ${id}`;
    const user = Array.isArray(rows) && rows.length ? rows[0] : rows?.rows?.[0] ?? null;
    cb(null, user);
  } catch (err) {
    cb(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.get(
  "/auth/google/prowessityvlms",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});