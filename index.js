import express from "express";
import morgan from "morgan";
import { sql } from "./db.js";
import dotenv from "dotenv";

const app = express();
const port = process.env.PORT || 3000;

dotenv.config();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

async function initDB() {
  try {
    // Create table if it doesn't exist
    await sql`
      CREATE TABLE IF NOT EXISTS items (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL
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
    console.log("SQL result:", result);
    const items = Array.isArray(result) ? result : result.rows ?? [];
    console.log("items:", items);

    res.render("index.ejs", {
      listItems: items,
    });
  } catch (err) {
    console.log(err);
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

    // Hash password before storing
    // const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user and return new id
    const insertResult = await sql`
      INSERT INTO users (email, password, username)
      VALUES (${email}, ${password}, ${username})
      RETURNING id
    `;

    const newId = insertResult?.[0]?.id ?? null;
    console.log("Created user id:", newId);

    // Render or redirect after successful signup
    return res.render("dashboard.ejs", { userId: newId, username });
  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).send("Server error");
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.email || req.body.username; // accept either field name
  const password = req.body.password;

  if (!email || !password) {
    return res.status(400).send("Missing email or password");
  }

  try {
    // Prevent caching of sensitive responses
    res.set("Cache-Control", "no-store");

    // IMPORTANT: sql`` returns an array of row objects (NOT { rows: [...] })
    const rows = await sql`SELECT id, username, password FROM users WHERE email = ${email}`;

    // Debug line you can uncomment to inspect the DB result shape:
    // console.log("login query rows:", rows);

    if (!rows || rows.length === 0) {
      return res.status(401).send("User not found");
    }
    const user = rows[0];
    const storedPassword = user.password;
    // Compare password (bcrypt expected). If you still have plaintext passwords,
    // the fallback below will allow login and immediately migrate that user to bcrypt.
    // let passwordMatches = false;

    if (rows.length > 0) {
      const user = rows[0];
      const storedPassword = user.password;

      if (password === storedPassword) {
        res.render("dashboard.ejs", {
          userId: user.id,
          username: user.username,
        });
      } else {
        res.send("Incorrect Password");
      }
    } else {
      res.send("User not found");
    }
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).send("Server error");
  }
});

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
