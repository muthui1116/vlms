import express from "express";
import morgan from "morgan";
// import pg from "pg";
import { sql } from "./db.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

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

// const db = new pg.Client({
//   user: "postgres",
//   host: "localhost",
//   database: "vlms",
//   password: "1234567fkq.",
//   port: 5432,
// });
// db.connect();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

app.get("/", async (req, res) => {
  try {
    const result = await sql`SELECT * FROM items ORDER BY id ASC`;
    console.log("SQL result:", result);
    // const items = result.rows;
    const items = Array.isArray(result) ? result : result.rows ?? [];
    console.log("items:", items);

    res.render("index.ejs", {
      listTitle: "Today",
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

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});
