import express from "express";
import morgan from "morgan";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import multer from "multer";
import path from "path";
import fs from "fs";
import { sql } from "./db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const saltRounds = 10;

// Make sure uploads dir exists
const UPLOAD_DIR = path.join(process.cwd(), "public", "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Multer config for file uploads with basic file-size limit
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

// Basic express setup
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morgan("dev"));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

// Passport local auth setup
app.use(passport.initialize());
app.use(passport.session());

// Add this small middleware after passport.session() initialization (so req.user is available)
// It ensures every template gets `user` as a local variable (either the logged-in user or null).
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  next();
});

passport.use(
  new LocalStrategy({ usernameField: "email", passwordField: "password" }, async (email, password, done) => {
    try {
      const rowsRes = await sql`SELECT id, username, email, password, role FROM users WHERE email = ${email.toLowerCase()}`;
      const user = Array.isArray(rowsRes) ? rowsRes[0] : rowsRes?.rows?.[0];
      if (!user) return done(null, false, { message: "User not found" });
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return done(null, false, { message: "Incorrect password" });
      return done(null, { id: user.id, username: user.username, email: user.email, role: Number(user.role) });
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, cb) => cb(null, user.id));
passport.deserializeUser(async (id, cb) => {
  try {
    const r = await sql`SELECT id, username, email, role FROM users WHERE id = ${id} LIMIT 1`;
    const user = Array.isArray(r) ? r[0] : r?.rows?.[0];
    cb(null, user || false);
  } catch (err) {
    cb(err);
  }
});

/* -----------------------
   Helper functions
   ----------------------- */
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.redirect("/login");
}
function ensureRole(requiredRole) {
  // role 1 = admin, 2 = instructor, 3 = learner
  return (req, res, next) => {
    if (!req.isAuthenticated || !req.isAuthenticated()) return res.redirect("/login");
    const role = Number(req.user?.role ?? 0);
    if (role === requiredRole || role === 1) return next(); // admin can do everything
    return res.status(403).send("Forbidden");
  };
}
function rows(result) {
  if (!result) return [];
  if (Array.isArray(result)) return result;
  if (result.rows) return result.rows;
  return [];
}

/* -----------------------
   Database initialization - simple beginner-friendly schema
   All tables created with IF NOT EXISTS so running the server is safe.
   ----------------------- */
async function initDB() {
  try {
    // users
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        username VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        role INTEGER NOT NULL DEFAULT 3,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // courses
    await sql`
      CREATE TABLE IF NOT EXISTS courses (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        link TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // enrollments (learner <-> courses)
    await sql`
      CREATE TABLE IF NOT EXISTS enrollments (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        enrolled_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(course_id, learner_id)
      )
    `;

    // instructor_courses (assign instructor to course)
    await sql`
      CREATE TABLE IF NOT EXISTS instructor_courses (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        instructor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        assigned_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(course_id, instructor_id)
      )
    `;

    // instructor_learner (assign instructor to learner)
    await sql`
      CREATE TABLE IF NOT EXISTS instructor_learner (
        id SERIAL PRIMARY KEY,
        instructor_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        assigned_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(instructor_id, learner_id)
      )
    `;

    // attendance (one row per learner/course/date)
    await sql`
      CREATE TABLE IF NOT EXISTS attendance (
        id SERIAL PRIMARY KEY,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        date DATE NOT NULL,
        status CHAR(1) NOT NULL DEFAULT 'A', -- A = Absent, B = Present (beginner friendly)
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(learner_id, course_id, date)
      )
    `;

    // assignments (created by instructor)
    await sql`
      CREATE TABLE IF NOT EXISTS assignments (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        instructor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        file_link TEXT,
        file_original_name TEXT,
        external_link TEXT,
        due_date DATE,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // optional assignment_targets: which learners were targeted for the assignment
    await sql`
      CREATE TABLE IF NOT EXISTS assignment_targets (
        id SERIAL PRIMARY KEY,
        assignment_id INTEGER REFERENCES assignments(id) ON DELETE CASCADE,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(assignment_id, learner_id)
      )
    `;

    // submissions (learner submits for assignment)
    await sql`
      CREATE TABLE IF NOT EXISTS submissions (
        id SERIAL PRIMARY KEY,
        assignment_id INTEGER REFERENCES assignments(id) ON DELETE CASCADE,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        file_link TEXT,
        file_original_name TEXT,
        external_link TEXT,
        submitted_at TIMESTAMP DEFAULT NOW(),
        graded BOOLEAN DEFAULT FALSE,
        grade TEXT,
        feedback TEXT,
        UNIQUE(assignment_id, learner_id)
      )
    `;

    // materials
    await sql`
      CREATE TABLE IF NOT EXISTS materials (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        instructor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        file_link TEXT,
        file_original_name TEXT,
        external_link TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // meetings (google meet link + time)
    await sql`
      CREATE TABLE IF NOT EXISTS meetings (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        instructor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
        link TEXT,
        start_time TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    await sql`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS graded BOOLEAN DEFAULT FALSE`;
    await sql`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS grade TEXT`;
    await sql`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS feedback TEXT`;

    // Optional fields used elsewhere
    await sql`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS file_original_name TEXT`;
    await sql`ALTER TABLE submissions ADD COLUMN IF NOT EXISTS external_link TEXT`;

    // Additional safe ensures (no-op if present)
    await sql`ALTER TABLE assignments ADD COLUMN IF NOT EXISTS file_link TEXT`;
    await sql`ALTER TABLE materials ADD COLUMN IF NOT EXISTS file_link TEXT`;

    // course_progress
    await sql`
      CREATE TABLE IF NOT EXISTS course_progress (
        id SERIAL PRIMARY KEY,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        progress_percent INTEGER DEFAULT 0,
        updated_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(course_id, user_id)
      )
    `;

    // certificate requests
    await sql`
      CREATE TABLE IF NOT EXISTS certificate_requests (
        id SERIAL PRIMARY KEY,
        learner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        course_id INTEGER REFERENCES courses(id) ON DELETE CASCADE,
        requested_at TIMESTAMP DEFAULT NOW(),
        status TEXT DEFAULT 'requested'
      )
    `;

    console.log("Database initialized");
  } catch (err) {
    console.error("DB init error", err);
    throw err;
  }
}

await initDB().catch((e) => console.error(e));

/* -----------------------
   Small query helpers
   ----------------------- */
async function fetchCourses() {
  const r = await sql`SELECT id, title, description, link FROM courses ORDER BY id DESC`;
  return rows(r);
}
async function fetchLearners() {
  const r = await sql`SELECT id, username, email FROM users WHERE role = 3 ORDER BY id DESC`;
  return rows(r);
}
async function fetchInstructors() {
  const r = await sql`SELECT id, username, email FROM users WHERE role = 2 ORDER BY id DESC`;
  return rows(r);
}
async function fetchEnrollmentsForUser(userId) {
  const r = await sql`
    SELECT c.*
    FROM courses c
    JOIN enrollments e ON e.course_id = c.id
    WHERE e.learner_id = ${userId}
    ORDER BY c.id DESC
  `;
  return rows(r);
}
async function fetchAssignmentsForLearner(learnerId) {
  // assignments that target the learner OR where the learner is enrolled in the course
  const r = await sql`
    SELECT DISTINCT a.*, u.username as instructor_name
    FROM assignments a
    LEFT JOIN users u ON u.id = a.instructor_id
    LEFT JOIN assignment_targets at ON at.assignment_id = a.id
    LEFT JOIN enrollments e ON e.course_id = a.course_id AND e.learner_id = ${learnerId}
    WHERE at.learner_id = ${learnerId} OR e.learner_id = ${learnerId}
    ORDER BY a.created_at DESC
  `;
  return rows(r);
}
async function fetchSubmissionsForInstructor(instructorId) {
  const r = await sql`
    SELECT s.*, a.title as assignment_title, u.username as learner_name, c.title as course_title, a.instructor_id
    FROM submissions s
    LEFT JOIN assignments a ON a.id = s.assignment_id
    LEFT JOIN users u ON u.id = s.learner_id
    LEFT JOIN courses c ON c.id = a.course_id
    WHERE a.instructor_id = ${instructorId}
    ORDER BY s.submitted_at DESC
  `;
  return rows(r);
}
async function fetchMaterialsForCourse(courseId) {
  const r = await sql`SELECT * FROM materials WHERE course_id = ${courseId} ORDER BY created_at DESC`;
  return rows(r);
}
async function fetchMeetingsForCourse(courseId) {
  const r = await sql`SELECT * FROM meetings WHERE course_id = ${courseId} ORDER BY start_time DESC`;
  return rows(r);
}
async function fetchAttendanceRecent(limit = 200) {
  const r = await sql`
    SELECT a.*, u.username as learner_name, c.title as course_title
    FROM attendance a
    LEFT JOIN users u ON u.id = a.learner_id
    LEFT JOIN courses c ON c.id = a.course_id
    ORDER BY a.date DESC
    LIMIT ${limit}
  `;
  return rows(r);
}
async function fetchCertificateRequests() {
  const r = await sql`
    SELECT cr.*, u.username as learner_name, c.title as course_title
    FROM certificate_requests cr
    LEFT JOIN users u ON u.id = cr.learner_id
    LEFT JOIN courses c ON c.id = cr.course_id
    ORDER BY cr.requested_at DESC
  `;
  return rows(r);
}

/* -----------------------
   Public routes
   ----------------------- */
app.get("/", async (req, res) => {
  try {
    const courses = await fetchCourses();
    res.render("index", { user: req.user || null, courses: rows(courses) });
  } catch (err) {
    console.error("/", err);
    res.status(500).send("Server error");
  }
});

/* -----------------------
   Auth: signup, login, logout
   Beginner-friendly simple forms, password hashed
   ----------------------- */
app.get("/signup", (req, res) => res.render("signup", { error: null }));
app.post("/signup", async (req, res) => {
  const username = (req.body.username || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  if (!username || !email || !password) return res.render("signup", { error: "All fields are required" });
  if (username.length > 200 || email.length > 200) return res.render("signup", { error: "Input too long" });
  try {
    const existing = await sql`SELECT id FROM users WHERE email = ${email}`;
    if (rows(existing).length) return res.render("signup", { error: "Email already in use" });
    const hash = await bcrypt.hash(password, saltRounds);
    const inserted = await sql`
      INSERT INTO users (email, username, password, role)
      VALUES (${email}, ${username}, ${hash}, ${3})
      RETURNING id, email, username, role
    `;
    const newUser = rows(inserted)[0];
    req.login({ id: newUser.id, username: newUser.username, email: newUser.email, role: Number(newUser.role) }, (err) => {
      if (err) return res.render("signup", { error: "Could not log you in" });
      return res.redirect("/dashboard");
    });
  } catch (err) {
    console.error("Signup error", err);
    return res.render("signup", { error: "Server error" });
  }
});

app.get("/login", (req, res) => res.render("login", { error: null }));
app.post("/login", passport.authenticate("local", { successRedirect: "/dashboard", failureRedirect: "/login" }));

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/login"));
  });
});

/* -----------------------
   Dashboard routing by role
   ----------------------- */
app.get("/dashboard", ensureAuthenticated, (req, res) => {
  const role = Number(req.user.role ?? 3);
  if (role === 1) return res.redirect("/admin-dashboard");
  if (role === 2) return res.redirect("/instructor-dashboard");
  return res.redirect("/learner-dashboard");
});

/* -----------------------
   Admin dashboard
   - create course
   - assign learner/course, instructor/course, instructor/learner
   - view certificate requests & attendance
   ----------------------- */
// Replace the existing /admin-dashboard route in your index.js with this block.
// It fetches course_progress rows and passes them into the admin template as courseProgress.
app.get("/admin-dashboard", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const learners = await fetchLearners();
    const instructors = await fetchInstructors();
    const courses = await fetchCourses();
    const attendance = await fetchAttendanceRecent();
    const certRequests = await fetchCertificateRequests();

    // Fetch recent course progress entries, include learner & course names
    const cpRaw = await sql`
      SELECT cp.*, u.username as learner_name, c.title as course_title
      FROM course_progress cp
      LEFT JOIN users u ON u.id = cp.user_id
      LEFT JOIN courses c ON c.id = cp.course_id
      ORDER BY cp.updated_at DESC
      LIMIT 500
    `;
    const courseProgress = rows(cpRaw);

    res.render("adminDashboard", {
      user: req.user,
      learners,
      instructors,
      courses,
      attendance,
      certificateRequests: certRequests,
      courseProgress,
    });
  } catch (err) {
    console.error("admin-dashboard", err);
    res.status(500).send("Server error");
  }
});

app.post("/admin/courses", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const title = (req.body.title || "").trim();
    const description = (req.body.description || "").trim() || null;
    const link = (req.body.link || "").trim() || null;
    if (!title) return res.status(400).send("Missing title");
    await sql`INSERT INTO courses (title, description, link) VALUES (${title}, ${description}, ${link})`;
    return res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("create course", err);
    res.status(500).send("Server error");
  }
});

// Replace the existing POST /instructor/update-progress handler with this fixed, robust version.
// It preserves your permission checks and upsert behavior but fixes the SQL typos and handles
// the case where the schema may have a learner_id column (some DB variants you showed earlier).
app.post("/instructor/update-progress", ensureAuthenticated, ensureRole(2), async (req, res) => {
  try {
    const instructorId = Number(req.user?.id);
    const courseId = Number(req.body.course_id || req.body.courseId || 0);
    const userId = Number(req.body.user_id || req.body.userId || 0);
    const percentRaw = Number(req.body.progress_percent || req.body.percent || 0);
    const percent = Math.max(0, Math.min(100, Number.isNaN(percentRaw) ? 0 : percentRaw));

    if (!courseId || !userId || Number.isNaN(percent)) {
      return res.status(400).send("Missing or invalid course_id, user_id or progress_percent");
    }

    // Optional permission check: instructor must be assigned to the course unless admin
    const assigned = await sql`SELECT 1 FROM instructor_courses WHERE course_id = ${courseId} AND instructor_id = ${instructorId}`;
    if (!rows(assigned).length && Number(req.user?.role) !== 1) {
      return res.status(403).send("Not assigned to this course");
    }

    // Some deployments/schemas may have a learner_id column (not in the original schema)
    // and some do not. Detect column presence and issue an appropriate upsert so we don't
    // try to insert NULL into learner_id when it exists and is NOT NULL.
    const colCheck = await sql`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'course_progress' AND column_name = 'learner_id'
      LIMIT 1
    `;
    const hasLearnerId = rows(colCheck).length > 0;

    if (hasLearnerId) {
      // if learner_id exists, provide it (use same value as user_id)
      await sql`
        INSERT INTO course_progress (course_id, user_id, learner_id, progress_percent, updated_at)
        VALUES (${courseId}, ${userId}, ${userId}, ${percent}, NOW())
        ON CONFLICT (course_id, user_id)
        DO UPDATE SET progress_percent = EXCLUDED.progress_percent, updated_at = NOW()
      `;
    } else {
      // standard schema: no learner_id column
      await sql`
        INSERT INTO course_progress (course_id, user_id, progress_percent, updated_at)
        VALUES (${courseId}, ${userId}, ${percent}, NOW())
        ON CONFLICT (course_id, user_id)
        DO UPDATE SET progress_percent = EXCLUDED.progress_percent, updated_at = NOW()
      `;
    }

    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("POST /instructor/update-progress error:", err && err.stack ? err.stack : err);
    return res.status(500).send("Server error");
  }
});

// enroll learner
app.post("/admin/enroll", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const learnerId = Number(req.body.learner_id);
    const courseId = Number(req.body.course_id);
    if (!learnerId || !courseId) return res.status(400).send("Missing data");
    await sql`
      INSERT INTO enrollments (course_id, learner_id)
      VALUES (${courseId}, ${learnerId})
      ON CONFLICT (course_id, learner_id) DO NOTHING
    `;
    return res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("enroll", err);
    res.status(500).send("Server error");
  }
});

// assign instructor to course
app.post("/admin/assign-instructor-course", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const instructorId = Number(req.body.instructor_id);
    const courseId = Number(req.body.course_id);
    if (!instructorId || !courseId) return res.status(400).send("Missing data");
    await sql`
      INSERT INTO instructor_courses (course_id, instructor_id)
      VALUES (${courseId}, ${instructorId})
      ON CONFLICT (course_id, instructor_id) DO NOTHING
    `;
    return res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("assign instructor", err);
    res.status(500).send("Server error");
  }
});

// assign instructor to learner
app.post("/admin/assign-instructor-learner", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const instructorId = Number(req.body.instructor_id);
    const learnerId = Number(req.body.learner_id);
    if (!instructorId || !learnerId) return res.status(400).send("Missing data");
    await sql`
      INSERT INTO instructor_learner (instructor_id, learner_id)
      VALUES (${instructorId}, ${learnerId})
      ON CONFLICT (instructor_id, learner_id) DO NOTHING
    `;
    return res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("assign instructor learner", err);
    res.status(500).send("Server error");
  }
});

// update certificate request status
app.post("/admin/certificate-update", ensureAuthenticated, ensureRole(1), async (req, res) => {
  try {
    const id = Number(req.body.request_id);
    const status = (req.body.status || "").trim();
    if (!id || !["requested", "issued"].includes(status)) return res.status(400).send("Invalid input");
    await sql`UPDATE certificate_requests SET status = ${status} WHERE id = ${id}`;
    return res.redirect("/admin-dashboard");
  } catch (err) {
    console.error("certificate update", err);
    res.status(500).send("Server error");
  }
});

/* -----------------------
   Instructor dashboard
   - create assignment (optional file, link), optionally target learners
   - create materials
   - create meeting (google meet link)
   - record attendance
   - view submissions to grade
   ----------------------- */
app.get("/instructor-dashboard", ensureAuthenticated, ensureRole(2), async (req, res) => {
  try {
    const instructorId = req.user.id;
    // courses assigned to this instructor
    const coursesRaw = await sql`SELECT c.* FROM courses c JOIN instructor_courses ic ON ic.course_id = c.id WHERE ic.instructor_id = ${instructorId} ORDER BY c.id DESC`;
    const courses = rows(coursesRaw);

    // learners list for forms
    const learners = await fetchLearners();

    // assignments by this instructor
    const assignments = await sql`SELECT a.*, c.title as course_title FROM assignments a LEFT JOIN courses c ON c.id = a.course_id WHERE a.instructor_id = ${instructorId} ORDER BY a.created_at DESC`;

    // materials by this instructor
    const materials = await sql`SELECT m.*, c.title as course_title FROM materials m LEFT JOIN courses c ON c.id = m.course_id WHERE m.instructor_id = ${instructorId} ORDER BY m.created_at DESC`;

    // meetings by this instructor
    const meetings = await sql`SELECT m.*, c.title as course_title FROM meetings m LEFT JOIN courses c ON c.id = m.course_id WHERE m.instructor_id = ${instructorId} ORDER BY m.start_time DESC`;

    // submissions to grade
    const submissionsToGrade = await fetchSubmissionsForInstructor(instructorId);

    // recent attendance for admin/instructor overview
    const attendance = await fetchAttendanceRecent();

    res.render("instructorDashboard", {
      user: req.user,
      courses,
      learners,
      assignments: rows(assignments),
      materials: rows(materials),
      meetings: rows(meetings),
      submissions: submissionsToGrade,
      attendance,
    });
  } catch (err) {
    console.error("instructor-dashboard", err);
    res.status(500).send("Server error");
  }
});

// Create assignment (optional file upload). instructor can choose target learners (array of learner ids)
app.post("/instructor/create-assignment", ensureAuthenticated, ensureRole(2), upload.single("file"), async (req, res) => {
  try {
    const instructorId = req.user.id;
    const courseId = Number(req.body.course_id);
    const title = (req.body.title || "").trim();
    const description = (req.body.description || "").trim() || null;
    const external_link = (req.body.external_link || "").trim() || null;
    const due_date = req.body.due_date || null;

    if (!title || !courseId) return res.status(400).send("Missing title or course");

    let file_link = null;
    let file_original_name = null;
    if (req.file) {
      file_link = `/uploads/${req.file.filename}`;
      file_original_name = req.file.originalname || null;
    }

    const inserted = await sql`
      INSERT INTO assignments (course_id, instructor_id, title, description, file_link, file_original_name, external_link, due_date)
      VALUES (${courseId}, ${instructorId}, ${title}, ${description}, ${file_link}, ${file_original_name}, ${external_link}, ${due_date})
      RETURNING id
    `;
    const assignmentId = rows(inserted)[0]?.id;

    // if instructor provided targeted learner ids (array), insert into assignment_targets
    const targets = req.body.target_learners;
    if (assignmentId && targets) {
      const arr = Array.isArray(targets) ? targets : [targets];
      for (const t of arr) {
        const learnerId = Number(t);
        if (!Number.isNaN(learnerId)) {
          await sql`INSERT INTO assignment_targets (assignment_id, learner_id) VALUES (${assignmentId}, ${learnerId}) ON CONFLICT DO NOTHING`;
        }
      }
    }

    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("create-assignment", err);
    res.status(500).send("Server error");
  }
});

// grade submission
app.post("/instructor/grade", ensureAuthenticated, ensureRole(2), async (req, res) => {
  try {
    const submissionId = Number(req.body.submission_id);
    const grade = (req.body.grade || "").trim();
    const feedback = (req.body.feedback || "").trim() || null;
    if (!submissionId || !grade) return res.status(400).send("Missing data");

    // Optionally check permission (instructor owns assignment). Simple check: instructor or admin allowed.
    const check = await sql`
      SELECT s.id
      FROM submissions s
      LEFT JOIN assignments a ON a.id = s.assignment_id
      WHERE s.id = ${submissionId} AND (a.instructor_id = ${req.user.id} OR ${req.user.id} = 1)
      LIMIT 1
    `;
    if (!rows(check).length) return res.status(403).send("Not allowed to grade");

    await sql`UPDATE submissions SET graded = TRUE, grade = ${grade}, feedback = ${feedback} WHERE id = ${submissionId}`;
    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("grade", err);
    res.status(500).send("Server error");
  }
});

// create materials (optional upload)
app.post("/instructor/create-material", ensureAuthenticated, ensureRole(2), upload.single("file"), async (req, res) => {
  try {
    const instructorId = req.user.id;
    const courseId = Number(req.body.course_id);
    const title = (req.body.title || "").trim();
    const description = (req.body.description || "").trim() || null;
    const external_link = (req.body.external_link || "").trim() || null;
    if (!title || !courseId) return res.status(400).send("Missing title or course");

    let file_link = null;
    let file_original_name = null;
    if (req.file) {
      file_link = `/uploads/${req.file.filename}`;
      file_original_name = req.file.originalname || null;
    }

    await sql`
      INSERT INTO materials (course_id, instructor_id, title, description, file_link, file_original_name, external_link)
      VALUES (${courseId}, ${instructorId}, ${title}, ${description}, ${file_link}, ${file_original_name}, ${external_link})
    `;
    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("create material", err);
    res.status(500).send("Server error");
  }
});

// create meeting (google meet link)
app.post("/instructor/create-meeting", ensureAuthenticated, ensureRole(2), async (req, res) => {
  try {
    const instructorId = req.user.id;
    const courseId = Number(req.body.course_id);
    const link = (req.body.link || "").trim();
    const start_time = req.body.start_time || null;
    if (!courseId || !link || !start_time) return res.status(400).send("Missing data");
    await sql`INSERT INTO meetings (course_id, instructor_id, link, start_time) VALUES (${courseId}, ${instructorId}, ${link}, ${start_time})`;
    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("create meeting", err);
    res.status(500).send("Server error");
  }
});

// record attendance for many learners on a given date
app.post("/instructor/record-attendance", ensureAuthenticated, ensureRole(2), async (req, res) => {
  try {
    const instructorId = req.user.id;
    const courseId = Number(req.body.course_id);
    const date = req.body.date;
    // expected body: statuses like status_<learnerId> = 'A' or 'B'
    if (!courseId || !date) return res.status(400).send("Missing course or date");

    // For simple beginner UI, instructor sends statuses in the form
    // Iterate keys and look for status_*
    for (const key of Object.keys(req.body)) {
      const match = key.match(/^status_(\d+)$/);
      if (!match) continue;
      const learnerId = Number(match[1]);
      const statusRaw = (req.body[key] || "").toUpperCase().trim();
      const status = statusRaw === "B" ? "B" : "A"; // default to Absent if not B
      await sql`
        INSERT INTO attendance (learner_id, course_id, date, status)
        VALUES (${learnerId}, ${courseId}, ${date}, ${status})
        ON CONFLICT (learner_id, course_id, date)
        DO UPDATE SET status = EXCLUDED.status, created_at = NOW()
      `;
    }

    return res.redirect("/instructor-dashboard");
  } catch (err) {
    console.error("record attendance", err);
    res.status(500).send("Server error");
  }
});

/* -----------------------
   Learner dashboard
   - view enrolled courses, materials, meetings
   - submit assignment (upload or link) -> appears to instructor for grading
   - request certificate (only if progress=100)
   ----------------------- */
app.get("/learner-dashboard", ensureAuthenticated, ensureRole(3), async (req, res) => {
  try {
    const userId = req.user.id;
    const courses = await fetchEnrollmentsForUser(userId);
    const assignments = await fetchAssignmentsForLearner(userId);
    const submissions = await sql`SELECT s.*, a.title as assignment_title FROM submissions s LEFT JOIN assignments a ON a.id = s.assignment_id WHERE s.learner_id = ${userId} ORDER BY s.submitted_at DESC`;
    const progress = await sql`SELECT * FROM course_progress WHERE user_id = ${userId}`;
    // For each enrolled course, fetch materials and meetings (simple demo)
    const courseIds = rows(courses).map((c) => c.id);
    const materials = [];
    const meetings = [];
    for (const cid of courseIds) {
      const m = await fetchMaterialsForCourse(cid);
      const mt = await fetchMeetingsForCourse(cid);
      materials.push(...m);
      meetings.push(...mt);
    }
    res.render("learnerDashboard", {
      user: req.user,
      courses: rows(courses),
      assignments: rows(assignments),
      submissions: rows(submissions),
      progress: rows(progress),
      materials,
      meetings,
      learners: [req.user], // simple select so learner can choose themselves when submitting
    });
  } catch (err) {
    console.error("learner-dashboard", err);
    res.status(500).send("Server error");
  }
});

// submit assignment (file optional)
app.post("/learner/submit-assignment", ensureAuthenticated, ensureRole(3), upload.single("file"), async (req, res) => {
  try {
    const learnerId = req.user.id;
    const assignmentId = Number(req.body.assignment_id);
    const external_link = (req.body.external_link || "").trim() || null;
    if (!assignmentId) return res.status(400).send("Missing assignment");
    // prevent duplicate submissions via unique constraint
    const exists = await sql`SELECT id FROM submissions WHERE assignment_id = ${assignmentId} AND learner_id = ${learnerId}`;
    if (rows(exists).length) return res.status(409).send("Already submitted");

    let file_link = null;
    let file_original_name = null;
    if (req.file) {
      file_link = `/uploads/${req.file.filename}`;
      file_original_name = req.file.originalname || null;
    }

    await sql`
      INSERT INTO submissions (assignment_id, learner_id, file_link, file_original_name, external_link)
      VALUES (${assignmentId}, ${learnerId}, ${file_link}, ${file_original_name}, ${external_link})
    `;
    return res.redirect("/learner-dashboard");
  } catch (err) {
    console.error("submit assignment", err);
    res.status(500).send("Server error");
  }
});

// request certificate
app.post("/learner/request-certificate", ensureAuthenticated, ensureRole(3), async (req, res) => {
  try {
    const learnerId = req.user.id;
    const courseId = Number(req.body.course_id);
    if (!courseId) return res.status(400).send("Missing course");

    // Check progress
    const progRes = await sql`SELECT progress_percent FROM course_progress WHERE course_id = ${courseId} AND user_id = ${learnerId} LIMIT 1`;
    const prog = rows(progRes)[0];
    const percent = prog ? Number(prog.progress_percent || 0) : 0;
    if (percent < 100) return res.status(400).send("Course not complete (100% required)");

    await sql`
      INSERT INTO certificate_requests (learner_id, course_id)
      VALUES (${learnerId}, ${courseId})
      ON CONFLICT DO NOTHING
    `;

    return res.redirect("/learner-dashboard");
  } catch (err) {
    console.error("request certificate", err);
    res.status(500).send("Server error");
  }
});

/* -----------------------
   Start server
   ----------------------- */
app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});