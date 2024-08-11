const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const pool = require("./database");
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: true,
  })
);

app.set("view engine", "ejs");

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    next();
  } else {
    res.redirect("/login");
  }
}

// Routes

// Home route
app.get("/", (req, res) => {
  res.redirect("/login");
});

// Login route
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);
  if (result.rows.length > 0) {
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      req.session.user = user;
      return res.redirect(
        user.role === "admin" ? "/admin-dashboard" : "/player-dashboard"
      );
    }
  }
  res.redirect("/login");
});

// Register route
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
    [name, email, hashedPassword, role]
  );
  res.redirect("/login");
});

// Admin Dashboard
app.get("/admin-dashboard", isAuthenticated, async (req, res) => {
  const sports = await pool.query("SELECT * FROM sports");
  const sessions = await pool.query(`
        SELECT sessions.*, sports.name AS sport_name, users.name AS creator_name
        FROM sessions
        JOIN sports ON sessions.sport_id = sports.id
        JOIN users ON sessions.creator_id = users.id
    `);
  res.render("admin-dashboard", {
    user: req.session.user,
    sports: sports.rows,
    sessions: sessions.rows,
  });
});

app.post("/create-sport", isAuthenticated, async (req, res) => {
  const { name } = req.body;
  await pool.query("INSERT INTO sports (name) VALUES ($1)", [name]);
  res.redirect("/admin-dashboard");
});

app.post("/delete-session", isAuthenticated, async (req, res) => {
  const { session_id } = req.body;
  await pool.query("DELETE FROM sessions WHERE id = $1", [session_id]);
  res.redirect("/admin-dashboard");
});

// Player Dashboard
app.get("/player-dashboard", isAuthenticated, async (req, res) => {
  const sessions = await pool.query(`
        SELECT sessions.*, sports.name AS sport_name
        FROM sessions
        JOIN sports ON sessions.sport_id = sports.id
    `);
  const sports = await pool.query("SELECT * FROM sports");
  res.render("player-dashboard", {
    user: req.session.user,
    sessions: sessions.rows,
    sports: sports.rows,
  });
});

app.post("/create-session", isAuthenticated, async (req, res) => {
  const { sport_id, team1, team2, additional_players, date, venue } = req.body;
  await pool.query(
    "INSERT INTO sessions (sport_id, creator_id, team1, team2, additional_players, date, venue) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [
      sport_id,
      req.session.user.id,
      team1,
      team2,
      additional_players,
      date,
      venue,
    ]
  );
  res.redirect("/player-dashboard");
});

app.post("/join-session", isAuthenticated, async (req, res) => {
  const { session_id } = req.body;
  const user_id = req.session.user.id;

  // Check if the user is already joined to the session
  const existing = await pool.query(
    "SELECT * FROM session_players WHERE session_id = $1 AND player_id = $2",
    [session_id, user_id]
  );

  if (existing.rows.length > 0) {
    // User is already joined, handle this case
    console.log("User is already joined to the session");
    return res.redirect("/player-dashboard");
  }

  // If not, join the session
  await pool.query(
    "INSERT INTO session_players (session_id, player_id) VALUES ($1, $2)",
    [session_id, user_id]
  );

  res.redirect("/player-dashboard");
});

// Logout route
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

// Reports route (admin only)
app.get("/reports", isAuthenticated, async (req, res) => {
  const sessions = await pool.query(`
        SELECT sessions.*, sports.name AS sport_name
        FROM sessions
        JOIN sports ON sessions.sport_id = sports.id
    `);
  const popularity = await pool.query(`
        SELECT sports.name, COUNT(sessions.id) AS count
        FROM sessions
        JOIN sports ON sessions.sport_id = sports.id
        GROUP BY sports.name
    `);
  res.render("reports", {
    sessions: sessions.rows,
    popularity: popularity.rows,
  });
});

// Start server
app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
