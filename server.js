import express from "express";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// ── USERS STORE ──────────────────────────────────────────────────────────────
// users.json lives next to server.js; create it if missing
const USERS_FILE =
  process.env.USERS_FILE_PATH ||
  (process.env.VERCEL
    ? path.join("/tmp", "users.json")
    : path.join(__dirname, "users.json"));
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");

function loadUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}
function findUser(predicate) {
  return loadUsers().find(predicate);
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "evalboard-dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ── PASSPORT: LOCAL ───────────────────────────────────────────────────────────
passport.use(
  new LocalStrategy(async (username, password, done) => {
    const user = findUser(
      (u) => u.username === username && u.provider === "local"
    );
    if (!user) return done(null, false, { message: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return done(null, false, { message: "Invalid credentials" });
    return done(null, user);
  })
);

// ── PASSPORT: GOOGLE ──────────────────────────────────────────────────────────
const HAS_GOOGLE_AUTH =
  Boolean(process.env.GOOGLE_CLIENT_ID) &&
  Boolean(process.env.GOOGLE_CLIENT_SECRET);

if (HAS_GOOGLE_AUTH) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
      },
      (accessToken, refreshToken, profile, done) => {
        const users = loadUsers();
        let user = users.find(
          (u) => u.provider === "google" && u.googleId === profile.id
        );
        if (!user) {
          // Auto-register on first Google sign-in
          user = {
            id: `google_${profile.id}`,
            googleId: profile.id,
            username: profile.emails?.[0]?.value || profile.displayName,
            displayName: profile.displayName,
            provider: "google",
          };
          users.push(user);
          saveUsers(users);
        }
        return done(null, user);
      }
    )
  );
}

// ── PASSPORT: SESSION SERIALIZATION ──────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = findUser((u) => u.id === id);
  done(null, user || false);
});

// ── AUTH GUARD ────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────

// Login page
app.get("/login", (req, res) => {
  if (req.isAuthenticated()) return res.redirect("/");
  res.sendFile(path.join(__dirname, "login.html"));
});

// Local login
app.post(
  "/auth/local",
  passport.authenticate("local", {
    failureRedirect: "/login?error=invalid",
  }),
  (req, res) => res.redirect("/")
);

// Register a new local user (POST — you can expose a UI or call via curl)
app.post("/auth/register", async (req, res) => {
  const { username, password, adminSecret } = req.body;

  // Protect registration with an admin secret set via env var
  if (adminSecret !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }
  if (!username || !password) {
    return res.status(400).json({ error: "username and password required" });
  }

  const users = loadUsers();
  if (users.find((u) => u.username === username && u.provider === "local")) {
    return res.status(409).json({ error: "Username already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const user = {
    id: `local_${Date.now()}`,
    username,
    displayName: username,
    provider: "local",
    passwordHash,
  };
  users.push(user);
  saveUsers(users);
  res.json({ ok: true, username });
});

// Google OAuth
if (HAS_GOOGLE_AUTH) {
  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login?error=google" }),
    (req, res) => res.redirect("/")
  );
} else {
  app.get("/auth/google", (req, res) => {
    res.status(503).json({
      error:
        "Google authentication is not configured on this deployment. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.",
    });
  });
  app.get("/auth/google/callback", (req, res) => {
    res.status(503).json({
      error:
        "Google authentication callback is unavailable because Google auth is not configured.",
    });
  });
}

// Logout
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/login");
  });
});

// ── API: current user info (used by frontend) ─────────────────────────────────
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    username: req.user.username,
    displayName: req.user.displayName,
    provider: req.user.provider,
  });
});

// ── PROTECTED: main app ───────────────────────────────────────────────────────
app.get("/", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// All other static assets (no auth needed for fonts/scripts, but index.html is guarded above)
app.use(express.static(__dirname));

// ── START ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`EvalBoard running on http://localhost:${PORT}`)
);

export default app; // needed for Vercel serverless
