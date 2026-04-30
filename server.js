import "dotenv/config";
import express from "express";
import session from "cookie-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const ENV_AUTH_USERNAME = process.env.AUTH_USERNAME;
const ENV_AUTH_PASSWORD = process.env.AUTH_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ENV_AUTH_USERNAME || !ENV_AUTH_PASSWORD) {
  throw new Error(
    "Missing AUTH_USERNAME or AUTH_PASSWORD in environment variables."
  );
}

if (!SESSION_SECRET || SESSION_SECRET === "evalboard-dev-secret-change-me") {
  throw new Error(
    "SESSION_SECRET must be set to a strong random value before starting the server."
  );
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    name: "session",
    keys: [SESSION_SECRET],
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ── PASSPORT: LOCAL ───────────────────────────────────────────────────────────
passport.use(
  new LocalStrategy((username, password, done) => {
    if (username !== ENV_AUTH_USERNAME || password !== ENV_AUTH_PASSWORD) {
      return done(null, false, { message: "Invalid credentials" });
    }

    return done(null, {
      id: "env_local_user",
      username: ENV_AUTH_USERNAME,
      displayName: ENV_AUTH_USERNAME,
      provider: "env-local",
    });
  })
);

// ── PASSPORT: SESSION SERIALIZATION ──────────────────────────────────────────
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  if (id !== "env_local_user") return done(null, false);
  done(null, {
    id: "env_local_user",
    username: ENV_AUTH_USERNAME,
    displayName: ENV_AUTH_USERNAME,
    provider: "env-local",
  });
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
