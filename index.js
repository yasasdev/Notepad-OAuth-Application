import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
    res.render("index.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/notes",
  passport.authenticate("google", {
    successRedirect: "/notes",
    failureRedirect: "/login",
  })
);

app.post("/login",
  passport.authenticate("local", {
    successRedirect: "/notes",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if(checkResult.rows.length > 0){
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if(err){
          console.error("Error hashing password: ", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", 
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("Successfully registered and logged in");
            res.redirect("/notes");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use("local",
  new Strategy(async function verify(email, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if(result.rows.length > 0){
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if(err){
            console.error("Error comparing passwords: ", err);
            return cb(err);
          } else {
            if(valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, "User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.use("google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/notes",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if(result.rows.length === 0){
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);  
      }
    }
  )
);

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});