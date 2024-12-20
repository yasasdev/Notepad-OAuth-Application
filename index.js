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

app.get("/logout", (req, res) => {
  req.logout(function (err){
    if(err){
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/notes", async (req, res) => {
  if (req.isAuthenticated()){
    // console.log("Authenticated:", req.isAuthenticated());
    // console.log("User:", req.user);
    try {
      const result = await db.query("SELECT id,notes FROM notes WHERE email=$1", [req.user.email]);
      const notes = result.rows;
      res.render("notes.ejs", {
        notes: notes
      });
    } catch (error) {
      console.log(error);      
    }
  } else {
    res.redirect("/login");
  }
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

app.post("/add", async (req, res) => {
  const note = req.body.newNote;
  try {
    const result = await db.query(
      "INSERT INTO notes (email, notes) VALUES ($1, $2) RETURNING *", [req.user.email, note]
    );
    res.redirect("/notes");
  } catch (error) {
    console.log(error);    
  }
});

app.post("/edit", async (req, res) => {
  const noteId = req.body.noteId;
  const updatedNote = req.body.newNote;
  try {
    await db.query("UPDATE notes SET notes = $1 WHERE id = $2", [updatedNote, noteId]);
    res.redirect("/notes");
  } catch (error) {
    console.error("Error editing note:", error);
    res.redirect("/notes");  
  }
});

app.post("/delete", async (req, res) => {
  const deleteNoteId = req.body.deleteItemId;
  try {
    await db.query("DELETE FROM notes WHERE id = $1", [deleteNoteId]);
    res.redirect("/notes");
  } catch (error) {
    console.error("Error deleting note:", error);
    res.redirect("/notes");
    
  }
});

app.post('/login', 
  passport.authenticate('local', {
    successRedirect: '/notes',
    failureRedirect: '/login',
  })
);

app.post("/add", async (req, res) => {
  const note = req.body.note;
  // console.log("Note:", note);
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if(checkResult.rows.length > 0){
      // console.log("User  already exists");
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

          // Inserting the user's email into the notes table
          await db.query(
            "INSERT INTO notes (email, notes) VALUES ($1, $2)", 
            [email, "Default note, feel fre to edit or delete."]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            // console.log("Successfully registered and logged in");
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
  new Strategy(async function verify(username, password, cb) {
    try {
      // console.log("Verifying user");
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if(result.rows.length > 0){
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if(err){
            console.error("Error comparing passwords: ", err);
            return cb(err);
          } else {
            if(valid) {
              // console.log("User authenticated successfully");
              return cb(null, user);
            } else {
              console.log("Invalid password");
              return cb(null, false);
            }
          }
        });
      } else {
        // console.log("User not found");
        return cb(null, false);
      }
    } catch (err) {
      console.error("Error during login:", err);
      return cb(err);
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
        // console.log("Google Profile:", profile);
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);

        if(result.rows.length === 0){
          //Inserting a new user to the users table
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]
          );

          // Inserting the user's email into the notes table
          await db.query(
            "INSERT INTO notes (email, notes) VALUES ($1, $2)", 
            [profile.email, "Default note, feel fre to edit or delete."]
          );

          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        console.error("Error in Google Strategy:", err);  
        return cb(err);  
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); // Storing only the user ID in the session
});

passport.deserializeUser(async (id, cb) => {
  try {
    const user = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, user.rows[0]);
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});