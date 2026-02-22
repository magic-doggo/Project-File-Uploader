const path = require("node:path");
const bcrypt = require("bcryptjs");

const express = require("express");
const app = express();

const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const { body, validationResult } = require('express-validator');
app.use(express.urlencoded({ extended: false }));

//https://github.com/kleydon/prisma-session-store#readme
const expressSession = require('express-session');
require('dotenv/config'); //not require('dotenv').config(); ?
const { PrismaPg } = require('@prisma/adapter-pg');  // For other db adapters, see Prisma docs
const { PrismaClient } = require('./generated/prisma/client.js');
const { PrismaSessionStore } = require('@quixo3/prisma-session-store');

// DATABASE_URL defined in env file included in prisma.config.js; see Prisma docs
const connectionString = `${process.env.DATABASE_URL}`;
const adapter = new PrismaPg({ connectionString });
const prisma = new PrismaClient({ adapter });

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");


app.use(
  expressSession({
    cookie: {
      maxAge: 7 * 24 * 60 * 60 * 1000 // ms
    },
    secret: process.env.role_password,
    resave: true,
    saveUninitialized: true,
    store: new PrismaSessionStore(
      prisma,
      {
        checkPeriod: 2 * 60 * 1000,  //ms
        dbRecordIdIsSessionId: true,
        dbRecordIdFunction: undefined,
      }
    )
  })
);
app.use(passport.session());

app.get("/", (req, res) => {console.log("current user: ", req.user); res.render("index", {user: req.user})});
app.get("/sign-up", (req, res) => res.render("sign-up", {user: req.user}));
app.get("/sign-in", (req, res) => res.render("sign-in", {user: req.user}));
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  })
});

app.post("/sign-up",
  //maybe try importing a full validateUser instead? https://www.theodinproject.com/lessons/nodejs-forms-and-data-handling
  //and add withMessage for to show valid errors in ejs using locals.errors
  body('password').isLength({ min: 5 }),
  body('confirmPassword').custom((value, { req }) => {
    return value === req.body.password;
  }),
  async (req, res, next) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render("sign-up", {
        errors: errors.array(),
        data: req.body
      })
    }

    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      // await pool.query("INSERT INTO Users (email, password, first_name, last_name) VALUES ($1, $2, $3, $4)", [
      //   req.body.email,
      //   hashedPassword,
      // ]);
      const user = await prisma.user.create({
        data: {
          email: req.body.email,
          password: hashedPassword,
        },
      });
      res.redirect("/");
    } catch (err) {
      return next(err);
    }
  });

  app.post("/sign-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/sign-in"
  })
)

passport.use(
  new LocalStrategy({
    usernameField: "email",
  }, async (email, password, done) => {
    try {
      // const { rows } = await pool.query("SELECT * FROM Users WHERE email = $1", [username]);
      // const user = rows[0];
      const user = await prisma.user.findUnique({ where: { email: email } }) //where: {id: 42}
      console.log(user, "user")
      if (!user) {
        console.log("no user")
        return done(null, false, { message: "Incorrect username" });
      }
      const match = await bcrypt.compare(password, user.password);
      if (!match) {
        console.log("wrong pass")
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    }
    catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
})

passport.deserializeUser(async (id, done) => {
  try {
    // const { rows } = await pool.query("SELECT * FROM Users where id = $1", [id]);
    // const user = rows[0];
    const user = await prisma.user.findUnique({ where: { id: Number(id) } })
    done(null, user);
  } catch (err) {
    done(err);
  }
})


const PORT = 3000;
app.listen(PORT, (error) => {
  if (error) {
    throw error;
  }
  console.log("app listening on port 3000!");
});

