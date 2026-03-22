const path = require("node:path");
const fs = require("node:fs/promises");
const bcrypt = require("bcryptjs");

const express = require("express");
const multer = require('multer')
const upload = multer({ dest: 'uploads/' })
const app = express();

const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const { body, validationResult } = require('express-validator');
app.use(express.urlencoded({ extended: false }));

const { prisma } = require('./lib/prisma.js')
const { PrismaSessionStore } = require('@quixo3/prisma-session-store');
const expressSession = require('express-session');

//https://github.com/kleydon/prisma-session-store#readme   ; moved most of this to lib/prisma.js
// require('dotenv/config'); //not require('dotenv').config(); ?
// const { PrismaPg } = require('@prisma/adapter-pg');  // For other db adapters, see Prisma docs
// const { PrismaClient } = require('./generated/prisma/client.js');
// DATABASE_URL defined in env file included in prisma.config.js;
// const connectionString = `${process.env.DATABASE_URL}`;
// const adapter = new PrismaPg({ connectionString });
// const prisma = new PrismaClient({ adapter });

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

const fileRouter = require("./routes/fileRouter.js")

app.get("/", async (req, res) => {
  if (!req.user) return res.render("index", { user: null, folders: [], currentFolder: null });
  const folders = await prisma.folder.findMany({
    where: { parentId: null, userId: req.user.id }
  });
  const files = await prisma.file.findMany({
    where: {
      folderId: null, //in home folder
      userId: req.user.id
    }
  })
  console.log(files)
  res.render("index", { user: req.user, folders, currentFolder: { files: files } }) // currentFolder is used by app.get("/:id") route, which shares same index page ejs
});


app.get("/sign-up", (req, res) => res.render("sign-up", { user: req.user }));
app.get("/sign-in", (req, res) => res.render("sign-in", { user: req.user }));
app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  })
});

app.get("/download/:fileId", async (req, res) => {
  try {
    const file = await prisma.file.findUnique({
      where: {
        id: parseInt(req.params.fileId),
        userId: req.user.id
      }
    });
    if (!file) return res.status(404).send("File not Found");
    const absolutePath = path.join(__dirname, file.url);
    res.download(absolutePath, file.name);
  } catch (err) {
    console.error(err);
    res.status(500).send("error downloading file");
  }
})

app.use("/file", fileRouter);

// app.get("/file/:fileId", async(req, res) => {
//   try {
//     const file = await prisma.file.findUnique({
//       where: {
//         id: parseInt(req.params.fileId),
//         userId: req.user.id
//       }
//     });
//     if (!file) return res.status(404).send('File not Found');
//     res.render("file", { file: file})
//   } catch (err) {
//     console.err(err);
//     res.status(500).send("error getting file details")
//   }
// })

//MAKE SURE! this is the last .get routes, otherwise this would get called for get requests like /sign-up
//this route is made specifically to get folder ids. find a better way?
app.get("/:id", async (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  try {
    const folderId = parseInt(req.params.id);
    const currentFolder = await prisma.folder.findUnique({
      where: {
        id: folderId,
        userId: req.user.id
      },
      include: { children: true, files: true }
    });
    if (!currentFolder) return res.status(404).send("Folder not found")
    console.log("currentFolder: ", currentFolder, " CurrentFolderChildren: ", currentFolder.children)
    res.render("index", { user: req.user, folders: currentFolder.children, currentFolder })

  } catch (err) {
    next(err)
  }
  // console.log("current user: ", req.user);
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

//upload files either in home page or specified folderId
//maybe move .get / and /:id to same get call in array like below when moving this to separate route folders?
app.post(["/upload", "/upload/:folderId"], upload.array('files', 10), async (req, res) => {
  const parentFolderId = req.params.folderId ? parseInt(req.params.folderId) : null;
  console.log("req.files: ", req.files, "req.params: ", req.params)
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).send('No files uploaded');
    }
    console.log(`uploaded ${req.files.length} files(s)`)
    const filesData = req.files.map(file => ({
      name: file.originalname,
      url: file.path,
      size: file.size,
      folderId: parentFolderId,
      userId: req.user.id
    }));
    console.log("files data: ", filesData)

    await prisma.file.createManyAndReturn({
      data: filesData,
    })
    let redirectURL = parentFolderId ? `/${parentFolderId}` : "/"
    res.redirect(redirectURL);
  } catch (err) {
    console.error(err);
    res.status(500).send("Upload failed");
  }
})

app.post("/deleteFile/:fileId", async (req, res) => {
  if (!req.user) return res.redirect("/sign-in");
  let fileId = parseInt(req.params.fileId);
  try {
    const file = await prisma.file.findUnique({
      where: {
        id: fileId,
        userId: req.user.id
      }
    });
    if (!file) {
      return res.status(404).send("File not found or belongs to another user")
    }

    try {
      const filePath = path.join(__dirname, file.url);
      await fs.unlink(filePath);
    } catch (err) {
      console.err("Could not delete from file system: ", err)
    }

    await prisma.file.delete({
      where: {
        id: fileId
      }
    });
    const backURL = req.get('Referrer') || '/';
    res.redirect(backURL);
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to delete file");
  }

  // try {
  //   await prisma.file.delete({
  //     where: {
  //       id: fileId,
  //       userId: req.user.id
  //     }
  //   })
  //   const backURL = req.get('Referrer') || '/';
  //   res.redirect(backURL);
  // } catch (err) {
  //   console.error(err);
  //   res.status(500).send("Failed to delete file")
  // }
})

app.post("/createNewFolder", async (req, res) => {
  // console.log("req.params: ", req.params.path , " req.body: ", req.body)
  await prisma.folder.create({
    data: {
      name: req.body.folder,
      userId: req.user.id,
      parentId: null
    }
  })
  // res.send(`Folder path: ${folderLocation}/${req.body.folder}`)
  res.redirect("/");
});

app.post("/:id/createNewFolder", async (req, res, next) => {
  if (isNaN(req.params.id)) return next();
  const parentFolderId = parseInt(req.params.id);
  try {
    const parentFolder = await prisma.folder.findFirst({
      where: {
        id: parentFolderId,
        userId: req.user.id
      }
    });
    if (!parentFolder) return res.status(404).send("Parent folder not found / Access Denied");
    await prisma.folder.create({
      data: {
        name: req.body.folder,
        userId: req.user.id,
        parentId: parentFolderId
      }
    })
    res.redirect(`/${parentFolderId}`);
  } catch (err) {
    console.error(err);
    res.status(500).send("server error");
  }
})

app.post("/renameFolder/:id", async (req, res) => {
  try {
    const updateFolder = await prisma.folder.update({
      where: {
        id: parseInt(req.params.id),
        userId: req.user.id
      },
      data: { name: req.body.newName }
    })
    // 'back' was deprecated https://expressjs.com/en/4x/api.html, use this to refresh
    const backURL = req.get('Referrer') || '/';
    res.redirect(backURL);
  }
  catch (err) {
    console.error()
    res.status(500).send("Could not rename folder. It does not exist or you do not own this folder");
  }
})

app.post("/deleteFolder/:id", async (req, res) => {
  if (!req.user) return res.redirect("/sign-in");
  try {
    const folderId = parseInt(req.params.id);

    async function getAllDescendantFolderIds(parentId) {
      const children = await prisma.folder.findMany({
        where: {
          parentId: parentId,
          userId: req.user.id
        }
      })
      let ids = children.map(c => c.id);
      for (let child of children) {
        const descendantIds = await getAllDescendantFolderIds(child.id);
        ids = ids.concat(descendantIds)
      }
      return ids;
    }

    const descendantFolderIds = await getAllDescendantFolderIds(folderId);
    const allFolderIds = [folderId, ...descendantFolderIds];
    const files = await prisma.file.findMany({
      where: {
        folderId: { in: allFolderIds },
        userId: req.user.id
      }
    })

    for (let file of files) {
      try {
        let filePath = path.join(__dirname, file.url);
        await fs.unlink(filePath)
      } catch (err) {
        console.error(`Could not delete from file system file ${file.name}: ` , err);
      }
    }
    await prisma.folder.delete({
      where: {
        id: folderId,
        userId: req.user.id
      }
    });
    const backURL = req.get('Referrer') || '/';
    res.redirect(backURL);
  } catch (err) {
    console.error()
    res.status(500).send("Could not delete folder. It does not exist or you do not own this folder");
  }
})

passport.use(
  new LocalStrategy({
    usernameField: "email",
  }, async (email, password, done) => {
    try {
      // const { rows } = await pool.query("SELECT * FROM Users WHERE email = $1", [username]);
      // const user = rows[0];
      const user = await prisma.user.findUnique({ where: { email: email } }) //where: {id: 42}
      // console.log(user, "user")
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



// if i proceed with null home folder for each user:
// each file must have an user assigned to it
// the folderid of a file can be null
// need separate logic in ejs and app.js/routes for creating in home page vs inside a folder
