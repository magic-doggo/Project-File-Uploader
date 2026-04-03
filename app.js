const path = require("node:path");
const fs = require("node:fs/promises");
const bcrypt = require("bcryptjs");
require('dotenv/config');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');


const express = require("express");
const multer = require('multer')
// const upload = multer({ dest: 'uploads/' })
const upload = multer({
  storage: multer.memoryStorage(), //https://cloudinary.com/blog/guest_post/upload-images-to-cloudinary-with-node-js-and-react memory storage (ram) instead of disk storage
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit per file
    files: 5 // Max 5 files/request
  },
  fileFilter: (req, file, cb) => {
    const blockedExtensions = ['.exe', '.bat', '.msi', '.cmd', '.sh', '.vbs', '.scr'];
    const ext = path.extname(file.originalname).toLowerCase();

    if (blockedExtensions.includes(ext)) {
      return cb(new Error(`Security block: ${ext} files are not allowed.`), false);
    }
    cb(null, true);
  }
});

const app = express();

const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
const { body, validationResult } = require('express-validator');
app.use(express.urlencoded({ extended: false }));

const { prisma } = require('./lib/prisma.js')
const { PrismaSessionStore } = require('@quixo3/prisma-session-store');
const expressSession = require('express-session');

//https://github.com/kleydon/prisma-session-store#readme   ; moved most of this to lib/prisma.js
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

const fileRouter = require("./routes/fileRouter.js");
const { resolve } = require("node:dns");

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
  // console.log("FILES: ",files)
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
    const resourceType = file.url.includes('/raw/') ? 'raw'
      : file.url.includes('/video/') ? 'video'
        : 'image';
    const fileExtension = resourceType === 'raw' ? '' : file.name.split('.').pop();
    // //https://cloudinary.com/documentation/control_access_to_media#example_2_video_with_extended_expiry_time
    const signedUrl = cloudinary.utils.private_download_url(
      file.publicId,
      fileExtension,
      {
        resource_type: resourceType,
        expires_at: Math.floor(Date.now() / 1000) + 3600,
        attachment: true
      }
    );
    res.redirect(signedUrl);
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
    // console.log("currentFolder: ", currentFolder, " CurrentFolderChildren: ", currentFolder.children)
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
app.post(["/upload", "/upload/:folderId"], upload.array('files', 5), async (req, res) => {
  const parentFolderId = req.params.folderId ? parseInt(req.params.folderId) : null;
  console.log("req.files: ", req.files, "req.params: ", req.params)
  if (!req.files || req.files.length === 0) {
    return res.status(400).send('No files uploaded');
  }
  // https://cloudinary.com/blog/node_js_file_upload_to_a_local_server_or_to_the_cloud
  const uploadPromises = req.files.map(file => {
    return new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: "auto",
          type: "private",
          public_id: file.originalname
        },
        (error, result) => { //error, result
          if (error) reject(error);
          else resolve(result)
        }
      );
      streamifier.createReadStream(file.buffer).pipe(uploadStream);
    })
  });
  try {
    const cloudinaryResults = await Promise.all(uploadPromises);
    const filesData = cloudinaryResults.map((result, index) => ({
      name: req.files[index].originalname,
      url: result.secure_url,
      publicId: result.public_id, //https://cloudinary.com/documentation/control_access_to_media#providing_time_limited_access_to_private_media_assets
      size: result.bytes,
      folderId: parentFolderId,
      userId: req.user.id
    }));
    console.log(filesData, "filesdata")
    await prisma.file.createManyAndReturn({
      data: filesData,
    });
    let redirectURL = parentFolderId ? `/${parentFolderId}` : "/"
    res.redirect(redirectURL);
  } catch (err) {
    console.error(err);
    res.status(500).send("Upload Failed");
  }
})
//to stop app from crashing invalid files attached
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).send(`Upload error: ${err.message}`);
  } else if (err) {
    return res.status(400).send(err.message);
  }
  next();
});

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
    // find Cloudinary bucket type
    const resourceType = file.url.includes('/raw/') ? 'raw'
      : file.url.includes('/video/') ? 'video'
        : 'image';

    const cloudinaryResponse = await cloudinary.uploader.destroy(file.publicId, {
      type: "private",
      resource_type: resourceType
    });
    if (cloudinaryResponse.result !== "ok") {
      console.error("Cloudinary deletion failed: ", cloudinaryResponse);
      return res.status(500).send(`Failed to delete from Cloudinary: ${cloudinaryResponse.result}`);
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
      try {//could try without try catch, so app stops the process if there is an error, and does not delete folder? would help against files orphaned in cloudinary 
        const resourceType = file.url.includes('/raw/') ? 'raw'
          : file.url.includes('/video/') ? 'video'
            : 'image';

        const cloudinaryResponse = await cloudinary.uploader.destroy(file.publicId, {
          type: "private",
          resource_type: resourceType
        });
        if (cloudinaryResponse.result !== "ok") {
          console.error(`Cloudinary deletion failed: for ${file.name} `, cloudinaryResponse);
          // return res.status(500).send(`Failed to delete from Cloudinary: ${cloudinaryResponse.result}`);
        }
      } catch (err) {
        console.error(`Could not delete from file system file ${file.name}: `, err);
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
    console.error("Folder deletion error: ", err)
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