const { Router } = require("express");
const fileRouter = Router();
const { prisma } = require("../lib/prisma.js")

fileRouter.get("/:fileId", async (req, res) => {
  try {
    const file = await prisma.file.findUnique({
      where: {
        id: parseInt(req.params.fileId),
        userId: req.user.id
      }
    });
    if (!file) return res.status(404).send('File not Found');
    res.render("file", { file: file })
  } catch (err) {
    console.err(err);
    res.status(500).send("error getting file details")
  }
})

module.exports = fileRouter;
// PrismaClient instantiation moved to lib/prisma.js, rest stays in app.js.
// https://www.prisma.io/docs/orm/prisma-client/setup-and-configuration/introduction
// https://www.prisma.io/docs/orm/prisma-client/setup-and-configuration/databases-connections#long-running-processes