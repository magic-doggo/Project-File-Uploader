// require("dotenv").config();
// const { PrismaPg } = require("@prisma/adapter-pg");
// const { PrismaClient } = require("../generated/prisma/client.js");
// const connectionString = `${process.env.DATABASE_URL}`;

// // const pool = new Pool({ connectionString });
// const adapter = new PrismaPg({connectionString});

// const prisma = new PrismaClient({ adapter });

// module.exports = { prisma };
require('dotenv').config();
const { PrismaPg } = require('@prisma/adapter-pg');
const { PrismaClient } = require('../generated/prisma/client.js');

const connectionString = `${process.env.DATABASE_URL}`;
const adapter = new PrismaPg({ connectionString });
const prisma = new PrismaClient({ adapter });

module.exports = { prisma };

// https://www.prisma.io/docs/orm/prisma-client/setup-and-configuration/introduction
//https://www.prisma.io/docs/orm/prisma-client/setup-and-configuration/databases-connections#long-running-processes
//keep prismaClient instantiation in prisma.js and import it to app or routes to keep same prisma instance running everywhere