import express, { NextFunction, Response } from "express";
import cors from "cors";
import { PrismaClient, User } from "@prisma/client";
import { compare, hash } from "bcrypt";
import jwt from "jsonwebtoken";
import { authenticate, ExpressRequest } from "./middlewares/auth";

const app = express();
const prisma = new PrismaClient();

app.use(express.json());
app.use(cors());

const generateJwt = (user: User): string => {
  return jwt.sign({ email: user.email }, "JWT_SECRET");
};

app.post("/users", async (req, res) => {
  try {
    const data = req.body;
    data.password = await hash(req.body.password, 10);

    const user = await prisma.user.create({
      data,
    });

    const { password: _password, ...userWithouPassword } = user;
    res.status(201).json({ ...userWithouPassword, token: generateJwt(user) });
  } catch (err) {
    console.error(err);
    res.status(404).json({
      error: "E-mail or username not are unique!",
    });
  }
});

app.post("/users/login", async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: {
        email: req.body.email,
      },
    });

    if (!user) {
      console.error("User not found!");
      throw new Error("User not found!");
    }
    const isPasswordCorrect = await compare(req.body.password, user.password);

    if (!isPasswordCorrect) {
      throw new Error("Incorrect password!");
    }

    const { password: _password, ...userWithouPassword } = user;
    res.status(200).json({ ...userWithouPassword, token: generateJwt(user) });
  } catch (err) {
    console.error(err);
    res.status(404).json({ error: "E-mail or password are wrong!" });
  }
});

app.get(
  "/users",
  authenticate,
  // @ts-ignore
  async (req: ExpressRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        return res.sendStatus(401);
      }
      const { password: _password, ...userWithoutPassword } = req.user;
      res.json(userWithoutPassword);
    } catch (err) {
      next(err);
    }
  }
);

async function main() {
  app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
  });
}

main()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (e) => {
    console.error(e);
    await prisma.$disconnect();
    process.exit(1);
  });
