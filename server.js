import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import admin from "firebase-admin";
import fs from "fs";
const serviceAccountKey = JSON.parse(
  fs.readFileSync(
    "./mernblogwebsite-9b9ff-firebase-adminsdk-fbsvc-538ee207c9.json",
    "utf8"
  )
);
import { getAuth } from "firebase-admin/auth";
import aws from "aws-sdk";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { nanoid } from "nanoid";
import User from "./Schema/User.js";

const server = express();
let PORT = 3000;

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

server.use(express.json());
server.use(cors());

mongoose
  .connect(process.env.MONGO_URI, { autoIndex: true })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

const s3 = new aws.S3({
  region: "ap-south-1",
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No access token" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Access token is invalid" });
    }
    req.user = user.id;
    next();
  });
};

const formatDatatoSend = (user) => {
  const access_token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let exists = await User.exists({ "personal_info.username": username });

  if (exists) {
    username += nanoid().substring(0, 3);
  }

  return username;
};

server.listen(PORT, () => {
  console.log(`listening on port -> ${PORT}`);
});
