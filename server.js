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

server.post("/signup", (req, res) => {
  let { fullname, email, password } = req.body;

  //validating the data from the frontend
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Fullname must be at least 3 letters long" });
  }

  if (!email.length) {
    return res.status(403).json({ error: "Enter email" });
  }

  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is invalid" });
  }

  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letters",
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_Password) => {
    let username = await generateUsername(email);

    let user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_Password,
        username,
      },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      })
      .catch((err) => {
        if (err.code === 11000) {
          return res.status(500).json({ error: "email already exists !" });
        }

        return res.status(500).json({ error: err.message });
      });
  });
});

server.post("/signin", (req, res) => {
  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }

      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res
              .status(403)
              .json({ error: "Error occured while login please try again" });
          }

          if (!result) {
            return res.status(403).json({ error: "Incorrect Password" });
          } else {
            return res.status(200).json(formatDatatoSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error: "Account was created using google. Try logging in with google",
        });
      }
    })
    .catch((err) => {
      console.log(err);
      return res.status(403).json({ error: err.message });
    });
});

server.post("/google-auth", async (req, res) => {
  const { access_token } = req.body;

  try {
    // Verify Firebase ID token
    const decodedUser = await getAuth().verifyIdToken(access_token);

    // Extract user details from verified token
    const { email, name, picture } = decodedUser;
    const largePicture = picture?.replace("s96-c", "s384-c") || null;

    // Find existing user by email
    let user = await User.findOne({ "personal_info.email": email })
      .select(
        "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
      )
      .exec();

    // If user exists
    if (user) {
      // If user didn't sign up with Google, reject login
      if (!user.google_auth) {
        return res.status(403).json({
          error:
            "This email was signed up without google. Please login with password to access the account",
        });
      }
    } else {
      // Create new user with google_auth true
      const username = await generateUsername(email);

      user = new User({
        personal_info: {
          fullname: name,
          email,
          username,
        },
        google_auth: true,
      });

      await user.save();
    }

    return res.status(200).json(formatDatatoSend(user));
  } catch (err) {
    console.error("Google auth error:", err);
    return res.status(500).json({
      error:
        "Failed to authenticate you with google. Try with some other google account",
    });
  }
});

server.listen(PORT, () => {
  console.log(`listening on port -> ${PORT}`);
});
