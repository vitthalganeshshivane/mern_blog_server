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
