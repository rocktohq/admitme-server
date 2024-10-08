const express = require("express");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();
const port = process.env.PORT || 5000;
const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://admitmehq.web.app",
      "https://admitmehq.firebaseapp.com",
    ],
    credentials: true,
  })
);
// * Default Route
app.get("/", (req, res) => {
  res.send("admitMe Server is running...");
});

// MongoDB URI
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@usermanagement.n4peacj.mongodb.net/?retryWrites=true&w=majority&appName=UserManagement`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // * Collections
    const userCollection = client.db("admitmes").collection("users");
    const universityCollection = client
      .db("admitme")
      .collection("universities");
    const courseCollection = client.db("admitme").collection("courses");
    const applicationCollection = client
      .db("admitme")
      .collection("applications");

    // * JWT Related APIs
    // JWT API
    app.post("/api/jwt", (req, res) => {
      try {
        const user = req.body;
        const token = jwt.sign(user, process.env.JWT_SECRET, {
          expiresIn: "24h",
        });

        res
          .cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            maxAge: 1000 * 60 * 60 * 24,
          })
          .send({ Action: "Token form Local", success: true, token });
      } catch (err) {
        res.send(err);
      }
    });

    // LogOut API
    app.post("/api/logout", (req, res) => {
      try {
        res
          .clearCookie("token", { maxAge: 0 })
          .send({ Action: "Logout user", success: true });
      } catch (err) {
        res.send(err);
      }
    });

    // Token Verification
    const verifyToken = (req, res, next) => {
      const token = req?.cookies?.token;
      if (!token)
        return res.status(401).send({ message: "Unauthorized access" });
      jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
        if (error)
          return res.status(401).send({ message: "Unauthorized access" });
        req.user = decoded;
        next();
      });
    };

    // Admin Verification
    const verifyAdmin = async (req, res, next) => {
      const email = req?.user?.email;
      const query = { email: email };
      const user = await userCollection.findOne(query);
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "Forbidden access" });
      }
      next();
    };

    // * Get APIs
    // * Get All Users [ADMIN ONLY]
    app.get("/api/admin/users", verifyToken, verifyAdmin, async (req, res) => {
      try {
        const page = parseInt(req?.query?.page);
        const size = parseInt(req.query.size);

        const result = await userCollection
          .find()
          .skip(page * size)
          .limit(size)
          .toArray();
        res.send({ users: result, userCount });
      } catch (err) {
        res.send(err);
      }
    });

    // * Get Single User [ADMIN]
    app.get("/api/users/:email", async (req, res) => {
      try {
        const query = { email: req.params.email };
        const result = await userCollection.findOne(query);
        res.send(result);
      } catch (err) {
        res.send(err);
      }
    });

    // Check Admin [LOGGEDIN USER]
    app.get("/api/users/admin/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;

        const query = { email: email };
        const user = await userCollection.findOne(query);
        let admin = false;
        if (user) {
          admin = user?.role === "admin";
        }
        res.send({ admin });
      } catch (err) {
        res.send(err);
      }
    });

    // await client.db("admin").command({ ping: 1 });
    // console.log("You successfully connected to MongoDB!");
  } finally {
  }
}
run().catch(console.dir);

// Listener
app.listen(port, () => {
  console.log("admitMe Server is running on port " + port);
});
