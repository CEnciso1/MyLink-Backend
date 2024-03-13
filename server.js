const express = require("express");
const cors = require("cors");
const axios = require("axios");
const passport = require("passport");
const passportConfig = require("./passportConfig");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
require("dotenv").config();
const mongoose = require("mongoose");
const crypto = require("crypto");
const User = require("./schemas/user");
const sessionSecret = crypto.randomBytes(32).toString("hex");
// const jwtSecret = crypto.randomBytes(32).toString("hex");
// module.exports.jwtSecret = jwtSecret;
require("dotenv").config();
const jwtSecret = process.env.REACT_APP_JWT_SECRET;

mongoose.connect(process.env.REACT_APP_MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

//set Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//cors allows client to make request to server
app.use(
  cors({
    origin: "https://mylink-frontend.onrender.com",
    credentials: true,
  })
);
app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(cookieParser(sessionSecret));
app.use(passport.initialize());
app.use(passport.session());
passportConfig(passport);

app.get("/instagram-auth", async (req, res) => {
  console.log(req);
  try {
    console.log(req.body);
    console.log(req.query);
  } catch (error) {
    console.log(error);
  }
});

app.post("/auth", async (req, res) => {
  const token = req.body.token;
  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      res.send(false);
    } else {
      res.send({ ...decoded, result: true });
    }
  });
});

app.post("/signin", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) throw err;
    if (!user)
      res.send({ message: "Email or password is incorrect", success: false });
    else {
      req.logIn(user, { session: false }, (err) => {
        if (err) throw err;
        //console.log(req.session, req.sessionID);
        console.log(user.id);
        const token = jwt.sign(user.toJSON(), jwtSecret);
        return res.send({
          message: "Succesfully Signed In",
          success: true,
          user: user,
          token: token,
        });
      });
    }
  })(req, res, next);
});

app.post("/signup", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) res.send({ message: "User Already Exist", success: false });
    else {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const newUser = new User({
        email: req.body.email,
        username: req.body.username,
        password: hashedPassword,
        links: [],
      });
      await newUser.save();
      res.send({ message: "User Created", success: true });
    }
  } catch (error) {
    console.log(error);
    res.send("An error has occurred");
  }
});
app.get("/signup", (req, res) => {
  console.log(req.body);
});

app.post("/logout", (req, res) => {
  console.log(req.session);
  console.log(req.isAuthenticated());
  req.logOut(function (err) {
    console.log("error", err);
  });
  console.log(req.isAuthenticated());
  res.send({ message: "Logout successful" });
});

app.post(
  "/add-link",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log(req.session, req.sessionID);
      const response = await User.findOneAndUpdate(
        { _id: req.body._id },
        { $set: { links: req.body.links } },
        { new: true }
      );
      console.log("response", response);
      res.send("Links was added");
    } catch (error) {
      console.log(error);
      res.send("An error has occurred");
    }
  }
);

app.put(
  "/delete-link",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log(req.session, req.sessionID);
      response = await User.updateOne(
        { _id: req.body._id },
        { $pull: { links: { $eq: req.body.link } } }
      );
      res.send("the link was deleted");
      console.log(response);
      console.log("The link was deleted");
    } catch (error) {
      console.log(error);
      res.send("An error has occurred");
    }
  }
);

app.put(
  "/edit-link",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log("test", req.body);
      const response = await User.findOneAndUpdate(
        { _id: req.body._id },
        { $set: { [`links.${req.body.index}.title`]: req.body.newTitle } },
        { new: true }
      );
      console.log(response);
      res.send("Update was made");
    } catch (error) {
      console.log(error);
      res.send("An error has occured");
    }
  }
);

app.get("/account-data/:username", async (req, res) => {
  try {
    const response = await User.findOne({ username: req.params.username });
    const displayData = { links: response.links };
    res.send(displayData);
  } catch (error) {
    console.log(error);
    res.send("An error has occured");
  }
});

app.get("/instagram-api", async (req, res) => {
  try {
    // const query = req._parsedOriginalUrl.query;
    console.log(req.query);
    response = await axios.get("https://api.instagram.com/oauth/authorize", {
      params: req.query,
    });
    console.log("https://www.instagram.com" + response.request.path);
    res.send("https://www.instagram.com" + response.request.path);
  } catch (error) {
    console.log(error);
    res.send("An error has occured");
  }
});

app.listen(5000, () => {
  console.log("listening on port 5000");
});
