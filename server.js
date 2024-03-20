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
const querystring = require("querystring");
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
    origin: ["https://mylink-frontend.onrender.com", "http://localhost:3000"],
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

app.use(cookieParser(sessionSecret, { httpOnly: false }));
app.use(passport.initialize());
app.use(passport.session());
passportConfig(passport);

app.post(
  "/authorize-user",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const user = await User.findOne({ username: req.body.username });
    console.log(user._id, req.user._id);
    if (user._id == req.user._id) {
      res.send(true);
    } else {
      res.send(false);
    }
  }
);

app.post("/spotify-refresh", async (req, res) => {
  console.log("DATA", req.body);
  const requestBody = querystring.stringify(req.body);
  console.log("requestBody", requestBody);
  try {
    const response = await axios.post(
      "https://accounts.spotify.com/api/token",
      requestBody,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization:
            "Basic " +
            new Buffer.from(
              req.body.client_id + ":" + req.body.client_secret
            ).toString("base64"),
        },
      }
    );
    console.log(response);
    res.send(response.data);
  } catch (error) {
    console.log(error);
  }
  res.send(response.data);
});

app.post(
  "/spotify-auth",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log(req.body);

      const data = {
        code: req.body.code,
        redirect_uri: req.body.redirect_uri,
        grant_type: req.body.grant_type,
      };

      console.log("DATA", data);
      const requestBody = querystring.stringify(data);
      console.log("requestBody", requestBody);

      const response = await axios.post(
        "https://accounts.spotify.com/api/token",
        requestBody,
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            Authorization:
              "Basic " +
              new Buffer.from(
                req.body.client_id + ":" + req.body.client_secret
              ).toString("base64"),
          },
        }
      );

      console.log(req.user);
      const user = await User.findById(req.user._id);
      if (!user) {
        console.log("User not found");
        res.send("User not found");
      }
      if (!user.apis) {
        user.apis = {
          spotify: {
            token: response.data.access_token,
            client_id: req.body.client_id,
            refresh_token: response.data.refresh_token,
          },
        };
        console.log("TEST", user, user.apis);
      } else {
        user.apis.spotify = {
          token: response.data.access_token,
          client_id: req.body.client_id,
          refresh_token: response.data.refresh_token,
        };
      }
      user.markModified("apis");
      console.log("userDoc", user);
      await user.save();

      console.log(response.data);
      res.send("You've successfully connected your Spotify account!");
    } catch (error) {
      console.log(error);
      res.send("An error has occured");
    }
  }
);

app.get(
  "/instagram-api",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
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
  }
);

app.post(
  "/instagram-auth",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log(req.body);
      const requestBody = querystring.stringify(req.body);
      const response = await axios.post(
        "https://api.instagram.com/oauth/access_token",
        requestBody,
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        }
      );
      console.log("RESPONSE", response.data);
      //Get long lived token
      const longTokenResponse = await axios.get(
        "https://graph.instagram.com/access_token",
        {
          params: {
            grant_type: "ig_exchange_token",
            client_secret: req.body.client_secret,
            access_token: response.data.access_token,
          },
        }
      );
      console.log("RESPONSE 2", longTokenResponse.data);
      //Store token and used_id in mongodb
      console.log(req.user);
      const user = await User.findById(req.user._id);
      if (!user) {
        console.log("User not found");
        res.send("User not found");
      }
      if (!user.apis) {
        user.apis = {
          instagram: {
            token: longTokenResponse.data.access_token,
            user_id: response.data.user_id,
          },
        };
        console.log("TEST", user, user.apis);
      } else {
        user.apis.instagram = {
          token: longTokenResponse.data.access_token,
          user_id: response.data.user_id,
        };
      }

      user.markModified("apis");
      console.log("userDoc", user);
      await user.save();
      //Get media data
      console.log(
        typeof response.data.user_id,
        typeof longTokenResponse.data.access_token
      );
      const mediaDataResponse = await axios.get(
        `https://graph.instagram.com/${response.data.user_id}/media`,
        {
          params: {
            access_token: longTokenResponse.data.access_token,
            fields: "media_type, media_url",
          },
        }
      );
      console.log("RESPONSE 3", mediaDataResponse.data);
      res.send("You've succesfully connected your instagram account");
    } catch (error) {
      res.send("An error has occured, Instagram account not connected");
      console.log(error);
    }
  }
);

app.post("/auth", async (req, res) => {
  const token = req.body.token;
  jwt.verify(token, jwtSecret, async (err, decoded) => {
    if (err) {
      res.send(false);
    } else {
      response = await User.findById(decoded._id);
      res.send({ ...response, result: true });
    }
  });
});

app.post("/signin", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) throw err;
    if (!user)
      res.send({ message: "Email or password is incorrect", success: false });
    else {
      req.logIn(user, (err) => {
        if (err) throw err;
        res.cookie("sessionID", req.sessionID);
        console.log("sessionID", req.sessionID);
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
    const userByUsername = await User.findOne({ username: req.body.username });
    if (userByUsername)
      res.send({ message: "Username is taken", success: false });
    if (user)
      res.send({
        message: "User With That Email Already Exist",
        success: false,
      });
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

app.post(
  "/logout",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    console.log(req.session);
    console.log(req.isAuthenticated());
    req.logOut(function (err) {
      console.log("error", err);
    });
    console.log(req.isAuthenticated());
    res.send({ message: "Logout successful" });
  }
);

app.post(
  "/add-link",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    try {
      console.log("sessionid", req.sessionID);
      console.log("user", req.user);
      console.log("cookies", req.cookies);
      const response = await User.findOneAndUpdate(
        { _id: req.body._id },
        { $set: { links: req.body.links } },
        { new: true }
      );
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
      console.log("SessionId", req.sessionID);
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

app.put("/edit-link", passport.authenticate("jwt"), async (req, res) => {
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
});

app.get("/account-data/:username", async (req, res) => {
  try {
    const response = await User.findOne({ username: req.params.username });
    const displayData = response.apis
      ? { links: response.links, apis: response.apis }
      : { links: response.links };
    res.send(displayData);
  } catch (error) {
    console.log(error);
    res.send("An error has occured");
  }
});

app.listen(5000, () => {
  console.log("listening on port 5000");
});
