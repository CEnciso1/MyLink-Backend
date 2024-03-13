const User = require("./schemas/user"); //import in the User model
const bcrypt = require("bcrypt");
const localStrategy = require("passport-local");
const crypto = require("crypto");
// const jwtSecret = crypto.randomBytes(32).toString("hex");
// module.exports.jwtSecret = jwtSecret;
require("dotenv").config();
const jwtSecret = process.env.REACT_APP_JWT_SECRET;
console.log(jwtSecret);
const { Strategy, ExtractJwt } = require("passport-jwt");
const { Serializer } = require("v8");
const jwtOptions = {
  secretOrKey: jwtSecret,
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
};

module.exports = function (passport) {
  passport.use(
    new localStrategy(
      {
        usernameField: "email",
        passwordField: "password",
      },
      async function (email, password, done) {
        try {
          const user = await User.findOne({ email: email });
          if (!user) {
            console.log("no user");
            return done(null, false);
          }
          bcrypt.compare(password, user.password, (error, result) => {
            if (error) throw error;
            if (result === true) {
              return done(null, user);
            } else {
              return done(null, false);
            }
          });
        } catch (error) {
          console.log(error);
          return done(error);
        }
      }
    )
  );
  passport.use(
    new Strategy(jwtOptions, async function (jwtPayload, done) {
      try {
        const user = await User.findById(jwtPayload._id);
        if (!user) {
          console.log("no user");
          return done(null, false);
        }
        return done(null, user);
      } catch (error) {
        console.log(error);
      }
    })
  );

  passport.serializeUser((user, done) => {
    console.log("Serializer");
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      console.log("deserializer");
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      console.log(error);
    }
  });
};
