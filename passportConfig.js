const User = require("./schemas/user"); //import in the User model
const bcrypt = require("bcrypt");
const localStrategy = require("passport-local");

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

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      console.log("deserialize", user);
      done(null, user);
    } catch (error) {
      console.log(error);
    }
  });
};
