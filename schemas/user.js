const { mongoose } = require("mongoose");

const user = new mongoose.Schema({
  email: String,
  username: String,
  password: String,
  links: Array,
  apis: Object,
});

module.exports = mongoose.model("User", user);
