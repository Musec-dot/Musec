// models/Message.js
const mongoose = require("mongoose");


const messageSchema = new mongoose.Schema({
  from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  content: String,
  timestamp: { type: Date, default: Date.now },
  seen: { type: Boolean, default: false }  // <-- ADD THIS
});


module.exports = mongoose.model("Message", messageSchema);
