
const mongoose = require('mongoose');
const PostSchema = new mongoose.Schema({
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  content: String,
  fileUrl: String,
  fileType: String, // 'image', 'video', 'audio', or null
  createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Post', PostSchema);
