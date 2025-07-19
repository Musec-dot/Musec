const mongoose = require('mongoose');

const liveStreamSchema = new mongoose.Schema({
  streamId:  { type: String, required: true, unique: true },
  streamer:  { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  isLive:    { type: Boolean, default: true },
  startedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('LiveStream', liveStreamSchema);