const { Schema, model } = require("mongoose");

const applicationSchema = new Schema({
  job: { type: Schema.Types.ObjectId, ref: "Job", required: true },
  musician: { type: Schema.Types.ObjectId, ref: "User", required: true },
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'selected'], default: 'pending' },
  createdAt: { type: Date, default: Date.now },
  // Application form data
  name: { type: String },
  age: { type: String },
  location: { type: String },
  contact: { type: String },
  portfolio: { type: String },
  mainRole: { type: String },
  instruments: { type: String },
  musicalStyle: { type: String },
  performingExperience: { type: String },
  liveGigsExperience: { type: String },
  performingDuration: { type: String },
  lastEvents: { type: String },
  audienceSize: { type: String },
  performanceLink: { type: String }
});

module.exports = model("Application", applicationSchema);

