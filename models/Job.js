const { Schema, model } = require("mongoose");

const jobSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  payment: { type: String, required: true },
  location: { type: String, required: true },
  genre: { type: String },
  instrument: { type: String },
  hirer: { type: Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['open', 'closed'], default: 'open' }
});

module.exports = model("Job", jobSchema);

