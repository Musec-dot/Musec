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
  status: { type: String, enum: ['open', 'closed'], default: 'open' },
  selectedApplication: { type: Schema.Types.ObjectId, ref: "Application", default: null },
  selectedMusician: { type: Schema.Types.ObjectId, ref: "User", default: null },
  // Payment and tracking fields
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed'], default: 'pending' },
  paymentDate: { type: Date, default: null },
  jobStatus: { type: String, enum: ['selected', 'payment_pending', 'in_progress', 'completed', 'cancelled'], default: 'selected' },
  completedDate: { type: Date, default: null },
  connectedAt: { type: Date, default: null }
});

module.exports = model("Job", jobSchema);

