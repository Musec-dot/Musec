const { Schema, model } = require("mongoose");

const paymentSchema = new Schema({
  job: { type: Schema.Types.ObjectId, ref: "Job", required: true },
  hirer: { type: Schema.Types.ObjectId, ref: "User", required: true },
  musician: { type: Schema.Types.ObjectId, ref: "User", required: true },
  amount: { type: String, required: true },
  paymentMethod: { type: String, enum: ['card', 'bank_transfer', 'paypal', 'other'], default: 'other' },
  status: { type: String, enum: ['pending', 'processing', 'completed', 'failed', 'refunded'], default: 'pending' },
  transactionId: { type: String, default: null },
  paymentDate: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
  notes: { type: String, default: null }
});

module.exports = model("Payment", paymentSchema);

