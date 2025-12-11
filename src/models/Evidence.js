import mongoose from "mongoose";

const EvidenceSchema = new mongoose.Schema({
  deviceId: String,
  type: String,       // video, pcap, log
  filename: String,
  filepath: String,
  sha256: String,
  size: Number,
  collected_at: { type: Date, default: Date.now }
});

export default mongoose.model("Evidence", EvidenceSchema);
