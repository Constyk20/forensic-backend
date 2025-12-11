import mongoose from "mongoose";

const connectDB = async () => {
  try {
    await mongoose.connect("mongodb+srv://achidubem1215_db_user:iNqGCq1awk8u8xsY@cluster0.synej4i.mongodb.net/?appName=Cluster0");
    console.log("MongoDB Connected");
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

export default connectDB;
