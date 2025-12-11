import express from "express";
import cors from "cors";
import connectDB from "./src/config/db.js";

import deviceRoutes from "./src/routes/deviceRoutes.js";
import evidenceRoutes from "./src/routes/evidenceRoutes.js";
import analysisRoutes from "./src/routes/analysisRoutes.js";

const app = express();
app.use(cors());
app.use(express.json());

connectDB();

app.use("/api/devices", deviceRoutes);
app.use("/api/evidence", evidenceRoutes);
app.use("/api/analysis", analysisRoutes);

app.listen(3000, () => console.log("Server running on port 3000"));
