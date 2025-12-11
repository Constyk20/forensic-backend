import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import fs from "fs-extra";
import path from "path";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

dotenv.config(); // ✅ Load environment variables FIRST

// Fix ES module dirname issue
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log("📁 Current directory:", __dirname);
console.log("🔍 Checking for routes directory...");

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Create required directories
const createDirectories = async () => {
  const dirs = ["evidence", "samples", "logs"];

  for (const dir of dirs) {
    const dirPath = path.join(__dirname, dir);
    await fs.ensureDir(dirPath);
    console.log(`✓ Directory ensured: ${dir}/`);
  }
};

// Connect to MongoDB
const connectDB = async () => {
  try {
    console.log("🔍 Checking MongoDB URI...");
    console.log("MONGO_URI =", process.env.MONGO_URI ? "[OK]" : "[UNDEFINED]");

    if (!process.env.MONGO_URI) {
      throw new Error("❌ MONGO_URI is missing from Render environment variables.");
    }

    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✓ MongoDB connected: ${conn.connection.host}`);

  } catch (error) {
    console.error("✗ MongoDB connection error:", error.message);
    process.exit(1);
  }
};

// Initialize routes
const initializeRoutes = async () => {
  try {
    console.log("📂 Checking route files...");

    let deviceRoutes, evidenceRoutes, analysisRoutes;

    const routesExist = {
      device: fs.existsSync(path.join(__dirname, "routes", "deviceRoutes.js")),
      evidence: fs.existsSync(path.join(__dirname, "routes", "evidenceRoutes.js")),
      analysis: fs.existsSync(path.join(__dirname, "routes", "analysisRoutes.js"))
    };

    console.log("Route files found:", routesExist);

    // DEVICE ROUTES
    if (routesExist.device) {
      deviceRoutes = (await import("./routes/deviceRoutes.js")).default;
      console.log("✓ deviceRoutes loaded");
    } else {
      console.log("⚠️ deviceRoutes.js missing – using fallback");
      deviceRoutes = express.Router();
      deviceRoutes.get("/", (req, res) =>
        res.json({ message: "Device routes placeholder" })
      );
    }

    // EVIDENCE ROUTES
    if (routesExist.evidence) {
      evidenceRoutes = (await import("./routes/evidenceRoutes.js")).default;
      console.log("✓ evidenceRoutes loaded");
    } else {
      console.log("⚠️ evidenceRoutes.js missing – using fallback");
      evidenceRoutes = express.Router();
      evidenceRoutes.post("/acquire", (req, res) =>
        res.json({ error: "evidenceRoutes.js missing" })
      );
    }

    // ANALYSIS ROUTES
    if (routesExist.analysis) {
      analysisRoutes = (await import("./routes/analysisRoutes.js")).default;
      console.log("✓ analysisRoutes loaded");
    } else {
      console.log("⚠️ analysisRoutes.js missing – using fallback");
      analysisRoutes = express.Router();
      analysisRoutes.get("/", (req, res) =>
        res.json({ message: "Analysis routes placeholder" })
      );
    }

    app.use("/api/devices", deviceRoutes);
    app.use("/api/evidence", evidenceRoutes);
    app.use("/api/analysis", analysisRoutes);

    console.log("✅ All routes initialized successfully");

  } catch (error) {
    console.error("❌ Error initializing routes:", error);
  }
};

// Health Check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "operational",
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    timestamp: new Date().toISOString()
  });
});

// Root
app.get("/", (req, res) => {
  res.json({
    message: "IoT CCTV Forensic Analysis API",
    version: "1.0.0",
    routes: {
      health: "/api/health",
      docs: "/api/docs",
      devices: "/api/devices",
      evidence: "/api/evidence",
      analysis: "/api/analysis"
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(err.status || 500).json({
    error: err.message || "Internal server error"
  });
});

// Start Server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  console.log("🚀 Starting server initialization...");
  await createDirectories();
  await connectDB();
  await initializeRoutes();

  app.listen(PORT, () => {
    console.log(`\n✅ Server running on port ${PORT}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  });
};

// Graceful shutdown
process.on("SIGINT", async () => {
  console.log("\nShutting down...");
  await mongoose.connection.close();
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\nShutting down...");
  await mongoose.connection.close();
  process.exit(0);
});

startServer();

export default app;
