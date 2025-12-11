import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import fs from "fs-extra";
import path from "path";
import { fileURLToPath } from "url";

// Import routes
import deviceRoutes from "./routes/deviceRoutes.js";
import evidenceRoutes from "./routes/evidenceRoutes.js";
import analysisRoutes from "./routes/analysisRoutes.js";

// Get current directory in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// Request logging middleware
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

// Database connection
const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGODB_URI || "mongodb://localhost:27017/forensic_iot";
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true
    });
    
    console.log("✓ MongoDB connected successfully");
  } catch (error) {
    console.error("✗ MongoDB connection error:", error);
    process.exit(1);
  }
};

// Routes
app.use("/api/devices", deviceRoutes);
app.use("/api/evidence", evidenceRoutes);
app.use("/api/analysis", analysisRoutes);

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "operational",
    timestamp: new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    version: "1.0.0"
  });
});

// API documentation endpoint
app.get("/api/docs", (req, res) => {
  res.json({
    title: "IoT CCTV Forensic Analysis API",
    version: "1.0.0",
    description: "Comprehensive forensic tools for analyzing IoT devices, specifically CCTV systems",
    endpoints: {
      devices: {
        "POST /api/devices/discover": "Discover CCTV devices on network",
        "GET /api/devices": "List all devices with filters",
        "GET /api/devices/security-summary": "Get security overview",
        "GET /api/devices/:deviceId": "Get device details",
        "PUT /api/devices/:deviceId": "Update device",
        "DELETE /api/devices/:deviceId": "Delete device"
      },
      evidence: {
        "POST /api/evidence/acquire": "Acquire evidence from device",
        "GET /api/evidence/export/:evidenceId": "Export evidence with documentation",
        "GET /api/evidence/verify/:evidenceId": "Verify evidence integrity"
      },
      analysis: {
        "POST /api/analysis/analyze": "Analyze evidence (video/pcap/logs)",
        "GET /api/analysis/report/:evidenceId": "Generate forensic report",
        "GET /api/analysis/evidence": "List all evidence",
        "GET /api/analysis/evidence/:evidenceId": "Get evidence details"
      },
      system: {
        "GET /api/health": "System health check",
        "GET /api/docs": "API documentation"
      }
    },
    documentation: "See README.md for detailed usage examples"
  });
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({
    message: "IoT CCTV Forensic Analysis API",
    version: "1.0.0",
    endpoints: {
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
    method: req.method,
    message: "Please check API documentation at /api/docs"
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Error:", err);
  
  res.status(err.status || 500).json({
    error: err.message || "Internal server error",
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
    ...(process.env.NODE_ENV === "development" && { stack: err.stack })
  });
});

// Initialize server
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    // Create required directories
    await createDirectories();
    
    // Connect to database
    await connectDB();
    
    // Start server
    app.listen(PORT, () => {
      console.log("\n╔════════════════════════════════════════════════╗");
      console.log("║   IoT CCTV Forensic Analysis System           ║");
      console.log("╚════════════════════════════════════════════════╝");
      console.log(`\n✓ Server running on port ${PORT}`);
      console.log(`✓ Environment: ${process.env.NODE_ENV || "development"}`);
      console.log(`\n📡 API Endpoints:`);
      console.log(`   Health:  http://localhost:${PORT}/api/health`);
      console.log(`   Docs:    http://localhost:${PORT}/api/docs`);
      console.log(`   Devices: http://localhost:${PORT}/api/devices`);
      console.log(`   Evidence: http://localhost:${PORT}/api/evidence`);
      console.log(`   Analysis: http://localhost:${PORT}/api/analysis`);
      console.log("\n════════════════════════════════════════════════\n");
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on("SIGINT", async () => {
  console.log("\n\nShutting down gracefully...");
  await mongoose.connection.close();
  console.log("✓ Database connection closed");
  process.exit(0);
});

process.on("SIGTERM", async () => {
  console.log("\n\nShutting down gracefully...");
  await mongoose.connection.close();
  console.log("✓ Database connection closed");
  process.exit(0);
});

// Start the server
startServer();

export default app;