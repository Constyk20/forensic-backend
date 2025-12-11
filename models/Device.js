import mongoose from "mongoose";

// Evidence Model - Enhanced
const evidenceSchema = new mongoose.Schema({
  // Basic Information
  deviceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Device",
    required: true
  },
  type: {
    type: String,
    enum: ["video", "pcap", "log", "firmware", "config", "image", "audio"],
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  filepath: {
    type: String,
    required: true
  },
  
  // Case Information
  caseNumber: {
    type: String,
    required: true,
    index: true
  },
  investigator: {
    type: String,
    required: true
  },
  notes: String,
  
  // Cryptographic Hashes for Integrity
  md5: String,
  sha1: String,
  sha256: {
    type: String,
    required: true,
    index: true
  },
  sha512: String,
  
  // File Properties
  size: {
    type: Number,
    required: true
  },
  acquisitionDate: {
    type: Date,
    default: Date.now,
    required: true
  },
  lastModified: Date,
  
  // Metadata
  metadata: {
    acquisitionTime: String,
    fileExtension: String,
    duration: Number,
    codec: String,
    resolution: String,
    bitrate: Number,
    fps: Number,
    lineCount: Number,
    encoding: String,
    pcapInfo: String,
    extractionError: String
  },
  
  // Integrity and Protection
  integrity: {
    fileExists: Boolean,
    readable: Boolean,
    size: Number,
    lastModified: Date,
    permissions: String,
    isCorrupted: Boolean,
    corruptionReason: String
  },
  writeProtection: {
    writeProtected: Boolean,
    permissions: String
  },
  
  // Chain of Custody
  chainOfCustody: [{
    timestamp: {
      type: String,
      required: true
    },
    action: {
      type: String,
      enum: [
        "acquired", "analyzed", "transferred", "accessed", 
        "integrity_verified", "integrity_failed", "exported", "modified"
      ],
      required: true
    },
    user: String,
    ipAddress: String,
    notes: String
  }],
  
  // Analysis
  analyzed: {
    type: Boolean,
    default: false
  },
  lastAnalyzed: Date,
  analysisResults: mongoose.Schema.Types.Mixed,
  
  // Status
  status: {
    type: String,
    enum: ["acquired", "analyzing", "analyzed", "exported", "archived"],
    default: "acquired"
  },
  
  // Tags for organization
  tags: [String]
}, {
  timestamps: true
});

// Indexes for faster queries
evidenceSchema.index({ deviceId: 1, type: 1 });
evidenceSchema.index({ caseNumber: 1, acquisitionDate: -1 });
evidenceSchema.index({ investigator: 1 });

const Evidence = mongoose.model("Evidence", evidenceSchema);

// Device Model - Enhanced
const deviceSchema = new mongoose.Schema({
  // Basic Information
  name: {
    type: String,
    required: true
  },
  ip: {
    type: String,
    required: true,
    index: true
  },
  manufacturer: {
    type: String,
    default: "Unknown"
  },
  model: {
    type: String,
    default: "Unknown"
  },
  type: {
    type: String,
    enum: ["CCTV", "DVR", "NVR", "IoT", "Unknown"],
    default: "CCTV"
  },
  
  // Network Information
  macAddress: String,
  openPorts: [Number],
  services: [{
    port: Number,
    service: String,
    protocol: String,
    description: String
  }],
  
  // Firmware and Configuration
  firmware: {
    firmwareVersion: String,
    serialNumber: String,
    deviceModel: String,
    buildDate: Date
  },
  
  // Security Assessment
  vulnerabilities: [{
    severity: {
      type: String,
      enum: ["critical", "high", "medium", "low", "info"]
    },
    type: String,
    description: String,
    cve: String,
    remediation: String
  }],
  
  securityAudit: {
    timestamp: Date,
    deviceIp: String,
    findings: [{
      category: String,
      issue: String,
      recommendation: String,
      severity: String
    }],
    riskLevel: {
      type: String,
      enum: ["critical", "high", "medium", "low"]
    },
    score: Number
  },
  
  // Device Credentials (encrypted in production)
  credentials: {
    username: String,
    passwordHash: String, // Should be encrypted
    authMethod: {
      type: String,
      enum: ["basic", "digest", "certificate", "none"]
    }
  },
  
  // Location and Physical Info
  location: {
    building: String,
    floor: String,
    room: String,
    coordinates: {
      latitude: Number,
      longitude: Number
    }
  },
  
  // Operational Information
  status: {
    type: String,
    enum: ["active", "inactive", "offline", "simulated", "decommissioned"],
    default: "active"
  },
  discoveredAt: {
    type: Date,
    default: Date.now
  },
  lastSeen: Date,
  
  // Additional metadata
  notes: String,
  tags: [String]
}, {
  timestamps: true
});

// Indexes
deviceSchema.index({ ip: 1 });
deviceSchema.index({ manufacturer: 1, model: 1 });
deviceSchema.index({ status: 1 });

const Device = mongoose.model("Device", deviceSchema);

// Case Model - For organizing investigations
const caseSchema = new mongoose.Schema({
  caseNumber: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  description: String,
  
  // Case Details
  investigator: {
    type: String,
    required: true
  },
  department: String,
  priority: {
    type: String,
    enum: ["critical", "high", "medium", "low"],
    default: "medium"
  },
  
  // Status Tracking
  status: {
    type: String,
    enum: ["open", "in_progress", "under_review", "closed", "archived"],
    default: "open"
  },
  
  // Dates
  openedDate: {
    type: Date,
    default: Date.now
  },
  closedDate: Date,
  
  // Associated Data
  devices: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Device"
  }],
  evidence: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Evidence"
  }],
  
  // Case Notes and Activity Log
  notes: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    author: String,
    content: String,
    type: {
      type: String,
      enum: ["note", "finding", "action", "decision"]
    }
  }],
  
  // Final Report
  finalReport: {
    summary: String,
    findings: [String],
    recommendations: [String],
    conclusion: String,
    generatedAt: Date,
    generatedBy: String
  },
  
  // Tags and Categories
  tags: [String],
  category: String
}, {
  timestamps: true
});

const Case = mongoose.model("Case", caseSchema);

// Export all models
export { Evidence, Device, Case };
export default Evidence;