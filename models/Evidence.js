import mongoose from "mongoose";

const EvidenceSchema = new mongoose.Schema({
  // Core Identification
  caseNumber: {
    type: String,
    required: true,
    index: true,
    trim: true
  },
  evidenceNumber: {
    type: String,
    unique: true,
    required: true,
    index: true
  },
  deviceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Device',
    required: true,
    index: true
  },
  
  // Evidence Details
  type: {
    type: String,
    enum: ['video', 'pcap', 'log', 'image', 'memory', 'disk', 'network', 'other'],
    required: true,
    index: true
  },
  subtype: {
    type: String,
    enum: [
      'surveillance_video', 'traffic_camera', 'dash_cam',
      'network_traffic', 'wireless_capture', 'bluetooth',
      'system_logs', 'application_logs', 'security_logs',
      'screenshot', 'photograph', 'screenshot_sequence',
      'ram_dump', 'process_memory',
      'disk_image', 'file_system',
      'http_traffic', 'dns_records', 'email_traffic',
      'custom'
    ],
    index: true
  },
  
  // File Information
  filename: {
    type: String,
    required: true,
    trim: true
  },
  originalFilename: {
    type: String,
    trim: true
  },
  filepath: {
    type: String,
    required: true
  },
  backupPath: {
    type: String
  },
  size: {
    type: Number,
    required: true,
    min: 0
  },
  format: {
    type: String,
    enum: ['mp4', 'avi', 'mov', 'pcap', 'pcapng', 'log', 'txt', 'json', 'xml', 'jpg', 'png', 'raw', 'bin', 'other'],
    index: true
  },
  
  // Integrity & Verification
  sha256: {
    type: String,
    required: true,
    match: /^[a-fA-F0-9]{64}$/,
    index: true
  },
  md5: {
    type: String,
    match: /^[a-fA-F0-9]{32}$/
  },
  crc32: {
    type: String,
    match: /^[a-fA-F0-9]{8}$/
  },
  
  // Metadata
  metadata: {
    resolution: String,
    duration: Number,
    frameRate: Number,
    bitrate: Number,
    codec: String,
    packets: Number,
    startTime: Date,
    endTime: Date,
    sourceIP: String,
    destinationIP: String,
    protocol: String,
    port: Number,
    custom: mongoose.Schema.Types.Mixed
  },
  
  // Collection Info
  collectedBy: {
    type: String,
    required: true,
    trim: true
  },
  collectionMethod: {
    type: String,
    enum: ['network_sniffing', 'log_extraction', 'video_capture', 'memory_acquisition', 'disk_imaging', 'manual', 'automated'],
    required: true
  },
  collectionLocation: String,
  collectionCoordinates: {
    latitude: Number,
    longitude: Number
  },
  
  // Timestamps
  collected_at: {
    type: Date,
    default: Date.now,
    required: true,
    index: true
  },
  modified_at: {
    type: Date,
    default: Date.now
  },
  evidenceDate: {
    type: Date,
    index: true
  },
  
  // Chain of Custody
  chainOfCustody: [{
    custodian: String,
    action: {
      type: String,
      enum: ['collected', 'transferred', 'analyzed', 'stored', 'archived', 'returned', 'destroyed']
    },
    timestamp: {
      type: Date,
      default: Date.now
    },
    location: String,
    notes: String,
    signature: String
  }],
  
  // Analysis
  status: {
    type: String,
    enum: ['collected', 'pending_analysis', 'analyzing', 'analyzed', 'verified', 'quarantined', 'archived', 'destroyed'],
    default: 'collected',
    index: true
  },
  analysisResults: {
    analyzedBy: String,
    analyzedAt: Date,
    findings: [{
      type: {
        type: String,
        enum: ['anomaly', 'threat', 'incident', 'evidence', 'metadata']
      },
      description: String,
      severity: {
        type: String,
        enum: ['low', 'medium', 'high', 'critical']
      },
      confidence: Number,
      timestamp: Date,
      data: mongoose.Schema.Types.Mixed
    }],
    reportPath: String,
    summary: String
  },
  
  // Tags
  tags: [{
    type: String,
    trim: true,
    lowercase: true,
    index: true
  }],
  classification: {
    type: String,
    enum: ['public', 'internal', 'confidential', 'secret', 'top_secret'],
    default: 'internal'
  },
  
  // Storage
  storage: {
    location: String,
    encrypted: {
      type: Boolean,
      default: false
    },
    encryptionKeyId: String,
    compression: {
      type: Boolean,
      default: false
    },
    compressionRatio: Number
  },
  
  // Legal
  legal: {
    warrantNumber: String,
    warrantExpiry: Date,
    authorizedBy: String,
    retentionPolicy: String,
    retentionExpiry: Date
  },
  
  // Notes
  description: String,
  notes: [{
    author: String,
    content: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    type: {
      type: String,
      enum: ['general', 'technical', 'legal', 'chain_of_custody']
    }
  }],
  
  // Relationships
  relatedEvidence: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Evidence'
  }],
  
  // Audit
  createdBy: {
    type: String,
    required: true
  },
  lastModifiedBy: String,
  version: {
    type: Number,
    default: 1
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Export Fix
export default mongoose.models.Evidence ||
  mongoose.model("Evidence", EvidenceSchema);
