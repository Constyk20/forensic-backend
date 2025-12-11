import fs from "fs-extra";
import crypto from "crypto";
import path from "path";
import Evidence from "../models/Evidence.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Chain of custody tracking
const createChainOfCustody = (evidenceId, action, user) => ({
  evidenceId,
  timestamp: new Date().toISOString(),
  action,
  user: user || "system",
  ipAddress: "logged_ip_here"
});

// Calculate multiple hashes for integrity verification
const calculateHashes = (buffer) => ({
  md5: crypto.createHash("md5").update(buffer).digest("hex"),
  sha1: crypto.createHash("sha1").update(buffer).digest("hex"),
  sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
  sha512: crypto.createHash("sha512").update(buffer).digest("hex")
});

// Extract metadata from different file types
const extractMetadata = async (filepath, type) => {
  const metadata = {
    acquisitionTime: new Date().toISOString(),
    fileExtension: path.extname(filepath)
  };

  try {
    if (type === "video") {
      // Use ffprobe to extract video metadata
      const { stdout } = await execAsync(
        `ffprobe -v quiet -print_format json -show_format -show_streams "${filepath}"`
      );
      const videoInfo = JSON.parse(stdout);
      metadata.duration = videoInfo.format.duration;
      metadata.codec = videoInfo.streams[0]?.codec_name;
      metadata.resolution = `${videoInfo.streams[0]?.width}x${videoInfo.streams[0]?.height}`;
      metadata.bitrate = videoInfo.format.bit_rate;
      metadata.fps = eval(videoInfo.streams[0]?.r_frame_rate); // frames per second
    } else if (type === "pcap") {
      // Basic pcap analysis
      const { stdout } = await execAsync(`capinfos -M "${filepath}"`);
      metadata.pcapInfo = stdout.trim();
    } else if (type === "log") {
      const content = await fs.readFile(filepath, "utf-8");
      metadata.lineCount = content.split("\n").length;
      metadata.encoding = "utf-8";
    }
  } catch (err) {
    metadata.extractionError = err.message;
  }

  return metadata;
};

// Verify file integrity and detect tampering
const verifyIntegrity = async (filepath) => {
  const stats = await fs.stat(filepath);
  const buffer = await fs.readFile(filepath);
  
  // Check for common signs of corruption
  const integrity = {
    fileExists: true,
    readable: true,
    size: stats.size,
    lastModified: stats.mtime,
    permissions: stats.mode.toString(8),
    isCorrupted: false
  };

  // Basic corruption check (file size = 0 or unreadable)
  if (stats.size === 0) {
    integrity.isCorrupted = true;
    integrity.corruptionReason = "Zero byte file";
  }

  return integrity;
};

// Create forensic write blocker simulation
const createWriteProtection = async (filepath) => {
  // Make file read-only
  await fs.chmod(filepath, 0o444);
  return { writeProtected: true, permissions: "r--r--r--" };
};

export const acquireEvidence = async (req, res) => {
  try {
    const { deviceId, type, caseNumber, investigator, notes } = req.body;

    // Validation
    if (!deviceId || !type) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    // Define sample files
    const sampleFiles = {
      video: "samples/sample.mp4",
      pcap: "samples/sample.pcap",
      log: "samples/device_logs.log",
      firmware: "samples/firmware.bin",
      config: "samples/device_config.json"
    };

    const sampleFile = sampleFiles[type];
    if (!sampleFile) {
      return res.status(400).json({ 
        error: "Invalid type",
        validTypes: Object.keys(sampleFiles)
      });
    }

    // Check if sample exists
    if (!await fs.pathExists(sampleFile)) {
      return res.status(404).json({ 
        error: `Sample file not found: ${sampleFile}` 
      });
    }

    // Create evidence directory if not exists
    await fs.ensureDir("evidence");

    // Generate forensically sound filename
    const timestamp = Date.now();
    const sanitizedDevice = deviceId.replace(/[^a-zA-Z0-9]/g, "_");
    const outFile = `evidence/${type}_${sanitizedDevice}_${timestamp}${path.extname(sampleFile)}`;

    // Acquire evidence (copy with verification)
    await fs.copy(sampleFile, outFile, { preserveTimestamps: true });

    // Read file for analysis
    const buffer = await fs.readFile(outFile);
    
    // Calculate cryptographic hashes
    const hashes = calculateHashes(buffer);
    
    // Get file statistics
    const stat = await fs.stat(outFile);
    
    // Extract metadata
    const metadata = await extractMetadata(outFile, type);
    
    // Verify integrity
    const integrity = await verifyIntegrity(outFile);
    
    // Apply write protection
    const writeProtection = await createWriteProtection(outFile);

    // Create evidence record
    const evidenceData = {
      deviceId,
      type,
      filename: path.basename(outFile),
      filepath: outFile,
      caseNumber: caseNumber || `CASE-${timestamp}`,
      investigator: investigator || "Unknown",
      notes: notes || "",
      
      // Hashes for integrity
      md5: hashes.md5,
      sha1: hashes.sha1,
      sha256: hashes.sha256,
      sha512: hashes.sha512,
      
      // File properties
      size: stat.size,
      acquisitionDate: new Date(),
      lastModified: stat.mtime,
      
      // Metadata
      metadata,
      
      // Integrity verification
      integrity,
      writeProtection,
      
      // Chain of custody
      chainOfCustody: [
        createChainOfCustody(null, "acquired", investigator)
      ],
      
      // Status
      status: "acquired",
      analyzed: false
    };

    const saved = await Evidence.create(evidenceData);

    res.json({ 
      success: true, 
      evidence: saved,
      message: "Evidence acquired successfully with forensic integrity",
      hashes: hashes,
      writeProtected: true
    });

  } catch (error) {
    console.error("Evidence acquisition error:", error);
    res.status(500).json({ 
      error: "Failed to acquire evidence", 
      details: error.message 
    });
  }
};

// Export evidence with complete documentation
export const exportEvidence = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    
    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }

    // Create forensic report
    const report = {
      caseNumber: evidence.caseNumber,
      evidenceId: evidence._id,
      acquisitionDate: evidence.acquisitionDate,
      investigator: evidence.investigator,
      deviceId: evidence.deviceId,
      type: evidence.type,
      filename: evidence.filename,
      hashes: {
        md5: evidence.md5,
        sha1: evidence.sha1,
        sha256: evidence.sha256,
        sha512: evidence.sha512
      },
      size: evidence.size,
      metadata: evidence.metadata,
      chainOfCustody: evidence.chainOfCustody,
      integrity: evidence.integrity,
      analysisResults: evidence.analysisResults || "Not yet analyzed"
    };

    res.json({ success: true, report });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Verify evidence integrity at any time
export const verifyEvidenceIntegrity = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    
    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }

    // Recalculate hash
    const buffer = await fs.readFile(evidence.filepath);
    const currentHash = crypto.createHash("sha256").update(buffer).digest("hex");
    
    const isValid = currentHash === evidence.sha256;
    
    // Update chain of custody
    await Evidence.findByIdAndUpdate(evidenceId, {
      $push: {
        chainOfCustody: createChainOfCustody(
          evidenceId, 
          isValid ? "integrity_verified" : "integrity_failed",
          req.body.investigator
        )
      }
    });

    res.json({
      success: true,
      isValid,
      originalHash: evidence.sha256,
      currentHash,
      message: isValid ? "Evidence integrity verified" : "WARNING: Evidence may be tampered!"
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// List all evidence
export const listEvidence = async (req, res) => {
  try {
    const { caseNumber, type, analyzed, deviceId, status, investigator, limit } = req.query;
    
    const query = {};
    if (caseNumber) query.caseNumber = caseNumber;
    if (type) query.type = type;
    if (analyzed !== undefined) query.analyzed = analyzed === "true";
    if (deviceId) query.deviceId = deviceId;
    if (status) query.status = status;
    if (investigator) query.investigator = new RegExp(investigator, "i");
    
    let evidenceQuery = Evidence.find(query)
      .sort({ acquisitionDate: -1 })
      .select('filename type sha256 size acquisitionDate analyzed caseNumber status investigator');
    
    if (limit) {
      evidenceQuery = evidenceQuery.limit(parseInt(limit));
    }
    
    const evidence = await evidenceQuery.exec();
    
    res.json({
      success: true,
      count: evidence.length,
      evidence
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get evidence by ID
export const getEvidenceById = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    
    const evidence = await Evidence.findById(evidenceId)
      .populate('deviceId', 'name ip manufacturer model');
    
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }
    
    res.json({
      success: true,
      evidence
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Update evidence metadata
export const updateEvidence = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const updates = req.body;
    
    // Fields that cannot be updated
    const protectedFields = ['_id', 'filepath', 'sha256', 'md5', 'sha1', 'sha512', 'size', 'acquisitionDate'];
    protectedFields.forEach(field => delete updates[field]);
    
    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }
    
    // Add to chain of custody
    if (!evidence.chainOfCustody) {
      evidence.chainOfCustody = [];
    }
    evidence.chainOfCustody.push(
      createChainOfCustody(evidenceId, "modified", updates.investigator || "system")
    );
    
    Object.assign(evidence, updates);
    await evidence.save();
    
    res.json({
      success: true,
      evidence,
      message: "Evidence updated successfully"
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Delete evidence
export const deleteEvidence = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const { permanent } = req.query;
    
    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }
    
    // Check if evidence is on legal hold
    if (evidence.legalHold) {
      return res.status(403).json({ 
        error: "Evidence is on legal hold and cannot be deleted" 
      });
    }
    
    if (permanent === "true") {
      // Delete file from disk
      try {
        await fs.remove(evidence.filepath);
        // Delete frames if they exist
        if (evidence.analysisResults?.videoAnalysis?.metadata?.framesPath) {
          await fs.remove(evidence.analysisResults.videoAnalysis.metadata.framesPath);
        }
      } catch (err) {
        console.error("Error deleting files:", err);
      }
      
      // Delete from database
      await Evidence.findByIdAndDelete(evidenceId);
      
      res.json({
        success: true,
        message: "Evidence permanently deleted",
        deletedEvidence: {
          id: evidence._id,
          filename: evidence.filename,
          type: evidence.type
        }
      });
    } else {
      // Soft delete - mark as archived
      evidence.status = "archived";
      evidence.chainOfCustody.push(
        createChainOfCustody(evidenceId, "archived", req.body.investigator || "system")
      );
      await evidence.save();
      
      res.json({
        success: true,
        message: "Evidence archived (soft delete)",
        evidence
      });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get evidence by case number
export const getEvidenceByCase = async (req, res) => {
  try {
    const { caseNumber } = req.params;
    
    const evidence = await Evidence.find({ caseNumber })
      .sort({ acquisitionDate: -1 })
      .populate('deviceId', 'name ip manufacturer model');
    
    const summary = {
      totalEvidence: evidence.length,
      byType: {},
      analyzed: 0,
      totalSize: 0
    };
    
    evidence.forEach(e => {
      summary.byType[e.type] = (summary.byType[e.type] || 0) + 1;
      if (e.analyzed) summary.analyzed++;
      summary.totalSize += e.size;
    });
    
    res.json({
      success: true,
      caseNumber,
      summary,
      evidence
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Bulk verify integrity
export const bulkVerifyIntegrity = async (req, res) => {
  try {
    const { evidenceIds, investigator } = req.body;
    
    if (!evidenceIds || !Array.isArray(evidenceIds)) {
      return res.status(400).json({ error: "evidenceIds array is required" });
    }
    
    const results = [];
    
    for (const evidenceId of evidenceIds) {
      try {
        const evidence = await Evidence.findById(evidenceId);
        if (!evidence) {
          results.push({
            evidenceId,
            success: false,
            error: "Evidence not found"
          });
          continue;
        }
        
        const buffer = await fs.readFile(evidence.filepath);
        const currentHash = crypto.createHash("sha256").update(buffer).digest("hex");
        const isValid = currentHash === evidence.sha256;
        
        // Update chain of custody
        await Evidence.findByIdAndUpdate(evidenceId, {
          $push: {
            chainOfCustody: createChainOfCustody(
              evidenceId,
              isValid ? "integrity_verified" : "integrity_failed",
              investigator
            )
          }
        });
        
        results.push({
          evidenceId,
          filename: evidence.filename,
          success: true,
          isValid,
          message: isValid ? "Integrity verified" : "Integrity check failed"
        });
      } catch (error) {
        results.push({
          evidenceId,
          success: false,
          error: error.message
        });
      }
    }
    
    const summary = {
      total: results.length,
      verified: results.filter(r => r.success && r.isValid).length,
      failed: results.filter(r => r.success && !r.isValid).length,
      errors: results.filter(r => !r.success).length
    };
    
    res.json({
      success: true,
      summary,
      results
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};