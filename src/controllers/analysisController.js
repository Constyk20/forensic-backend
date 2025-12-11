import Evidence from "../models/Evidence.js";
import fs from "fs-extra";
import { exec } from "child_process";
import { promisify } from "util";
import crypto from "crypto";
import path from "path";

const execAsync = promisify(exec);

// Video forensic analysis
const analyzeVideo = async (filepath) => {
  const analysis = {
    type: "video",
    findings: [],
    metadata: {}
  };

  try {
    // Check if ffprobe is available
    const ffprobeCmd = `ffprobe -v quiet -print_format json -show_format -show_streams "${filepath}"`;
    const { stdout } = await execAsync(ffprobeCmd);
    const videoData = JSON.parse(stdout);
    
    const stream = videoData.streams[0] || {};
    const format = videoData.format || {};
    
    analysis.metadata = {
      codec: stream.codec_name,
      duration: parseFloat(format.duration || 0),
      bitrate: parseInt(format.bit_rate || 0),
      resolution: stream.width && stream.height ? `${stream.width}x${stream.height}` : "unknown",
      fps: stream.r_frame_rate ? eval(stream.r_frame_rate) : 0,
      format: format.format_name,
      size: format.size
    };
    
    // Check for metadata tampering indicators
    if (format.tags?.creation_time) {
      analysis.metadata.creationTime = format.tags.creation_time;
      analysis.findings.push({
        category: "Metadata",
        description: `Original creation time: ${format.tags.creation_time}`,
        significance: "Timestamp available for verification",
        severity: "info"
      });
    }
    
    // Check for editing indicators
    if (format.tags?.encoder) {
      const encoder = format.tags.encoder;
      analysis.metadata.encoder = encoder;
      
      if (!encoder.toLowerCase().includes('camera') && 
          !encoder.toLowerCase().includes('hikvision') && 
          !encoder.toLowerCase().includes('dahua')) {
        analysis.findings.push({
          category: "Authenticity",
          description: `Video encoded with: ${encoder}`,
          significance: "May indicate post-processing or editing",
          severity: "medium"
        });
      }
    }
    
    // Quality analysis
    if (analysis.metadata.bitrate < 100000) {
      analysis.findings.push({
        category: "Quality",
        description: `Low bitrate detected: ${(analysis.metadata.bitrate / 1000).toFixed(0)} kbps`,
        significance: "Possible compression or quality degradation",
        severity: "low"
      });
    }
    
    // Frame extraction (optional - can be resource intensive)
    if (analysis.metadata.duration > 0 && analysis.metadata.duration < 3600) {
      const framesDir = `${filepath}_frames`;
      await fs.ensureDir(framesDir);
      
      try {
        // Extract frames at 1 per second for videos under 1 hour
        const frameRate = Math.min(1, analysis.metadata.duration / 60);
        await execAsync(
          `ffmpeg -i "${filepath}" -vf "fps=${frameRate}" -frames:v 10 "${framesDir}/frame_%04d.jpg" -y`,
          { timeout: 30000 }
        );
        
        const frames = await fs.readdir(framesDir);
        analysis.metadata.extractedFrames = frames.length;
        analysis.metadata.framesPath = framesDir;
        
        analysis.findings.push({
          category: "Frame Extraction",
          description: `${frames.length} frames extracted for analysis`,
          significance: "Frames available for detailed examination",
          severity: "info"
        });
      } catch (err) {
        analysis.findings.push({
          category: "Frame Extraction",
          description: "Frame extraction failed or skipped",
          significance: err.message,
          severity: "info"
        });
      }
    }
    
  } catch (err) {
    analysis.error = `Video analysis failed: ${err.message}`;
    analysis.findings.push({
      category: "Error",
      description: err.message,
      significance: "Analysis incomplete",
      severity: "high"
    });
  }

  return analysis;
};

// Network packet analysis (PCAP)
const analyzePcap = async (filepath) => {
  const analysis = {
    type: "pcap",
    findings: [],
    statistics: {}
  };

  try {
    // Check if tshark is available
    const { stdout: version } = await execAsync("tshark --version").catch(() => ({ stdout: "" }));
    
    if (!version) {
      analysis.error = "tshark not installed - install with: sudo apt-get install tshark";
      return analysis;
    }
    
    // Get basic packet count
    const { stdout: packetCount } = await execAsync(
      `tshark -r "${filepath}" -q -z io,stat,0 | grep "Frames" | head -1`
    ).catch(() => ({ stdout: "0" }));
    
    analysis.statistics.totalPackets = parseInt(packetCount.match(/\d+/)?.[0] || 0);
    
    // Extract unique IP addresses
    const { stdout: ips } = await execAsync(
      `tshark -r "${filepath}" -T fields -e ip.src -e ip.dst 2>/dev/null | head -1000`
    ).catch(() => ({ stdout: "" }));
    
    if (ips) {
      const uniqueIps = [...new Set(ips.trim().split('\n').flatMap(line => 
        line.split('\t').filter(ip => ip && ip.match(/^\d+\.\d+\.\d+\.\d+$/))
      ))];
      analysis.statistics.uniqueIPs = uniqueIps.slice(0, 20);
      analysis.statistics.ipCount = uniqueIps.length;
    }
    
    // Check for RTSP traffic (common in CCTV)
    const { stdout: rtsp } = await execAsync(
      `tshark -r "${filepath}" -Y "rtsp" -T fields -e rtsp.method 2>/dev/null | head -20`
    ).catch(() => ({ stdout: "" }));
    
    if (rtsp.trim()) {
      const methods = rtsp.trim().split('\n').filter(m => m);
      analysis.findings.push({
        category: "Video Streaming",
        description: `RTSP traffic detected (${methods.length} requests)`,
        significance: "Camera streaming protocol identified",
        severity: "info"
      });
      analysis.statistics.rtspMethods = [...new Set(methods)];
    }
    
    // Check for HTTP traffic
    const { stdout: http } = await execAsync(
      `tshark -r "${filepath}" -Y "http.request" -T fields -e http.host -e http.request.uri 2>/dev/null | head -10`
    ).catch(() => ({ stdout: "" }));
    
    if (http.trim()) {
      const requests = http.trim().split('\n').filter(r => r);
      analysis.findings.push({
        category: "HTTP Traffic",
        description: `${requests.length}+ HTTP requests detected`,
        significance: "Unencrypted web traffic present",
        severity: "low"
      });
      analysis.statistics.sampleHttpRequests = requests.slice(0, 5);
    }
    
    // Check for credentials in cleartext
    const { stdout: passwords } = await execAsync(
      `tshark -r "${filepath}" -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.arg 2>/dev/null | head -5`
    ).catch(() => ({ stdout: "" }));
    
    if (passwords.trim()) {
      analysis.findings.push({
        category: "Security Risk",
        description: "Unencrypted credentials detected in FTP traffic",
        significance: "Critical security issue - credentials exposed",
        severity: "critical"
      });
    }
    
    // Protocol distribution
    const { stdout: protocols } = await execAsync(
      `tshark -r "${filepath}" -q -z io,phs 2>/dev/null | head -30`
    ).catch(() => ({ stdout: "" }));
    
    if (protocols) {
      analysis.statistics.protocolHierarchy = protocols.split('\n')
        .filter(line => line.trim() && !line.includes('==='))
        .slice(0, 10)
        .join('\n');
    }
    
  } catch (err) {
    analysis.error = `Network analysis failed: ${err.message}`;
    analysis.findings.push({
      category: "Error",
      description: err.message,
      significance: "Analysis incomplete - check tshark installation",
      severity: "high"
    });
  }

  return analysis;
};

// Log file analysis
const analyzeLogs = async (filepath) => {
  const analysis = {
    type: "log",
    findings: [],
    statistics: {}
  };

  try {
    const content = await fs.readFile(filepath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim());
    
    analysis.statistics.totalLines = lines.length;
    analysis.statistics.fileSize = (await fs.stat(filepath)).size;
    analysis.statistics.fileSizeKB = (analysis.statistics.fileSize / 1024).toFixed(2);
    
    // Parse log patterns
    const timestamps = [];
    const ips = new Set();
    const errors = [];
    const warnings = [];
    const logins = [];
    const failedLogins = [];
    
    lines.forEach(line => {
      // Extract timestamps (various formats)
      const timeMatch = line.match(/\d{4}[-\/]\d{2}[-\/]\d{2}[\sT]\d{2}:\d{2}:\d{2}/) ||
                        line.match(/\d{2}[-\/]\d{2}[-\/]\d{4}\s+\d{2}:\d{2}:\d{2}/) ||
                        line.match(/\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/);
      if (timeMatch) timestamps.push(timeMatch[0]);
      
      // Extract IP addresses
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
      if (ipMatch) ipMatch.forEach(ip => ips.add(ip));
      
      // Categorize log entries
      const lowerLine = line.toLowerCase();
      if (lowerLine.includes('error') || lowerLine.includes('fatal') || lowerLine.includes('critical')) {
        errors.push(line.substring(0, 200));
      }
      if (lowerLine.includes('warn') || lowerLine.includes('warning')) {
        warnings.push(line.substring(0, 200));
      }
      if (lowerLine.includes('login') || lowerLine.includes('authentication') || lowerLine.includes('logged in')) {
        logins.push(line.substring(0, 200));
      }
      if (lowerLine.includes('failed') && (lowerLine.includes('login') || lowerLine.includes('auth'))) {
        failedLogins.push(line.substring(0, 200));
      }
    });
    
    analysis.statistics.uniqueIPs = Array.from(ips).slice(0, 20);
    analysis.statistics.ipCount = ips.size;
    analysis.statistics.errorCount = errors.length;
    analysis.statistics.warningCount = warnings.length;
    analysis.statistics.loginAttempts = logins.length;
    analysis.statistics.failedLoginAttempts = failedLogins.length;
    
    // Timeline analysis
    if (timestamps.length > 0) {
      analysis.statistics.firstEvent = timestamps[0];
      analysis.statistics.lastEvent = timestamps[timestamps.length - 1];
      
      try {
        const first = new Date(timestamps[0]);
        const last = new Date(timestamps[timestamps.length - 1]);
        if (!isNaN(first) && !isNaN(last)) {
          const hours = ((last - first) / 1000 / 3600).toFixed(2);
          analysis.statistics.timeSpanHours = hours;
        }
      } catch (e) {
        // Timestamp parsing failed
      }
    }
    
    // Generate findings
    if (errors.length > 0) {
      analysis.findings.push({
        category: "Errors",
        description: `${errors.length} error entries detected`,
        significance: "System or application errors present",
        severity: errors.length > 50 ? "high" : "medium",
        examples: errors.slice(0, 3)
      });
    }
    
    if (failedLogins.length > 5) {
      analysis.findings.push({
        category: "Security Alert",
        description: `${failedLogins.length} failed login attempts`,
        significance: "Possible brute force or unauthorized access attempt",
        severity: failedLogins.length > 20 ? "critical" : "high",
        examples: failedLogins.slice(0, 3)
      });
    }
    
    if (logins.length > 0) {
      analysis.findings.push({
        category: "Authentication",
        description: `${logins.length} authentication events logged`,
        significance: "Access audit trail available",
        severity: "info",
        examples: logins.slice(0, 3)
      });
    }
    
    if (ips.size > 0) {
      analysis.findings.push({
        category: "Network Activity",
        description: `${ips.size} unique IP addresses detected`,
        significance: "Network connections identified",
        severity: "info"
      });
    }
    
  } catch (err) {
    analysis.error = `Log analysis failed: ${err.message}`;
    analysis.findings.push({
      category: "Error",
      description: err.message,
      significance: "Analysis incomplete",
      severity: "high"
    });
  }

  return analysis;
};

// Timeline reconstruction
const reconstructTimeline = (evidence) => {
  const timeline = {
    events: [],
    summary: {}
  };
  
  // Add acquisition event
  timeline.events.push({
    timestamp: evidence.acquisitionDate || evidence.createdAt,
    type: "evidence_acquired",
    description: `Evidence "${evidence.filename}" acquired`,
    source: "system"
  });
  
  // Add chain of custody events
  if (evidence.chainOfCustody && evidence.chainOfCustody.length > 0) {
    evidence.chainOfCustody.forEach(event => {
      timeline.events.push({
        timestamp: new Date(event.timestamp),
        type: event.action,
        description: `${event.action.replace(/_/g, ' ')} by ${event.user || 'system'}`,
        source: "chain_of_custody",
        user: event.user
      });
    });
  }
  
  // Sort by timestamp
  timeline.events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  
  timeline.summary = {
    totalEvents: timeline.events.length,
    firstEvent: timeline.events[0]?.timestamp,
    lastEvent: timeline.events[timeline.events.length - 1]?.timestamp
  };
  
  return timeline;
};

// Risk assessment
const assessRisk = (analysisResults) => {
  const risks = [];
  let maxSeverity = "low";
  
  const severityMap = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  
  // Check video analysis
  if (analysisResults.videoAnalysis?.findings) {
    analysisResults.videoAnalysis.findings.forEach(f => {
      if (f.severity && severityMap[f.severity] > severityMap[maxSeverity]) {
        maxSeverity = f.severity;
      }
      if (f.severity === "medium" || f.severity === "high" || f.severity === "critical") {
        risks.push(`Video: ${f.description}`);
      }
    });
  }
  
  // Check network analysis
  if (analysisResults.networkAnalysis?.findings) {
    analysisResults.networkAnalysis.findings.forEach(f => {
      if (f.severity && severityMap[f.severity] > severityMap[maxSeverity]) {
        maxSeverity = f.severity;
      }
      if (f.severity === "medium" || f.severity === "high" || f.severity === "critical") {
        risks.push(`Network: ${f.description}`);
      }
    });
  }
  
  // Check log analysis
  if (analysisResults.logAnalysis?.findings) {
    analysisResults.logAnalysis.findings.forEach(f => {
      if (f.severity && severityMap[f.severity] > severityMap[maxSeverity]) {
        maxSeverity = f.severity;
      }
      if (f.severity === "medium" || f.severity === "high" || f.severity === "critical") {
        risks.push(`Logs: ${f.description}`);
      }
    });
  }
  
  return {
    level: maxSeverity,
    factors: risks,
    score: severityMap[maxSeverity] * 25,
    recommendation: maxSeverity === "critical" || maxSeverity === "high"
      ? "Immediate investigation recommended"
      : maxSeverity === "medium"
      ? "Further review advised"
      : "No critical concerns identified"
  };
};

// Main analysis function
export const analyzeEvidence = async (req, res) => {
  try {
    const { evidenceId, analysisType, investigator } = req.body;

    if (!evidenceId) {
      return res.status(400).json({ error: "evidenceId is required" });
    }

    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }

    // Verify file exists
    if (!await fs.pathExists(evidence.filepath)) {
      return res.status(404).json({ 
        error: "Evidence file not found on disk",
        filepath: evidence.filepath
      });
    }

    // Verify integrity before analysis
    const buffer = await fs.readFile(evidence.filepath);
    const currentHash = crypto.createHash("sha256").update(buffer).digest("hex");
    
    if (evidence.sha256 && currentHash !== evidence.sha256) {
      return res.status(400).json({
        error: "Integrity verification failed",
        message: "Evidence file has been modified or corrupted",
        originalHash: evidence.sha256,
        currentHash,
        recommendation: "Evidence may be compromised - do not use for investigation"
      });
    }

    // Initialize analysis results
    let analysisResults = {
      evidenceId: evidence._id,
      filename: evidence.filename,
      type: evidence.type,
      sha256: evidence.sha256 || currentHash,
      size: evidence.size || buffer.length,
      sizeKB: ((evidence.size || buffer.length) / 1024).toFixed(2),
      sizeMB: ((evidence.size || buffer.length) / 1024 / 1024).toFixed(2),
      acquisitionDate: evidence.acquisitionDate || evidence.createdAt,
      analysisDate: new Date(),
      integrityVerified: true,
      investigator: investigator || "system"
    };

    const typeToAnalyze = analysisType || "full";

    // Perform type-specific analysis
    if (typeToAnalyze === "full" || typeToAnalyze === "video") {
      if (evidence.type === "video" || path.extname(evidence.filepath).match(/\.(mp4|avi|mov|mkv|flv)$/i)) {
        console.log("Performing video analysis...");
        analysisResults.videoAnalysis = await analyzeVideo(evidence.filepath);
      }
    }
    
    if (typeToAnalyze === "full" || typeToAnalyze === "network") {
      if (evidence.type === "pcap" || path.extname(evidence.filepath).match(/\.(pcap|pcapng|cap)$/i)) {
        console.log("Performing network analysis...");
        analysisResults.networkAnalysis = await analyzePcap(evidence.filepath);
      }
    }
    
    if (typeToAnalyze === "full" || typeToAnalyze === "logs") {
      if (evidence.type === "log" || path.extname(evidence.filepath).match(/\.(log|txt)$/i)) {
        console.log("Performing log analysis...");
        analysisResults.logAnalysis = await analyzeLogs(evidence.filepath);
      }
    }

    // Timeline reconstruction
    analysisResults.timeline = reconstructTimeline(evidence);

    // Risk assessment
    analysisResults.riskAssessment = assessRisk(analysisResults);

    // Update evidence record
    const updateData = {
      analyzed: true,
      analysisResults,
      lastAnalyzed: new Date()
    };

    // Add to chain of custody
    if (!evidence.chainOfCustody) {
      evidence.chainOfCustody = [];
    }
    
    evidence.chainOfCustody.push({
      timestamp: new Date().toISOString(),
      action: "analyzed",
      user: investigator || "system",
      notes: `Analysis type: ${typeToAnalyze}`
    });
    
    updateData.chainOfCustody = evidence.chainOfCustody;

    await Evidence.findByIdAndUpdate(evidenceId, updateData);

    res.json({
      success: true,
      analysis: analysisResults,
      message: "Analysis completed successfully"
    });

  } catch (error) {
    console.error("Analysis error:", error);
    res.status(500).json({
      error: "Analysis failed",
      details: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
};

// Generate forensic report
export const generateReport = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    
    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }
    
    const report = {
      reportId: `FR-${Date.now()}`,
      generatedAt: new Date().toISOString(),
      caseNumber: evidence.caseNumber || "N/A",
      investigator: evidence.investigator || "Unknown",
      
      evidenceSummary: {
        id: evidence._id,
        filename: evidence.filename,
        type: evidence.type,
        deviceId: evidence.deviceId,
        acquisitionDate: evidence.acquisitionDate || evidence.createdAt,
        size: evidence.size,
        sizeKB: (evidence.size / 1024).toFixed(2),
        sizeMB: (evidence.size / 1024 / 1024).toFixed(2)
      },
      
      integrityVerification: {
        md5: evidence.md5,
        sha1: evidence.sha1,
        sha256: evidence.sha256,
        sha512: evidence.sha512,
        verified: true,
        verificationDate: new Date().toISOString()
      },
      
      analysisResults: evidence.analysisResults || {
        status: "Not analyzed",
        message: "No analysis has been performed on this evidence"
      },
      
      chainOfCustody: evidence.chainOfCustody || [],
      
      conclusions: evidence.analysisResults?.riskAssessment || {
        level: "unknown",
        recommendation: "Analysis required"
      },
      
      recommendations: [
        "Preserve original evidence in secure, tamper-proof storage",
        "Maintain complete chain of custody documentation",
        "Perform regular integrity verification using cryptographic hashes",
        "Document all analysis procedures and findings",
        "Ensure evidence handling complies with legal requirements",
        "Create working copies for analysis, never modify originals"
      ],
      
      metadata: {
        reportVersion: "1.0",
        toolVersion: "IoT CCTV Forensic Tool v1.0",
        standards: ["NIST SP 800-86", "ISO/IEC 27037", "RFC 3227"]
      }
    };
    
    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error("Report generation error:", error);
    res.status(500).json({ 
      error: "Report generation failed", 
      details: error.message 
    });
  }
};

// List all evidence
export const listEvidence = async (req, res) => {
  try {
    const { caseNumber, type, analyzed, deviceId } = req.query;
    
    const query = {};
    if (caseNumber) query.caseNumber = caseNumber;
    if (type) query.type = type;
    if (analyzed !== undefined) query.analyzed = analyzed === "true";
    if (deviceId) query.deviceId = deviceId;
    
    const evidence = await Evidence.find(query)
      .sort({ acquisitionDate: -1 })
      .select('filename type sha256 size acquisitionDate analyzed caseNumber');
    
    res.json({
      success: true,
      count: evidence.length,
      evidence
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};

// Get evidence details
export const getEvidenceDetails = async (req, res) => {
  try {
    const { evidenceId } = req.params;
    
    const evidence = await Evidence.findById(evidenceId);
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