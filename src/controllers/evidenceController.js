import Evidence from "../models/Evidence.js";
import fs from "fs-extra";
import { exec } from "child_process";
import { promisify } from "util";
import crypto from "crypto";

const execAsync = promisify(exec);

// Video forensic analysis
const analyzeVideo = async (filepath) => {
  const analysis = {
    type: "video",
    findings: []
  };

  try {
    // Extract video metadata with ffprobe
    const { stdout } = await execAsync(
      `ffprobe -v quiet -print_format json -show_format -show_streams "${filepath}"`
    );
    const videoData = JSON.parse(stdout);
    
    analysis.codec = videoData.streams[0]?.codec_name;
    analysis.duration = parseFloat(videoData.format.duration);
    analysis.bitrate = parseInt(videoData.format.bit_rate);
    analysis.resolution = `${videoData.streams[0]?.width}x${videoData.streams[0]?.height}`;
    analysis.fps = eval(videoData.streams[0]?.r_frame_rate);
    analysis.format = videoData.format.format_name;
    
    // Check for metadata tampering indicators
    const creationTime = videoData.format.tags?.creation_time;
    if (creationTime) {
      analysis.originalCreationTime = creationTime;
      analysis.findings.push({
        category: "Metadata",
        description: `Video created at: ${creationTime}`,
        significance: "Timestamp verification"
      });
    }
    
    // Extract frames for analysis
    const framesDir = `${filepath}_frames`;
    await fs.ensureDir(framesDir);
    
    // Extract key frames (every 10 seconds)
    const frameInterval = Math.max(1, Math.floor(analysis.duration / 10));
    await execAsync(
      `ffmpeg -i "${filepath}" -vf "select='not(mod(n\\,${frameInterval * Math.floor(analysis.fps)}))'" -vsync vfr "${framesDir}/frame_%04d.jpg"`
    );
    
    const frames = await fs.readdir(framesDir);
    analysis.extractedFrames = frames.length;
    analysis.framesPath = framesDir;
    
    // Check for anomalies
    if (analysis.bitrate < 100000) {
      analysis.findings.push({
        category: "Quality",
        description: "Unusually low bitrate detected",
        significance: "Possible compression or degradation",
        severity: "medium"
      });
    }
    
    // Check for editing indicators
    if (videoData.format.tags?.encoder && !videoData.format.tags.encoder.includes("camera")) {
      analysis.findings.push({
        category: "Authenticity",
        description: `Video encoded with: ${videoData.format.tags.encoder}`,
        significance: "Possible post-processing or editing",
        severity: "high"
      });
    }
    
  } catch (err) {
    analysis.error = err.message;
  }

  return analysis;
};

// Network packet analysis (PCAP)
const analyzePcap = async (filepath) => {
  const analysis = {
    type: "pcap",
    findings: []
  };

  try {
    // Get packet statistics with tshark
    const { stdout: stats } = await execAsync(
      `tshark -r "${filepath}" -q -z io,stat,0`
    );
    analysis.statistics = stats;
    
    // Extract protocol distribution
    const { stdout: protocols } = await execAsync(
      `tshark -r "${filepath}" -q -z io,phs`
    );
    analysis.protocolHierarchy = protocols;
    
    // Find unique IP addresses
    const { stdout: ips } = await execAsync(
      `tshark -r "${filepath}" -T fields -e ip.src -e ip.dst | sort -u`
    );
    const uniqueIps = [...new Set(ips.trim().split('\n').flatMap(line => line.split('\t')))];
    analysis.uniqueIPs = uniqueIps.filter(ip => ip && ip !== '');
    
    // Detect suspicious traffic patterns
    const { stdout: httpTraffic } = await execAsync(
      `tshark -r "${filepath}" -Y "http.request" -T fields -e http.host -e http.request.uri`
    ).catch(() => ({ stdout: '' }));
    
    if (httpTraffic.trim()) {
      analysis.httpRequests = httpTraffic.trim().split('\n').slice(0, 10);
      analysis.findings.push({
        category: "HTTP Traffic",
        description: `Detected ${httpTraffic.trim().split('\n').length} HTTP requests`,
        significance: "Unencrypted web traffic captured"
      });
    }
    
    // Check for RTSP streams (common in CCTV)
    const { stdout: rtspTraffic } = await execAsync(
      `tshark -r "${filepath}" -Y "rtsp" -T fields -e rtsp.method`
    ).catch(() => ({ stdout: '' }));
    
    if (rtspTraffic.trim()) {
      analysis.findings.push({
        category: "Video Streaming",
        description: "RTSP traffic detected",
        significance: "Camera streaming protocol identified",
        severity: "info"
      });
    }
    
    // Detect potential security issues
    const { stdout: ftpTraffic } = await execAsync(
      `tshark -r "${filepath}" -Y "ftp" -T fields -e ftp.request.command`
    ).catch(() => ({ stdout: '' }));
    
    if (ftpTraffic.includes('USER') || ftpTraffic.includes('PASS')) {
      analysis.findings.push({
        category: "Security",
        description: "Unencrypted FTP credentials detected",
        significance: "Potential credential exposure",
        severity: "high"
      });
    }
    
  } catch (err) {
    analysis.error = err.message;
  }

  return analysis;
};

// Log file analysis
const analyzeLogs = async (filepath) => {
  const analysis = {
    type: "log",
    findings: []
  };

  try {
    const content = await fs.readFile(filepath, 'utf-8');
    const lines = content.split('\n');
    
    analysis.totalLines = lines.length;
    analysis.fileSize = (await fs.stat(filepath)).size;
    
    // Parse log patterns
    const timestamps = [];
    const ips = [];
    const errors = [];
    const warnings = [];
    const logins = [];
    
    lines.forEach(line => {
      // Extract timestamps
      const timeMatch = line.match(/\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}/);
      if (timeMatch) timestamps.push(timeMatch[0]);
      
      // Extract IPs
      const ipMatch = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) ips.push(ipMatch[0]);
      
      // Find errors
      if (/error|failed|fatal/i.test(line)) errors.push(line.trim());
      
      // Find warnings
      if (/warn|warning/i.test(line)) warnings.push(line.trim());
      
      // Find login attempts
      if (/login|authentication|logged in|sign in/i.test(line)) logins.push(line.trim());
    });
    
    analysis.uniqueIPs = [...new Set(ips)];
    analysis.errorCount = errors.length;
    analysis.warningCount = warnings.length;
    analysis.loginAttempts = logins.length;
    
    // Timeline analysis
    if (timestamps.length > 0) {
      analysis.firstEvent = timestamps[0];
      analysis.lastEvent = timestamps[timestamps.length - 1];
      
      const first = new Date(timestamps[0]);
      const last = new Date(timestamps[timestamps.length - 1]);
      analysis.timeSpan = `${((last - first) / 1000 / 3600).toFixed(2)} hours`;
    }
    
    // Security findings
    if (errors.length > 0) {
      analysis.findings.push({
        category: "Errors",
        description: `${errors.length} error entries found`,
        examples: errors.slice(0, 5),
        severity: "medium"
      });
    }
    
    if (logins.length > 0) {
      analysis.findings.push({
        category: "Authentication",
        description: `${logins.length} login attempts recorded`,
        examples: logins.slice(0, 5),
        significance: "Access audit trail"
      });
    }
    
    // Check for suspicious patterns
    const failedLogins = lines.filter(l => /failed.*login|authentication.*failed/i.test(l));
    if (failedLogins.length > 5) {
      analysis.findings.push({
        category: "Security Alert",
        description: `${failedLogins.length} failed login attempts`,
        significance: "Possible brute force attack",
        severity: "high"
      });
    }
    
  } catch (err) {
    analysis.error = err.message;
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
    timestamp: evidence.acquisitionDate,
    type: "evidence_acquired",
    description: `Evidence ${evidence.filename} acquired`,
    source: evidence.deviceId
  });
  
  // Add chain of custody events
  if (evidence.chainOfCustody) {
    evidence.chainOfCustody.forEach(event => {
      timeline.events.push({
        timestamp: new Date(event.timestamp),
        type: event.action,
        description: `${event.action} by ${event.user}`,
        source: "chain_of_custody"
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

// Main analysis function
export const analyzeEvidence = async (req, res) => {
  try {
    const { evidenceId, analysisType } = req.body;

    const evidence = await Evidence.findById(evidenceId);
    if (!evidence) {
      return res.status(404).json({ error: "Evidence not found" });
    }

    // Verify integrity before analysis
    const buffer = await fs.readFile(evidence.filepath);
    const currentHash = crypto.createHash("sha256").update(buffer).digest("hex");
    
    if (currentHash !== evidence.sha256) {
      return res.status(400).json({
        error: "Integrity verification failed",
        message: "Evidence file has been modified",
        originalHash: evidence.sha256,
        currentHash
      });
    }

    let analysisResults = {
      evidenceId: evidence._id,
      filename: evidence.filename,
      type: evidence.type,
      sha256: evidence.sha256,
      size: evidence.size,
      sizeKB: (evidence.size / 1024).toFixed(2),
      sizeMB: (evidence.size / 1024 / 1024).toFixed(2),
      acquisitionDate: evidence.acquisitionDate,
      analysisDate: new Date(),
      integrityVerified: true
    };

    // Perform type-specific analysis
    if (analysisType === "full" || analysisType === "video") {
      if (evidence.type === "video") {
        analysisResults.videoAnalysis = await analyzeVideo(evidence.filepath);
      }
    }
    
    if (analysisType === "full" || analysisType === "network") {
      if (evidence.type === "pcap") {
        analysisResults.networkAnalysis = await analyzePcap(evidence.filepath);
      }
    }
    
    if (analysisType === "full" || analysisType === "logs") {
      if (evidence.type === "log") {
        analysisResults.logAnalysis = await analyzeLogs(evidence.filepath);
      }
    }

    // Timeline reconstruction
    analysisResults.timeline = reconstructTimeline(evidence);

    // Generate risk assessment
    const riskFactors = [];
    let riskLevel = "low";
    
    if (analysisResults.videoAnalysis?.findings?.some(f => f.severity === "high")) {
      riskFactors.push("Video authenticity concerns");
      riskLevel = "high";
    }
    
    if (analysisResults.networkAnalysis?.findings?.some(f => f.severity === "high")) {
      riskFactors.push("Network security issues");
      riskLevel = "high";
    }
    
    if (analysisResults.logAnalysis?.findings?.some(f => f.severity === "high")) {
      riskFactors.push("Suspicious log entries");
      riskLevel = "high";
    }
    
    analysisResults.riskAssessment = {
      level: riskLevel,
      factors: riskFactors,
      recommendation: riskLevel === "high" 
        ? "Further investigation recommended" 
        : "No immediate concerns identified"
    };

    // Update evidence with analysis results
    await Evidence.findByIdAndUpdate(evidenceId, {
      analyzed: true,
      analysisResults,
      lastAnalyzed: new Date(),
      $push: {
        chainOfCustody: {
          evidenceId,
          timestamp: new Date().toISOString(),
          action: "analyzed",
          user: req.body.investigator || "system"
        }
      }
    });

    res.json({
      success: true,
      analysis: analysisResults,
      message: "Analysis completed successfully"
    });

  } catch (error) {
    console.error("Analysis error:", error);
    res.status(500).json({
      error: "Analysis failed",
      details: error.message
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
      caseNumber: evidence.caseNumber,
      investigator: evidence.investigator,
      
      evidenceSummary: {
        id: evidence._id,
        filename: evidence.filename,
        type: evidence.type,
        deviceId: evidence.deviceId,
        acquisitionDate: evidence.acquisitionDate,
        size: evidence.size
      },
      
      integrityVerification: {
        md5: evidence.md5,
        sha1: evidence.sha1,
        sha256: evidence.sha256,
        sha512: evidence.sha512,
        verified: true
      },
      
      analysisResults: evidence.analysisResults || "Not analyzed",
      
      chainOfCustody: evidence.chainOfCustody,
      
      conclusions: evidence.analysisResults?.riskAssessment || "Pending analysis",
      
      recommendations: [
        "Preserve original evidence in secure storage",
        "Maintain complete chain of custody documentation",
        "Perform regular integrity verification",
        "Document all analysis procedures"
      ]
    };
    
    res.json({
      success: true,
      report
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};