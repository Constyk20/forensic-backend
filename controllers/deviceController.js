import Device from "../models/Device.js";
import { exec } from "child_process";
import { promisify } from "util";
import net from "net";

const execAsync = promisify(exec);

// Common CCTV ports to scan
const CCTV_PORTS = [80, 443, 554, 8000, 8080, 8081, 37777, 37778, 9000];

// Known CCTV manufacturers and their signatures
const CCTV_SIGNATURES = {
  hikvision: {
    ports: [80, 8000],
    keywords: ["hikvision", "app-webs", "iVMS"],
    defaultPaths: ["/doc/page/login.asp", "/"]
  },
  dahua: {
    ports: [80, 37777],
    keywords: ["dahua", "DH-", "dh_webClient"],
    defaultPaths: ["/"]
  },
  axis: {
    ports: [80, 443],
    keywords: ["axis", "AXIS"],
    defaultPaths: ["/axis-cgi/serverreport.cgi"]
  },
  foscam: {
    ports: [88, 8088],
    keywords: ["foscam"],
    defaultPaths: ["/"]
  }
};

// Ping an IP address to check if host is alive
const pingHost = async (ip, timeout = 2000) => {
  try {
    const isWindows = process.platform === "win32";
    const pingCmd = isWindows 
      ? `ping -n 1 -w ${timeout} ${ip}`
      : `ping -c 1 -W ${Math.floor(timeout/1000)} ${ip}`;
    
    const { stdout } = await execAsync(pingCmd, { timeout: timeout + 1000 });
    
    // Check for successful ping
    if (isWindows) {
      return stdout.includes("Reply from") || stdout.includes("bytes=");
    } else {
      return stdout.includes("1 received") || stdout.includes("1 packets received");
    }
  } catch (err) {
    return false;
  }
};

// Scan a single port on a host
const scanPort = (ip, port, timeout = 2000) => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;

    socket.setTimeout(timeout);
    
    socket.on("connect", () => {
      isOpen = true;
      socket.destroy();
      resolve(true);
    });

    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });

    socket.on("error", () => {
      resolve(false);
    });

    socket.connect(port, ip);
  });
};

// Scan multiple ports on a host
const scanPorts = async (ip, ports = CCTV_PORTS) => {
  const openPorts = [];
  
  for (const port of ports) {
    const isOpen = await scanPort(ip, port, 1500);
    if (isOpen) {
      openPorts.push(port);
    }
  }
  
  return openPorts;
};

// Try to identify device manufacturer
const identifyManufacturer = async (ip, openPorts) => {
  let manufacturer = "Unknown";
  let model = "Unknown";
  let type = "Unknown";
  
  // Try HTTP request on common ports
  for (const port of openPorts.filter(p => [80, 8000, 8080, 8081].includes(p))) {
    try {
      // Use curl for HTTP requests (cross-platform)
      const { stdout } = await execAsync(
        `curl -s -m 3 --max-time 3 http://${ip}:${port}/ || echo "failed"`,
        { timeout: 4000 }
      ).catch(() => ({ stdout: "" }));
      
      const response = stdout.toLowerCase();
      
      // Check for manufacturer signatures
      if (response.includes("hikvision") || response.includes("ivms") || response.includes("app-webs")) {
        manufacturer = "Hikvision";
        type = "CCTV";
        model = "IP Camera";
      } else if (response.includes("dahua") || response.includes("dh-") || response.includes("dh_webclient")) {
        manufacturer = "Dahua";
        type = "CCTV";
        model = "IP Camera";
      } else if (response.includes("axis")) {
        manufacturer = "Axis";
        type = "CCTV";
        model = "Network Camera";
      } else if (response.includes("foscam")) {
        manufacturer = "Foscam";
        type = "CCTV";
        model = "IP Camera";
      } else if (response.includes("camera") || response.includes("surveillance")) {
        type = "CCTV";
        manufacturer = "Generic";
        model = "IP Camera";
      }
      
      if (manufacturer !== "Unknown") break;
    } catch (err) {
      // Continue to next port
    }
  }
  
  // Check for RTSP port (common in cameras)
  if (openPorts.includes(554) && manufacturer === "Unknown") {
    type = "CCTV";
    manufacturer = "Generic";
    model = "RTSP Camera";
  }
  
  return { manufacturer, model, type };
};

// Get device services based on open ports
const identifyServices = (openPorts) => {
  const services = [];
  
  const portMap = {
    80: { service: "HTTP", protocol: "tcp", description: "Web interface" },
    443: { service: "HTTPS", protocol: "tcp", description: "Secure web interface" },
    554: { service: "RTSP", protocol: "tcp", description: "Real-time streaming" },
    8000: { service: "HTTP-Alt", protocol: "tcp", description: "Alternative HTTP port" },
    8080: { service: "HTTP-Proxy", protocol: "tcp", description: "HTTP proxy/web" },
    8081: { service: "HTTP-Alt", protocol: "tcp", description: "Alternative HTTP port" },
    37777: { service: "Dahua DVR", protocol: "tcp", description: "Dahua proprietary protocol" },
    37778: { service: "Dahua DVR-Alt", protocol: "tcp", description: "Dahua alternative port" },
    9000: { service: "Management", protocol: "tcp", description: "Device management port" }
  };
  
  openPorts.forEach(port => {
    if (portMap[port]) {
      services.push({
        port,
        ...portMap[port]
      });
    } else {
      services.push({
        port,
        service: "Unknown",
        protocol: "tcp",
        description: "Unidentified service"
      });
    }
  });
  
  return services;
};

// Check for common vulnerabilities
const checkVulnerabilities = (manufacturer, openPorts, model) => {
  const vulnerabilities = [];
  
  // Check for HTTP without HTTPS
  if (openPorts.includes(80) && !openPorts.includes(443)) {
    vulnerabilities.push({
      severity: "medium",
      type: "Unencrypted Communication",
      description: "Device uses HTTP without HTTPS encryption",
      cve: null,
      remediation: "Enable HTTPS and disable HTTP access"
    });
  }
  
  // Check for RTSP exposure
  if (openPorts.includes(554)) {
    vulnerabilities.push({
      severity: "low",
      type: "RTSP Port Exposed",
      description: "RTSP streaming port is accessible",
      cve: null,
      remediation: "Restrict RTSP access to trusted networks only"
    });
  }
  
  // Check for multiple open ports (large attack surface)
  if (openPorts.length > 4) {
    vulnerabilities.push({
      severity: "low",
      type: "Large Attack Surface",
      description: `${openPorts.length} ports are open`,
      cve: null,
      remediation: "Close unnecessary ports and services"
    });
  }
  
  // Known vulnerabilities for specific manufacturers
  if (manufacturer === "Hikvision") {
    vulnerabilities.push({
      severity: "info",
      type: "Known Manufacturer Issues",
      description: "Hikvision devices have had security vulnerabilities in the past",
      cve: "Various (CVE-2021-36260, etc.)",
      remediation: "Ensure firmware is up to date"
    });
  }
  
  if (manufacturer === "Dahua") {
    vulnerabilities.push({
      severity: "info",
      type: "Known Manufacturer Issues",
      description: "Dahua devices have had authentication bypass vulnerabilities",
      cve: "Various (CVE-2021-33044, etc.)",
      remediation: "Update firmware and change default credentials"
    });
  }
  
  return vulnerabilities;
};

// Perform security audit
const performSecurityAudit = (device) => {
  const audit = {
    timestamp: new Date(),
    deviceIp: device.ip,
    findings: [],
    riskLevel: "low",
    score: 100
  };
  
  // Check for default credentials risk
  audit.findings.push({
    category: "Authentication",
    issue: "Device may use default credentials",
    recommendation: "Change default username and password immediately",
    severity: "high"
  });
  audit.score -= 30;
  
  // Check encryption
  if (!device.openPorts.includes(443)) {
    audit.findings.push({
      category: "Encryption",
      issue: "No HTTPS support detected",
      recommendation: "Enable HTTPS for secure communication",
      severity: "medium"
    });
    audit.score -= 20;
  }
  
  // Check network exposure
  if (device.openPorts.length > 3) {
    audit.findings.push({
      category: "Network Security",
      issue: `${device.openPorts.length} ports are exposed`,
      recommendation: "Minimize open ports to reduce attack surface",
      severity: "low"
    });
    audit.score -= 10;
  }
  
  // Check for critical services
  if (device.openPorts.includes(554)) {
    audit.findings.push({
      category: "Service Exposure",
      issue: "RTSP streaming port is publicly accessible",
      recommendation: "Restrict RTSP access to local network only",
      severity: "low"
    });
    audit.score -= 5;
  }
  
  // Determine overall risk level
  if (audit.score < 50) {
    audit.riskLevel = "critical";
  } else if (audit.score < 70) {
    audit.riskLevel = "high";
  } else if (audit.score < 85) {
    audit.riskLevel = "medium";
  } else {
    audit.riskLevel = "low";
  }
  
  return audit;
};

// Network scan function
const scanNetwork = async (subnet = "192.168.1", startRange = 1, endRange = 254) => {
  console.log(`Scanning network: ${subnet}.${startRange}-${endRange}`);
  
  const aliveHosts = [];
  const scanPromises = [];
  
  // Scan in batches to avoid overwhelming the network
  const batchSize = 20;
  
  for (let i = startRange; i <= endRange; i += batchSize) {
    const batchPromises = [];
    
    for (let j = i; j < Math.min(i + batchSize, endRange + 1); j++) {
      const ip = `${subnet}.${j}`;
      batchPromises.push(
        pingHost(ip, 1500).then(isAlive => {
          if (isAlive) {
            console.log(`✓ Host alive: ${ip}`);
            return ip;
          }
          return null;
        })
      );
    }
    
    const batchResults = await Promise.all(batchPromises);
    aliveHosts.push(...batchResults.filter(ip => ip !== null));
  }
  
  console.log(`Found ${aliveHosts.length} alive hosts`);
  return aliveHosts;
};

// Main device discovery function
export const discoverDevices = async (req, res) => {
  try {
    const { subnet, deepScan, startRange, endRange } = req.body;
    
    const targetSubnet = subnet || "192.168.1";
    const start = parseInt(startRange) || 1;
    const end = parseInt(endRange) || 254;
    
    console.log("=== Starting Device Discovery ===");
    console.log(`Subnet: ${targetSubnet}.0/24`);
    console.log(`Deep Scan: ${deepScan ? "Yes" : "No"}`);
    
    const discoveredDevices = [];
    
    // Scan network for alive hosts
    const aliveHosts = await scanNetwork(targetSubnet, start, end);
    
    if (aliveHosts.length === 0) {
      console.log("No hosts found on network");
    }
    
    // Analyze each alive host
    for (const ip of aliveHosts) {
      console.log(`\nAnalyzing ${ip}...`);
      
      // Scan ports
      const openPorts = await scanPorts(ip);
      console.log(`  Open ports: ${openPorts.join(", ") || "none"}`);
      
      if (openPorts.length === 0) continue;
      
      // Identify manufacturer and type
      const deviceInfo = await identifyManufacturer(ip, openPorts);
      console.log(`  Type: ${deviceInfo.type}, Manufacturer: ${deviceInfo.manufacturer}`);
      
      // Only save if it's a CCTV device or has camera-related ports
      if (deviceInfo.type === "CCTV" || openPorts.includes(554) || 
          openPorts.includes(37777) || deviceInfo.manufacturer !== "Unknown") {
        
        const services = identifyServices(openPorts);
        const vulnerabilities = checkVulnerabilities(
          deviceInfo.manufacturer, 
          openPorts, 
          deviceInfo.model
        );
        
        const device = {
          name: `${deviceInfo.manufacturer} ${deviceInfo.model}`,
          ip,
          manufacturer: deviceInfo.manufacturer,
          model: deviceInfo.model,
          type: deviceInfo.type,
          openPorts,
          services,
          vulnerabilities,
          discoveredAt: new Date(),
          status: "active",
          lastSeen: new Date()
        };
        
        // Perform security audit if deep scan is enabled
        if (deepScan) {
          device.securityAudit = performSecurityAudit(device);
          console.log(`  Security Score: ${device.securityAudit.score}/100`);
        }
        
        discoveredDevices.push(device);
      }
    }
    
    console.log(`\n=== Discovery Complete ===`);
    console.log(`Found ${discoveredDevices.length} CCTV devices`);
    
    // Add simulated devices for testing/demo purposes
    const simulatedDevices = [
      {
        name: "Hikvision DS-2CD2142FWD-I",
        ip: "192.168.1.100",
        manufacturer: "Hikvision",
        model: "DS-2CD2142FWD-I",
        type: "CCTV",
        openPorts: [80, 554, 8000],
        services: [
          { port: 80, service: "HTTP", protocol: "tcp", description: "Web interface" },
          { port: 554, service: "RTSP", protocol: "tcp", description: "Real-time streaming" },
          { port: 8000, service: "HTTP-Alt", protocol: "tcp", description: "Alternative HTTP port" }
        ],
        vulnerabilities: [
          {
            severity: "medium",
            type: "Unencrypted Communication",
            description: "Device uses HTTP without HTTPS encryption",
            remediation: "Enable HTTPS"
          }
        ],
        firmware: {
          firmwareVersion: "V5.5.82",
          serialNumber: "HIKTEST12345",
          deviceModel: "DS-2CD2142FWD-I"
        },
        discoveredAt: new Date(),
        status: "simulated",
        lastSeen: new Date()
      },
      {
        name: "Dahua IPC-HFW4431R-Z",
        ip: "192.168.1.101",
        manufacturer: "Dahua",
        model: "IPC-HFW4431R-Z",
        type: "CCTV",
        openPorts: [80, 554, 37777],
        services: [
          { port: 80, service: "HTTP", protocol: "tcp", description: "Web interface" },
          { port: 554, service: "RTSP", protocol: "tcp", description: "Real-time streaming" },
          { port: 37777, service: "Dahua DVR", protocol: "tcp", description: "Dahua proprietary" }
        ],
        vulnerabilities: [
          {
            severity: "medium",
            type: "Unencrypted Communication",
            description: "Device uses HTTP without HTTPS",
            remediation: "Enable HTTPS"
          },
          {
            severity: "info",
            type: "Known Manufacturer Issues",
            description: "Dahua devices have had authentication vulnerabilities",
            cve: "CVE-2021-33044"
          }
        ],
        discoveredAt: new Date(),
        status: "simulated",
        lastSeen: new Date()
      },
      {
        name: "Axis M3046-V",
        ip: "192.168.1.102",
        manufacturer: "Axis",
        model: "M3046-V",
        type: "CCTV",
        openPorts: [80, 443, 554],
        services: [
          { port: 80, service: "HTTP", protocol: "tcp", description: "Web interface" },
          { port: 443, service: "HTTPS", protocol: "tcp", description: "Secure web interface" },
          { port: 554, service: "RTSP", protocol: "tcp", description: "Real-time streaming" }
        ],
        vulnerabilities: [],
        discoveredAt: new Date(),
        status: "simulated",
        lastSeen: new Date()
      }
    ];
    
    // Add security audits to simulated devices if deep scan
    if (deepScan) {
      simulatedDevices.forEach(device => {
        device.securityAudit = performSecurityAudit(device);
      });
    }
    
    // Save to database
    // Clear old simulated devices
    await Device.deleteMany({ status: "simulated" });
    
    // Save discovered and simulated devices
    const allDevices = [...discoveredDevices, ...simulatedDevices];
    if (allDevices.length > 0) {
      await Device.insertMany(allDevices);
    }
    
    res.json({
      success: true,
      summary: {
        total: allDevices.length,
        discovered: discoveredDevices.length,
        simulated: simulatedDevices.length,
        scanSubnet: targetSubnet,
        scanRange: `${start}-${end}`,
        deepScan: deepScan || false,
        hostsScanned: end - start + 1,
        aliveHosts: aliveHosts.length
      },
      devices: allDevices,
      message: `Found ${allDevices.length} CCTV devices (${discoveredDevices.length} discovered, ${simulatedDevices.length} simulated)`
    });

  } catch (error) {
    console.error("Device discovery error:", error);
    res.status(500).json({ 
      error: "Device discovery failed", 
      details: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined
    });
  }
};

// List devices with filtering
export const listDevices = async (req, res) => {
  try {
    const { status, manufacturer, type, sortBy, limit } = req.query;
    
    // Build query
    const query = {};
    if (status) query.status = status;
    if (manufacturer) query.manufacturer = new RegExp(manufacturer, "i");
    if (type) query.type = type;
    
    // Build sort
    let sortOptions = {};
    if (sortBy === "ip") {
      sortOptions = { ip: 1 };
    } else if (sortBy === "manufacturer") {
      sortOptions = { manufacturer: 1, model: 1 };
    } else if (sortBy === "name") {
      sortOptions = { name: 1 };
    } else {
      sortOptions = { discoveredAt: -1 };
    }
    
    // Execute query
    let deviceQuery = Device.find(query).sort(sortOptions);
    
    if (limit) {
      deviceQuery = deviceQuery.limit(parseInt(limit));
    }
    
    const devices = await deviceQuery.exec();
    
    res.json({
      success: true,
      count: devices.length,
      devices
    });
  } catch (error) {
    console.error("List devices error:", error);
    res.status(500).json({ 
      error: "Failed to list devices", 
      details: error.message 
    });
  }
};

// Get device details
export const getDeviceDetails = async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const device = await Device.findById(deviceId);
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    
    // Get associated evidence
    const Evidence = (await import("../models/Evidence.js")).default;
    const evidence = await Evidence.find({ deviceId: device._id })
      .sort({ acquisitionDate: -1 })
      .select('filename type sha256 size acquisitionDate analyzed');
    
    res.json({
      success: true,
      device,
      evidenceCount: evidence.length,
      evidence: evidence.map(e => ({
        id: e._id,
        type: e.type,
        filename: e.filename,
        acquisitionDate: e.acquisitionDate,
        size: e.size,
        sizeKB: (e.size / 1024).toFixed(2),
        analyzed: e.analyzed
      }))
    });
  } catch (error) {
    console.error("Get device details error:", error);
    res.status(500).json({ 
      error: "Failed to get device details", 
      details: error.message 
    });
  }
};

// Update device information
export const updateDevice = async (req, res) => {
  try {
    const { deviceId } = req.params;
    const updates = req.body;
    
    // Don't allow updating certain fields
    delete updates._id;
    delete updates.discoveredAt;
    
    const device = await Device.findByIdAndUpdate(
      deviceId, 
      { ...updates, lastSeen: new Date() },
      { new: true, runValidators: true }
    );
    
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    
    res.json({
      success: true,
      device,
      message: "Device updated successfully"
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Failed to update device", 
      details: error.message 
    });
  }
};

// Delete device
export const deleteDevice = async (req, res) => {
  try {
    const { deviceId } = req.params;
    
    const device = await Device.findByIdAndDelete(deviceId);
    
    if (!device) {
      return res.status(404).json({ error: "Device not found" });
    }
    
    res.json({
      success: true,
      message: "Device deleted successfully",
      deletedDevice: {
        id: device._id,
        name: device.name,
        ip: device.ip
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Failed to delete device", 
      details: error.message 
    });
  }
};

// Get security summary for all devices
export const getSecuritySummary = async (req, res) => {
  try {
    const devices = await Device.find();
    
    const summary = {
      totalDevices: devices.length,
      byManufacturer: {},
      byRiskLevel: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      commonVulnerabilities: {},
      devicesWithoutHTTPS: 0,
      devicesWithRTSP: 0,
      averageOpenPorts: 0
    };
    
    let totalPorts = 0;
    
    devices.forEach(device => {
      // Count by manufacturer
      summary.byManufacturer[device.manufacturer] = 
        (summary.byManufacturer[device.manufacturer] || 0) + 1;
      
      // Count by risk level
      if (device.securityAudit?.riskLevel) {
        summary.byRiskLevel[device.securityAudit.riskLevel]++;
      }
      
      // Count vulnerabilities
      device.vulnerabilities?.forEach(vuln => {
        summary.commonVulnerabilities[vuln.type] = 
          (summary.commonVulnerabilities[vuln.type] || 0) + 1;
      });
      
      // Count devices without HTTPS
      if (!device.openPorts.includes(443)) {
        summary.devicesWithoutHTTPS++;
      }
      
      // Count devices with RTSP
      if (device.openPorts.includes(554)) {
        summary.devicesWithRTSP++;
      }
      
      // Calculate average open ports
      totalPorts += device.openPorts.length;
    });
    
    summary.averageOpenPorts = devices.length > 0 
      ? (totalPorts / devices.length).toFixed(1) 
      : 0;
    
    res.json({
      success: true,
      summary
    });
  } catch (error) {
    res.status(500).json({ 
      error: "Failed to generate security summary", 
      details: error.message 
    });
  }
};