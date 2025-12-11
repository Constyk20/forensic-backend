import express from "express";
import { 
  discoverDevices, 
  listDevices,
  getDeviceDetails,
  updateDevice,
  deleteDevice,
  getSecuritySummary
} from "../controllers/deviceController.js";

const router = express.Router();

// Discover devices on network (POST for body params)
router.post("/discover", discoverDevices);

// List all devices with optional filters
router.get("/", listDevices);

// Get security summary across all devices
router.get("/security-summary", getSecuritySummary);

// Get specific device details with associated evidence
router.get("/:deviceId", getDeviceDetails);

// Update device information
router.put("/:deviceId", updateDevice);

// Delete device
router.delete("/:deviceId", deleteDevice);

export default router;