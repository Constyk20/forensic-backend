import express from "express";
import { 
  analyzeEvidence, 
  generateReport,
  listEvidence,
  getEvidenceDetails
} from "../controllers/analysisController.js";

const router = express.Router();

// Analyze evidence
router.post("/analyze", analyzeEvidence);

// Generate forensic report
router.get("/report/:evidenceId", generateReport);

// List all evidence with optional filters
router.get("/evidence", listEvidence);

// Get detailed evidence information
router.get("/evidence/:evidenceId", getEvidenceDetails);

export default router;