import express from "express";
import { 
  acquireEvidence,
  exportEvidence,
  verifyEvidenceIntegrity,
  listEvidence,
  getEvidenceById,
  updateEvidence,
  deleteEvidence,
  getEvidenceByCase,
  bulkVerifyIntegrity
} from "../controllers/evidenceController.js";

const router = express.Router();

// ==================== Core Evidence Operations ====================

/**
 * POST /api/evidence/acquire
 * Acquire new evidence from a device with full chain of custody
 * Body: { deviceId, type, caseNumber, investigator, notes }
 */
router.post("/acquire", acquireEvidence);

/**
 * GET /api/evidence/verify/:evidenceId
 * Verify evidence integrity using cryptographic hash comparison
 * Optional Body: { investigator }
 */
router.get("/verify/:evidenceId", verifyEvidenceIntegrity);

/**
 * GET /api/evidence/export/:evidenceId
 * Export evidence with complete forensic documentation
 */
router.get("/export/:evidenceId", exportEvidence);

// ==================== Evidence Management ====================

/**
 * GET /api/evidence
 * List all evidence with optional filtering
 * Query params: caseNumber, type, analyzed, deviceId, status, investigator
 */
router.get("/", listEvidence);

/**
 * GET /api/evidence/:evidenceId
 * Get detailed information about specific evidence
 */
router.get("/:evidenceId", getEvidenceById);

/**
 * PUT /api/evidence/:evidenceId
 * Update evidence metadata (notes, tags, status, etc.)
 * Body: { notes, tags, status, investigator, ... }
 */
router.put("/:evidenceId", updateEvidence);

/**
 * DELETE /api/evidence/:evidenceId
 * Delete evidence (with proper authorization)
 * Query params: ?permanent=true (for permanent deletion)
 */
router.delete("/:evidenceId", deleteEvidence);

// ==================== Case-Specific Operations ====================

/**
 * GET /api/evidence/case/:caseNumber
 * Get all evidence for a specific case
 */
router.get("/case/:caseNumber", getEvidenceByCase);

// ==================== Bulk Operations ====================

/**
 * POST /api/evidence/bulk-verify
 * Verify integrity of multiple evidence items
 * Body: { evidenceIds: [...], investigator }
 */
router.post("/bulk-verify", bulkVerifyIntegrity);

export default router;