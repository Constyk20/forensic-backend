import express from "express";
import { analyzeEvidence } from "../controllers/analysisController.js";

const router = express.Router();

router.post("/run", analyzeEvidence);

export default router;
