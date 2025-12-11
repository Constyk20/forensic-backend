import express from "express";
import { acquireEvidence } from "../controllers/evidenceController.js";

const router = express.Router();

router.post("/acquire", acquireEvidence);

export default router;
