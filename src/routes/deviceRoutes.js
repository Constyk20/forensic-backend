import express from "express";
import { discoverDevices, listDevices } from "../controllers/deviceController.js";

const router = express.Router();

router.get("/discover", discoverDevices);
router.get("/", listDevices);

export default router;
