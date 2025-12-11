import Device from "../models/Device.js";

export const discoverDevices = async (req, res) => {
  // Fake CCTV devices for testing
  const devices = [
    { name: "FakeCam 1", ip: "192.168.1.10", model: "SimCam-X" },
    { name: "FakeCam 2", ip: "192.168.1.11", model: "SimCam-Y" }
  ];

  // Save to DB (optional)
  await Device.deleteMany({});
  await Device.insertMany(devices);

  res.json({ success: true, devices });
};

export const listDevices = async (req, res) => {
  const devices = await Device.find();
  res.json(devices);
};
