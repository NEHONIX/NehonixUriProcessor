import express from "express";
import { nehonixShieldMiddleware, scanRequest } from "nehonix-uri-processor";

const app = express();
app.use(nehonixShieldMiddleware({ blockOnMalicious: true }));
app.get("/", (req, res) => {
  scanRequest(req, ["url"]);
  res.status(200).json({
    msg: "Hello world",
  });
});
app.listen(3000, () => console.log("Server running on port 3000"));
