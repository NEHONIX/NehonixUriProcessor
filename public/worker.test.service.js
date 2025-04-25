import { NehonixSecurityService } from "./NehonixSecurity.service.js";
console.log("test running")
// const NehonixSecurityService = require("./NehonixSecurity.service.js");

async function testWorker() {
  try {
    // Test with a Base64-encoded URL
    const decoded = await NehonixSecurityService.autoDetectAndDecodeAsync(
      "aHR0cHM6Ly9leGFtcGxlLmNvbQ==",
      { useWorker: true, maxIterations: 10, timeout: 5000 }
    );
    console.log("Decoded:", decoded);

    // Test with a percent-encoded URL
    const decoded2 = await NehonixSecurityService.autoDetectAndDecodeAsync(
      "https%3A%2F%2Fexample.com%2Fpath%3Fquery%3Dvalue",
      { useWorker: true, maxIterations: 10, timeout: 5000 }
    );
    console.log("Decoded:", decoded2);
  } catch (error) {
    console.error("Error:", error);
  }
}

testWorker();
