import { NehonixURIProcessor } from "..";
import { NSS } from "../services/NehonixSecurity.service";

// Test SQLi/XSS detection
async function runTest(input: string) {
  const result = await NehonixURIProcessor.asyncCheckUrl(input, {detectMaliciousPatterns: true, allowedProtocols: ["test"]});
  console.log(result);
  return result;
}

runTest("https://api.com/search?id=1;DROP TABLE users;");
