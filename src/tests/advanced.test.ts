import { NAISE } from "../services/NehonixAISecurityEnhancer";
import { NSB } from "../services/NehonixSecurityBooster.service";
import {
  MaliciousPatternOptions,
  MaliciousPatternResult,
  MaliciousPatternType,
} from "../services/MaliciousPatterns.service";
import { spawn } from "child_process";


// Test cases
const testCases = [
  {
    url: "http://malicious.example.com/login?payload=%252e%252e%2f",
    expectedMalicious: true,
    expectedPatterns: ["ANOMALY_DETECTED", "SUSPICIOUS_DOMAIN", "KNOWN_THREAT"],
    description: "Malicious URL with encoded path traversal",
  },
  {
    url: "https://google.com",
    expectedMalicious: false,
    expectedPatterns: [],
    description: "Benign URL",
  },
  {
    url: "http://127.0.0.1:8080/admin?sql=SELECT%20*%20FROM%20users",
    expectedMalicious: true,
    expectedPatterns: ["ANOMALY_DETECTED", "SUSPICIOUS_IP"],
    description: "Localhost with SQL injection attempt",
  },
  {
    url: "http://phishing.site/verify?token=base64encodeddatahere==",
    expectedMalicious: true,
    expectedPatterns: ["ANOMALY_DETECTED", "KNOWN_THREAT"],
    description: "Phishing URL with Base64 encoding",
  },
  {
    url: "ftp://invalid:port/path",
    expectedMalicious: true,
    expectedPatterns: ["ANOMALY_DETECTED"],
    description: "Invalid protocol and port",
  },
];

// Test runner
// async function runTests() {
//   console.log("Starting NAISE tests...");
//   let passed = 0;
//   let total = 0;

//   // Initialize NAISE
//   const naise = NAISE.getInstance();
//   NAISE.integrateWithNSB();

//   // Test 1: URL Analysis
//   console.log("\n=== Test 1: URL Analysis ===");
//   for (const {
//     url,
//     expectedMalicious,
//     expectedPatterns,
//     description,
//   } of testCases) {
//     total++;
//     console.log(`Testing: ${description} (${url})`);
//     try {
//       const options: MaliciousPatternOptions = { minScore: 50 };
//       const basicResult: MaliciousPatternResult = {
//         url,
//         score: 0,
//         isMalicious: false,
//         detectedPatterns: [],
//         confidence: "low",
//         recommendation: "Initial analysis",
//       };

//       const result = await naise.enhanceUrlAnalysis(url, basicResult, options);

//       const detectedPatternTypes = result.detectedPatterns.map((p) => p.type);
//       const patternsMatch = expectedPatterns.every((p) =>
//         detectedPatternTypes.includes(p as MaliciousPatternType)
//       );
//       const passedTest =
//         result.url === url &&
//         result.isMalicious === expectedMalicious &&
//         result.score >= 0 &&
//         result.score <= 1000 &&
//         ["low", "medium", "high"].includes(result.confidence) &&
//         patternsMatch &&
//         (result.isMalicious ? result.contextAnalysis != null : true);

//       console.log(`Result: ${passedTest ? "PASS" : "FAIL"}`);
//       console.log(
//         `- isMalicious: ${result.isMalicious} (expected: ${expectedMalicious})`
//       );
//       console.log(`- Score: ${result.score}`);
//       console.log(`- Patterns: ${detectedPatternTypes.join(", ")}`);
//       console.log(`- Confidence: ${result.confidence}`);
//       if (result.contextAnalysis) {
//         console.log(
//           `- Context: entropy=${result.contextAnalysis.entropyScore}, anomaly=${result.contextAnalysis.anomalyScore}`
//         );
//       }

//       if (passedTest) passed++;
//       else {
//         console.error(
//           `Failed: Expected patterns [${expectedPatterns}] but got [${detectedPatternTypes}]`
//         );
//       }
//     } catch (error) {
//       console.error(`Error: ${error.message}`);
//     }
//   }

//   // Test 2: Python ML Training
//   console.log("\n=== Test 2: Python ML Training ===");
//   total++;
//   try {
//     const trainingData = Array(100)
//       .fill(null)
//       .map((_, i) => ({
//         url: `http://test${i}.com`,
//         features: {
//           length: 50,
//           entropy: 4.0,
//           specialCharCount: 5,
//           digitCount: 2,
//           encodedCharCount: 0,
//           subdomainLevels: 1,
//           parameterCount: 0,
//           pathDepth: 1,
//           hasUnusualPort: false,
//           containsIPAddress: false,
//           hexEncodingRatio: 0,
//           domainLength: 10,
//           tld: "com",
//           hasBase64: false,
//         },
//         isMalicious: i % 2 === 0,
//         detectedPatternTypes: [],
//         score: i % 2 === 0 ? 80 : 20,
//         timestamp: Date.now(),
//       }));

//     (naise as any).trainingData = trainingData;
//     (naise as any).lastTrainingTime = 0;
//     await (naise as any).trainMLModel();

//     const trainingDataCleared = (naise as any).trainingData.length === 0;
//     console.log(`Result: ${trainingDataCleared ? "PASS" : "FAIL"}`);
//     console.log(`- Training data cleared: ${trainingDataCleared}`);
//     if (trainingDataCleared) passed++;
//     else console.error("Failed: Training data not cleared");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Test 3: Python ML Prediction
//   console.log("\n=== Test 3: Python ML Prediction ===");
//   total++;
//   try {
//     const url = "http://test.com";
//     const features = {
//       length: 50,
//       entropy: 4.0,
//       specialCharCount: 5,
//       digitCount: 2,
//       encodedCharCount: 0,
//       subdomainLevels: 1,
//       parameterCount: 0,
//       pathDepth: 1,
//       hasUnusualPort: false,
//       containsIPAddress: false,
//       hexEncodingRatio: 0,
//       domainLength: 10,
//       tld: "com",
//       hasBase64: false,
//     };

//     const probability = await (naise as any).predictThreatProbability(
//       url,
//       features
//     );
//     const validProbability = probability >= 0 && probability <= 1;
//     console.log(`Result: ${validProbability ? "PASS" : "FAIL"}`);
//     console.log(`- Probability: ${probability}`);
//     if (validProbability) passed++;
//     else console.error("Failed: Invalid probability value");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Test 4: Threat Intelligence
//   console.log("\n=== Test 4: Threat Intelligence ===");
//   total++;
//   try {
//     const threats = await (naise as any).fetchExternalThreats();
//     const hasLocalBlocklist = threats.some(
//       (t: any) => t.key === "malicious.example.com"
//     );
//     console.log(`Result: ${hasLocalBlocklist ? "PASS" : "FAIL"}`);
//     console.log(`- Threats fetched: ${threats.length}`);
//     if (hasLocalBlocklist) passed++;
//     else console.error("Failed: Local blocklist not included");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Test 5: DBSCAN Clustering
//   console.log("\n=== Test 5: DBSCAN Clustering ===");
//   total++;
//   try {
//     const trainingData = Array(20)
//       .fill(null)
//       .map((_, i) => ({
//         url: `http://malicious${i}.com`,
//         features: {
//           length: 100,
//           entropy: 5.0 + i * 0.1,
//           specialCharCount: 20,
//           digitCount: 5,
//           encodedCharCount: 10,
//           subdomainLevels: 2,
//           parameterCount: 3,
//           pathDepth: 2,
//           hasUnusualPort: false,
//           containsIPAddress: false,
//           hexEncodingRatio: 0.1,
//           domainLength: 15,
//           tld: "com",
//           hasBase64: false,
//         },
//         isMalicious: true,
//         detectedPatternTypes: ["ANOMALY_DETECTED"],
//         score: 80,
//         timestamp: Date.now(),
//       }));

//     (naise as any).trainingData = trainingData;
//     await (naise as any).updateZeroKnowledgePatterns();

//     const clusters = (naise as any).zeroKnowledgePatterns.patternClusters;
//     const hasClusters = clusters.length > 0;
//     console.log(`Result: ${hasClusters ? "PASS" : "FAIL"}`);
//     console.log(`- Clusters created: ${clusters.length}`);
//     if (hasClusters) passed++;
//     else console.error("Failed: No clusters created");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Test 6: NSB Integration
//   console.log("\n=== Test 6: NSB Integration ===");
//   total++;
//   try {
//     const url = "http://malicious.example.com";
//     const result = await NSB.analyzeUrl(url);
//     const enhanced = result.detectedPatterns.length >= 0 && result.url === url;
//     console.log(`Result: ${enhanced ? "PASS" : "FAIL"}`);
//     console.log(`- Patterns detected: ${result.detectedPatterns.length}`);
//     if (enhanced) passed++;
//     else console.error("Failed: NSB integration not enhancing URL analysis");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Test 7: Python Environment
//   console.log("\n=== Test 7: Python Environment ===");
//   total++;
//   try {
//     const pythonProcess = spawn("python", [NAISE.ml_path]);
//     let errorOutput = "";
//     let completed = false;

//     pythonProcess.stderr.on("data", (chunk) => {
//       errorOutput += chunk.toString();
//     });

//     pythonProcess.on("close", (code) => {
//       completed = true;
//       const passedTest = code === 0 || errorOutput.includes("Invalid command");
//       console.log(`Result: ${passedTest ? "PASS" : "FAIL"}`);
//       console.log(`- Exit code: ${code}`);
//       if (passedTest) passed++;
//       else console.error(`Failed: Python process error: ${errorOutput}`);
//     });

//     pythonProcess.on("error", (err) => {
//       console.error(`Error: ${err.message}`);
//     });

//     pythonProcess.stdin.write(JSON.stringify({ command: "test" }));
//     pythonProcess.stdin.end();

//     // Wait for process to complete
//     await new Promise((resolve) => setTimeout(resolve, 1000));
//     if (!completed)
//       console.error("Warning: Python process did not complete in time");
//   } catch (error) {
//     console.error(`Error: ${error.message}`);
//   }

//   // Summary
//   console.log("\n=== Test Summary ===");
//   console.log(`Passed: ${passed}/${total}`);
//   console.log(
//     `Status: ${passed === total ? "All tests passed!" : "Some tests failed."}`
//   );
// }

// runTests().catch((error) => console.error("Test runner error:", error));
async function testPythonMLTraining() {
  const trainingData = {
    command: "train",
    inputs: [
      // Malicious URL features (high entropy, special chars, suspicious domain)
      [4.5, 100, 3, 10, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1], // Encoded path traversal
      [4.8, 120, 2, 15, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1], // SQL injection
      [4.3, 90, 2, 12, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1], // Phishing with Base64
      [3.6, 50, 1, 8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1], // Invalid protocol
      // Benign URL features (low entropy, trusted domain)
      [3.5, 30, 1, 2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0], // google.com
      [3.2, 25, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0], // Other benign
    ],
    outputs: [[1], [1], [1], [1], [0], [0]], // 1 = malicious, 0 = benign
  };
  const pythonProcess = spawn("python", [NAISE.ml_path], { timeout: 10000 });
  const [stdout, stderr] = await new Promise((resolve) => {
    let stdout = "",
      stderr = "";
    pythonProcess.stdin.write(JSON.stringify(trainingData));
    pythonProcess.stdin.end();
    pythonProcess.stdout.on("data", (data) => (stdout += data));
    pythonProcess.stderr.on("data", (data) => (stderr += data));
    pythonProcess.on("close", () => resolve([stdout, stderr]));
  }) as any;
  console.log(
    "[DEBUG] Training Output:",
    stdout,
    "[DEBUG] Training Error:",
    stderr
  );
  return stdout.includes("Model trained");
}


testPythonMLTraining()
  .then((result) => console.log("Test Result:", result))
  .catch((error) => console.error("Test Error:", error));