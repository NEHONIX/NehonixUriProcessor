/**
 * NOTE: Test has beeen generated by ChatGpt
 * This test cover a lot of methods in the NehonixUriProcessor class
 * Test suite for NehonixURIProcessor
 * This file contains various test cases for different encoding types and scenarios.
 */

import { NehonixURIProcessor } from "..";

// import { NehonixURIProcessor } from "..";

// import { NehonixURIProcessor } from "..";

// Helper function to run and display test results
function runTest(
  name: string,
  input: string,
  expectedType: string | null = null,
  expectError: boolean = false
): void {
  console.log(`\n=== Test: ${name} ===`);
  console.log(`Input: ${input}`);
  try {
    const detection = NehonixURIProcessor.detectEncoding(input);
    console.log(
      `Detected: ${
        detection.mostLikely
      } (Confidence: ${detection.confidence.toFixed(2)})`
    );
    if (expectedType && detection.mostLikely !== expectedType) {
      console.log(
        `⚠️ WARNING: Expected ${expectedType} but detected ${detection.mostLikely}`
      );
    }

    const decoded = NehonixURIProcessor.detectAndDecode(input);
    console.log(`Decoded: ${decoded.val}`);
    console.log(
      `Encoding: ${
        decoded.encodingType
      } (Confidence: ${decoded.confidence.toFixed(2)})`
    );
    if (decoded.nestedTypes) {
      console.log(
        `Nested encodings detected: ${decoded.nestedTypes.join(" -> ")}`
      );
    }

    console.log(
      expectError
        ? "❌ Test should have failed but didn't"
        : "✅ Test completed"
    );
  } catch (error: any) {
    if (expectError) {
      console.log("✅ Expected error occurred:", error.message);
    } else {
      console.error(`❌ Unexpected error: ${error.message}`);
    }
  }
}

// Basic URL Encoding Tests
console.log("\n🔍 URL ENCODING TESTS");
runTest(
  "Simple percent encoding",
  "https://example.com/search?q=hello%20world",
  "percentEncoding"
);
runTest(
  "Complex percent encoding",
  "https://example.com/path%2Fto%2Fresource%3Fquery%3Dvalue",
  "percentEncoding"
);
runTest(
  "Double percent encoding",
  "https://example.com/search?q=hello%2520world",
  "doublePercentEncoding"
);

// Base64 Encoding Tests
console.log("\n🔍 BASE64 ENCODING TESTS");
runTest("Simple Base64", "aGVsbG8gd29ybGQ=", "base64"); // "hello world"
runTest(
  "URL parameter with Base64",
  "https://example.com/api?data=aGVsbG8gd29ybGQ=",
  "base64"
);
runTest(
  "URL-safe Base64",
  "https://example.com/api?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "base64"
);

// Hexadecimal Encoding Tests
console.log("\n🔍 HEXADECIMAL ENCODING TESTS");
runTest(
  "Hex with \\x prefix",
  "Payload: \\x48\\x65\\x6c\\x6c\\x6f",
  "hexadecimal"
);
runTest(
  "Hex with 0x prefix",
  "Char codes: 0x48 0x65 0x6c 0x6c 0x6f",
  "hexadecimal"
);
runTest("Raw hexadecimal", "68656c6c6f20776f726c64", "rawHexadecimal"); // "hello world"
runTest(
  "URL with raw hex",
  "https://example.com/api?id=68656c6c6f20776f726c64",
  "rawHexadecimal"
);

// Unicode Encoding Tests
console.log("\n🔍 UNICODE ENCODING TESTS");
runTest(
  "Unicode escapes",
  "Text: \\u0048\\u0065\\u006c\\u006c\\u006f",
  "unicode"
);
runTest("Unicode with braces", "Emoji: \\u{1F600}", "unicode");

// HTML Entity Encoding Tests
console.log("\n🔍 HTML ENTITY ENCODING TESTS");
runTest(
  "Named HTML entities",
  "Text: &lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;",
  "htmlEntity"
);
runTest(
  "Numeric HTML entities",
  "Text: &#72;&#101;&#108;&#108;&#111;",
  "htmlEntity"
);
runTest(
  "Hex HTML entities",
  "Text: &#x48;&#x65;&#x6c;&#x6c;&#x6f;",
  "htmlEntity"
);

// Punycode Tests
console.log("\n🔍 PUNYCODE TESTS");
runTest("Punycode domain", "https://xn--80akhbyknj4f.xn--p1ai/", "punycode");

// JWT Tests
console.log("\n🔍 JWT TESTS");
runTest(
  "JWT Token",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  "jwt"
);

// Nested Encoding Tests
console.log("\n🔍 NESTED ENCODING TESTS");
runTest(
  "Percent encoded Base64",
  "https://example.com/api?data=%61%47%56%73%62%47%38%67%64%32%39%79%62%47%51%3D",
  "percentEncoding"
);
runTest(
  "Double percent encoded value",
  "https://example.com/search?q=%2568%2565%256c%256c%256f",
  "doublePercentEncoding"
);
runTest(
  "Base64 of percent encoded",
  "aHR0cHM6Ly9leGFtcGxlLmNvbS9zZWFyY2g/cT1oZWxsbyUyMHdvcmxk",
  "base64"
);

// WAF Bypass Tests
console.log("\n🔍 WAF BYPASS TESTS");
const wafBypassVariants = NehonixURIProcessor.generateWAFBypassVariants(
  "<script>alert(1)</script>"
);
console.log('\n=== WAF Bypass Variants for "<script>alert(1)</script>" ===');
Object.entries(wafBypassVariants).forEach(([technique, encoded]) => {
  console.log(`${technique}: ${encoded}`);
});

// URL Analysis Tests
console.log("\n🔍 URL ANALYSIS TESTS");
const urlToAnalyze =
  "https://example.com/search?q=test<script>&id=1234%27%20OR%201=1&path=../etc/passwd";
console.log("\n=== URL Analysis Test ===");
console.log(`URL: ${urlToAnalyze}`);
const analysis = NehonixURIProcessor.analyzeURL(urlToAnalyze);
console.log("Base URL:", analysis.baseURL);
console.log("Parameters:", analysis.parameters);
console.log("Potential Vulnerabilities:");
analysis.potentialVulnerabilities.forEach((vuln, index) => {
  console.log(`  ${index + 1}. ${vuln}`);
});

// Custom Encoding/Decoding Tests
console.log("\n🔍 CUSTOM ENCODING/DECODING TESTS");
const textToEncode = "Special characters: !@#$%^&*()";
console.log("\n=== Custom Encoding Test ===");
console.log(`Original: ${textToEncode}`);

const percentEncoded = NehonixURIProcessor.encode(
  textToEncode,
  "percentEncoding"
);
console.log(`Percent Encoded: ${percentEncoded}`);
console.log(
  `Decoded back: ${NehonixURIProcessor.decode(
    percentEncoded,
    "percentEncoding"
  )}`
);

const base64Encoded = NehonixURIProcessor.encode(textToEncode, "base64");
console.log(`Base64 Encoded: ${base64Encoded}`);
console.log(
  `Decoded back: ${NehonixURIProcessor.decode(base64Encoded, "base64")}`
);

const unicodeEncoded = NehonixURIProcessor.encode(textToEncode, "unicode");
console.log(`Unicode Encoded: ${unicodeEncoded}`);
console.log(
  `Decoded back: ${NehonixURIProcessor.decode(unicodeEncoded, "unicode")}`
);

// Edge Case Tests
console.log("\n🔍 EDGE CASE TESTS");
runTest(
  "Mixed encodings in URL",
  "https://example.com/path%20with%20spaces?q=aGVsbG8=&id=48656c6c6f"
);
runTest("Empty string", "");
runTest("Plain text", "Hello, this is just plain text!", "plainText");
runTest("Invalid Base64", "aGVsbG8gd#$%29ybGQ=");
runTest("Invalid percent encoding", "Text with invalid % encoding: %ZZ");
runTest("Malformed URL", "https://example.com/test[abc]");
runTest(
  "Very long nested encoding",
  "https://example.com/api?data=%2561%2547%2556%2573%2562%2547%2538%2567%2564%2532%2539%2579%2562%2547%2551%253D"
);

console.log("\n✅ All tests completed");
