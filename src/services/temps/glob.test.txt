/**
 * NOTE: This test was wrotten by claud (Anthropic ai) for a full testing
 * Test suite for NehonixURIProcessor
 * Testing various decoding scenarios from simple to complex
 */ import NDS from "../services/NehonixDec.service";

// Simple test runner
function runTests() {
  let passedTests = 0;
  let failedTests = 0;
  const failedDetails: string[] = [];

  function assertEqual(actual: string, expected: string, testName: string) {
    if (
      actual.toLocaleLowerCase().trim() === expected.toLocaleLowerCase().trim()
    ) {
      console.log(`✓ PASS: ${testName}`);
      passedTests++;
      return true;
    } else {
      console.log(`✗ FAIL: ${testName}`);
      console.log(`  Expected: ${expected}`);
      console.log(`  Received: ${actual}`);
      failedTests++;
      failedDetails.push(testName);
      return false;
    }
  }

  // Simple encoding tests
  console.log("\n--- Basic Single Encoding Tests ---");

  // Test base64 decoding
  {
    const b64Input = "aHR0cHM6Ly9hcHAuY2hhcmlvdy5jb20vYXV0aC9sb2dpbj90ZXN0";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: b64Input, encodingType: "base64" }),
      expected,
      "Should decode base64 correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(b64Input),
      expected,
      "Should decode base64 correctly (auto-detect)"
    );
  }

  // Test ASCII octal decoding
  {
    const octInput =
      "\150\164\164\160\163\72\57\57\141\160\160\56\143\150\141\162\151\157\167\56\143\157\155\57\141\165\164\150\57\154\157\147\151\156\77\164\145\163\164";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: octInput, encodingType: "asciioct" }),
      expected,
      "Should decode ASCII octal code correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(octInput),
      expected,
      "Should decode ASCII octal code correctly (auto-detect)"
    );
  }

  // Test ASCII hex decoding
  {
    const hexInput =
      "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x61\x70\x70\x2e\x63\x68\x61\x72\x69\x6f\x77\x2e\x63\x6f\x6d\x2f\x61\x75\x74\x68\x2f\x6c\x6f\x67\x69\x6e\x3f\x74\x65\x73\x74";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: hexInput, encodingType: "asciihex" }),
      expected,
      "Should decode ASCII hex code correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(hexInput),
      expected,
      "Should decode ASCII hex code correctly (auto-detect)"
    );
  }

  // Test Unicode decoding
  {
    const unicodeInput =
      "\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002f\u0061\u0070\u0070\u002e\u0063\u0068\u0061\u0072\u0069\u006f\u0077\u002e\u0063\u006f\u006d\u002f\u0061\u0075\u0074\u0068\u002f\u006c\u006f\u0067\u0069\u006e\u003f\u0074\u0065\u0073\u0074";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: unicodeInput, encodingType: "unicode" }),
      expected,
      "Should decode Unicode correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(unicodeInput),
      expected,
      "Should decode Unicode correctly (auto-detect)"
    );
  }

  // Test hex string decoding
  {
    const rawHexInput =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
    const expected = "https://app.chariow.com/auth/login?test";
    console.log("tes: ", NDS.decodeAnyToPlaintext(rawHexInput));
    assertEqual(
      NDS.decode({ input: rawHexInput, encodingType: "hex" }),
      expected,
      "Should decode hex string correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rawHexInput),
      expected,
      "Should decode hex string correctly (auto-detect)"
    );
  }

  // Test URL encoding decoding
  {
    const urlInput = "https%3A%2F%2Fapp.chariow.com%2Fauth%2Flogin%3Ftest";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: urlInput, encodingType: "percentEncoding" }),
      expected,
      "Should decode URL encoding correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(urlInput),
      expected,
      "Should decode URL encoding correctly (auto-detect)"
    );
  }

  // Test HTML entities decoding
  {
    const htmlInput =
      "https&#58;&#47;&#47;app&#46;chariow&#46;com&#47;auth&#47;login&#63;test";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: htmlInput, encodingType: "htmlEntity" }),
      expected,
      "Should decode HTML entities correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(htmlInput),
      expected,
      "Should decode HTML entities correctly (auto-detect)"
    );
  }

  // Test rot13 decoding
  {
    const rot13Input = "uggcf://ncc.punevbj.pbz/nhgu/ybtva?grfg";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decode({ input: rot13Input, encodingType: "rot13" }),
      expected,
      "Should decode rot13 correctly (specific method)"
    );
    assertEqual(
      NDS.decodeAnyToPlaintext(rot13Input),
      expected,
      "Should decode rot13 correctly (auto-detect)"
    );
  }

  // Nested encoding tests
  console.log("\n--- Nested Encoding Tests ---");

  // Test double-nested base64
  {
    const doubleB64 =
      "YUhSMGNITTZMeTloY0hBdVkyaGhjbWx2ZHk1amIyMHZZWFYwYUM5c2IyZHBiajkwWlhOMQ==";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(doubleB64),
      expected,
      "Should decode double-nested base64"
    );
  }

  // Test URL encoding within base64
  {
    const urlInB64 =
      "aHR0cHMlM0ElMkYlMkZhcHAuY2hhcmlvdy5jb20lMkZhdXRoJTJGbG9naW4lM0Z0ZXN0";
    const expected = "https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlInB64),
      expected,
      "Should decode URL encoding within base64"
    );
  }

  // Test hex within URL encoding
  {
    const hexInUrl =
      "68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374%3D";
    const expected = "https://app.chariow.com/auth/login?test=";

    assertEqual(
      NDS.decodeAnyToPlaintext(hexInUrl),
      expected,
      "Should decode hex within URL encoding"
    );
  }

  // Test triple-nested encodings
  {
    const tripleNested = "ZUhKMFkzTTBNQSUzRCUzRA==";
    const expected = "test";

    assertEqual(
      NDS.decodeAnyToPlaintext(tripleNested),
      expected,
      "Should decode triple-nested encodings"
    );
  }

  // URL parameter tests
  console.log("\n--- URL Parameter Tests ---");

  // Test simple URL with encoded parameter
  {
    const urlWithEncodedParam =
      "https://app.chariow.com/stores?test=https%3A%2F%2Fapp.chariow.com%2Fauth%2Flogin%3Ftest";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithEncodedParam),
      expected,
      "Should decode simple URL with encoded parameter"
    );
  }

  // Test URL with hex encoded parameter value
  {
    const urlWithHexParam =
      "https://app.chariow.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithHexParam),
      expected,
      "Should decode URL with hex encoded parameter value"
    );
  }

  // Test URL with base64 encoded parameter
  {
    const urlWithB64Param =
      "https://app.chariow.com/stores?encoded=aHR0cHM6Ly9hcHAuY2hhcmlvdy5jb20vYXV0aC9sb2dpbj90ZXN0";
    const expected =
      "https://app.chariow.com/stores?encoded=https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithB64Param),
      expected,
      "Should decode URL with base64 encoded parameter"
    );
  }

  // Edge cases and complex scenarios
  console.log("\n--- Edge Cases and Complex Scenarios ---");

  // Test handling plaintext
  {
    const plaintext = "https://app.chariow.com/auth/login?test";
    assertEqual(
      NDS.decodeAnyToPlaintext(plaintext),
      plaintext,
      "Should handle plaintext correctly"
    );
  }

  // Test handling invalid encodings
  {
    const invalidB64 = "aHR0cHM6Ly9hcHAuY2h@#$%wy5jb20v";
    assertEqual(
      NDS.decodeAnyToPlaintext(invalidB64),
      invalidB64,
      "Should handle invalid encodings gracefully"
    );
  }

  // Test handling partial encodings
  {
    const partialEncoded = "Visit https%3A%2F%2Fapp.chariow.com for more info";
    const expected = "Visit https://app.chariow.com for more info";

    assertEqual(
      NDS.decodeAnyToPlaintext(partialEncoded),
      expected,
      "Should handle partial encodings in strings"
    );
  }

  // Target test cases
  console.log("\n--- Target Test Cases ---");

  // Test handling urlWithBasicEnc
  {
    const urlWithBasicEnc =
      "https://app.chariow.com/stores?test=https%3A%2F%2Fapp.chariow.com%2Fauth%2Flogin%3Ftest";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithBasicEnc),
      expected,
      "Should handle urlWithBasicEnc correctly"
    );
  }

  // Test handling urlWithComplexEnc1
  {
    const urlWithComplexEnc1 =
      "https://app.chariow.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithComplexEnc1),
      expected,
      "Should handle urlWithComplexEnc1 correctly"
    );
  }

  // Test handling urlWithComplexEnc2
  {
    const urlWithComplexEnc2 =
      "https://app.chariow.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374&&test2=https%3A%2F%2Fapp.chariow.com%2Fauth%2Flogin%3Ftes";
    const expected =
      "https://app.chariow.com/stores?test=https://app.chariow.com/auth/login?test&&test2=https://app.chariow.com/auth/login?tes";

    assertEqual(
      NDS.decodeAnyToPlaintext(urlWithComplexEnc2),
      expected,
      "Should handle urlWithComplexEnc2 correctly"
    );
  }

  // Print summary
  console.log("\n=== Test Summary ===");
  console.log(`Tests passed: ${passedTests}`);
  console.log(`Tests failed: ${failedTests}`);

  if (failedTests > 0) {
    console.log("\nFailed tests:");
    failedDetails.forEach((name, i) => {
      console.log(`${i + 1}. ${name}`);
    });
    process.exit(1);
  }
}

// Run all tests
runTests();
