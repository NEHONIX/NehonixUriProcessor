/**
 * NOTE: This test was wrotten by claud (Anthropic ai) for a full testing
 * Test suite for NehonixURIProcessor
 * Testing various decoding scenarios from simple to complex
 */ import { NehonixURIProcessor } from "..";
import NDS from "../services/NehonixDec.service";

const originalUrl =
  "https://nehonix.space?test=true&p2=hello world, I'm testing";

// Simple test runner
function runTests() {
  function dec(inp: string) {
    const x = NDS.decodeAnyToPlaintext(inp);
    return x;
  }
  {
    const testUri =
      "https://nehonix.space?test=true&p2=\u0068\u0065\u006c\u006c\u006f\u0020\u0077\u006f\u0072\u006c\u0064\u002c\u0020\u0049\u0027\u006d\u0020\u0074\u0065\u0073\u0074\u0069\u006e\u0067";
    console.log("Decoded 1: ", dec(testUri));
  }
  {
    const testUri =
      "https://example.com?param1=value1&param2=value2&param=value";
    console.log("Decoded 1: ", dec(testUri));
  }

  {
    const testUri =
      "https://nehonix.space?test=\x74\x72\x75\x65&p2=aGVsbG8gd29ybGQsIEknbSB0ZXN0aW5n&test2=65742068692062726f2075277265207573696e6720746865206c6962&ok=thank%20to%20nehonix&p2=\u0068\u0065\u006c\u006c\u006f\u0020\u0077\u006f\u0072\u006c\u0064\u002c\u0020\u0049\u0027\u006d\u0020\u0074\u0065\u0073\u0074\u0069\u006e\u0067";
    console.log("Decode 2:", dec(testUri));
  }
}

// Run all tests
runTests();
