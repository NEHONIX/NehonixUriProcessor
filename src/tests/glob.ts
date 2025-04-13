/**
 * This test cover a lot of methods in the NehonixUriProcessor class
 * Test suite for NehonixURIProcessor
 * This file contains various test cases for different encoding types and scenarios.
 */

import { NehonixURIProcessor } from "..";

const text =
  "https://app.chariow.com/stores?test=68747470733a2f2f6170702e63686172696f772e636f6d2f617574682f6c6f67696e3f74657374";
// const enc = NehonixURIProcessor.detectEncoding(text);
const enc_dec = NehonixURIProcessor.decode(text, "any");

// console.log("encoded detection res: ", enc);
console.log("encoded res: ", enc_dec);
