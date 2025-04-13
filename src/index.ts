import { NehonixEncService as enc } from "./services/NehonixEnc.service";
import { SecurityRules as sr } from "./rules/security.rules";
import { NehonixDecService as dec } from "./services/NehonixDec.service";
import { ENC_TYPE } from "./types";

/**
 * URI Encoding Detector and Decoder
 * A comprehensive library to detect and decode different types of URI encoding
 * Useful for security testing and attack analysis
 */

export class NehonixURIProcessor {
  //methods
  static generateWAFBypassVariants(input: string) {
    return sr.generateWAFBypassVariants(input);
  }

  static analyzeURL(input: string) {
    return sr.analyzeURL(input);
  }

  static encode(input: string, encodingType: ENC_TYPE) {
    return enc.encode(input, encodingType);
  }

  static detectEncoding(input: string, depth?: number) {
    return dec.detectEncoding(input, depth);
  }
  static detectAndDecode(input: string) {
    return dec.detectAndDecode(input);
  }

  static decode(
    input: string,
    encodingType: ENC_TYPE,
    maxRecursionDepth?: number
  ) {
    return dec.decode(input, encodingType, maxRecursionDepth);
  }
}
// export
