import { NehonixEncService as enc } from "./services/NehonixEnc.service";
import { SecurityRules as sr } from "./rules/security.rules";
import { NehonixDecService as dec } from "./services/NehonixDec.service";
import { DEC_FEATURE_TYPE, ENC_TYPE } from "./types";

/**
 * URI Encoding Detector and Decoder
 * A comprehensive library to detect and decode different types of URI encoding
 * Useful for security testing and attack analysis
 */

export class NehonixURIProcessor {
  /**
   * Generates encoding variants of a string for WAF bypass testing
   * @param input The string to encode
   * @returns An object containing different encoding variants
   */
  static generateWAFBypassVariants(input: string) {
    return sr.generateWAFBypassVariants(input);
  }

  /**
   * Analyzes a URL and extracts potentially vulnerable parameters
   * @param url The URL to analyze
   * @returns An object containing information about the URL and parameters
   */
  static analyzeURL(input: string) {
    return sr.analyzeURL(input);
  }
  /**
   * Encodes a string according to a specific encoding type
   * @param input The string to encode
   * @param encodingType The encoding type to use
   * @returns The encoded string
   */
  static encode(input: string, encodingType: ENC_TYPE) {
    return enc.encode(input, encodingType);
  }

  /**
   * Automatically detects the encoding type of a URI string
   * @param input The URI string to analyze
   * @returns An object containing the detected encoding types and their probability
   */
  static detectEncoding(input: string, depth?: number) {
    return dec.detectEncoding(input, depth);
  }
  /**
   * Automatically detects and decodes a URI based on the detected encoding type with increased precision
   * @version 1.1.1
   * @param input The URI string to decode
   * @returns The decoded string according to the most probable encoding type
   */
  static autoDetectAndDecode(input: string) {
    return dec.decodeAnyToPlaintext(input);
  }

  /**
   * Automatically detects and decodes a URI based on the detected encoding type
   * @param input The URI string to decode
   * @returns The decoded string according to the most probable encoding type
   */
  static detectAndDecode(input: string) {
    return dec.detectAndDecode(input);
  }
  /**
   * Decodes a string according to a specific encoding type
   * @param input The string to decode
   * @param encodingType The encoding type to use
   * @returns The decoded string
   */
  static decode(
    input: string,
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE,
    maxRecursionDepth?: number
  ) {
    return dec.decode({
      input,
      encodingType,
      maxRecursionDepth,
    });
  }
}
export { NehonixURIProcessor as NURIP };
// export default NehonixURIProcessor;
