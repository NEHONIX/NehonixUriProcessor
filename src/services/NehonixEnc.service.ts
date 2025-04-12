import { ENC_TYPE } from "../types";
import punycode from "punycode";
import { NehonixCoreUtils } from "../utils/NehonixCoreUtils";
class NES {
  private static NCU: typeof NehonixCoreUtils = NehonixCoreUtils;
  private static hasBase64Pattern = NES.NCU.hasBase64Pattern;
  private static decodeBase64 = NES.NCU.drwp;

  /**
   * Encodes a string according to a specific encoding type
   * @param input The string to encode
   * @param encodingType The encoding type to use
   * @returns The encoded string
   */
  static encode(input: string, encodingType: ENC_TYPE): string {
    try {
      switch (encodingType.toLowerCase()) {
        case "percent":
        case "percentencoding":
        case "url":
          return NES.encodePercentEncoding(input);
        case "doublepercent":
        case "doublepercentencoding":
          return NES.encodeDoublePercentEncoding(input);
        case "base64":
          return NES.encodeBase64(input);
        case "hex":
        case "hexadecimal":
          return NES.encodeHex(input);
        case "unicode":
          return NES.encodeUnicode(input);
        case "htmlentity":
        case "html":
          return NES.encodeHTMLEntities(input);
        case "punycode":
          return NES.encodePunycode(input);
        case "asciihex":
          return NES.encodeASCIIWithHex(input);
        case "asciioct":
          return NES.encodeASCIIWithOct(input);
        default:
          throw new Error(`Unsupported encoding type: ${encodingType}`);
      }
    } catch (e: any) {
      console.error(`Error while encoding (${encodingType}):`, e);
      throw e;
    }
  }

  // =============== ENCODING METHODS ===============

  /**
   * Encodes with percent encoding (URL)
   */
  static encodePercentEncoding(input: string, encodeSpaces = false): string {
    let encoded = encodeURIComponent(input);

    // If requested, convert spaces to %20 instead of +
    if (encodeSpaces) {
      encoded = encoded.replace(/\+/g, "%20");
    }

    return encoded;
  }

  /**
   * Encodes with double percent encoding
   */
  static encodeDoublePercentEncoding(input: string): string {
    // First encoding
    const firstPass = NES.encodePercentEncoding(input, true);

    // Second encoding (converts % to %25)
    return firstPass.replace(/%/g, "%25");
  }

  /**
   * Encodes in base64
   */
  static encodeBase64(input: string): string {
    try {
      // Node.js
      if (typeof Buffer !== "undefined") {
        return Buffer.from(input).toString("base64");
      }
      // Browser
      else {
        return btoa(input);
      }
    } catch (e: any) {
      // For non-ASCII characters in browser
      if (e.name === "InvalidCharacterError") {
        // Convert to UTF-8 before encoding
        const bytes = new TextEncoder().encode(input);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
      }
      throw new Error(`Base64 encoding failed: ${e.message}`);
    }
  }

  /**
   * Encodes in hexadecimal (format \xXX)
   */
  static encodeHex(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const hex = input.charCodeAt(i).toString(16).padStart(2, "0");
      result += `\\x${hex}`;
    }
    return result;
  }

  /**
   * Encodes in Unicode (format \uXXXX)
   */
  static encodeUnicode(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;

      // For characters that require more than 4 hex digits
      if (cp > 0xffff) {
        result += `\\u{${cp.toString(16)}}`;
        // Skip the next element for surrogate pairs
        if (cp > 0xffff) i++;
      } else {
        result += `\\u${cp.toString(16).padStart(4, "0")}`;
      }
    }
    return result;
  }

  /**
   * Encodes in HTML entities
   */
  static encodeHTMLEntities(input: string): string {
    const entities: { [key: string]: string } = {
      "<": "&lt;",
      ">": "&gt;",
      "&": "&amp;",
      '"': "&quot;",
      "'": "&apos;",
      " ": "&nbsp;",
      // Add other characters if needed
    };

    let result = "";
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      result += entities[char] || char;
    }

    return result;
  }

  /**
   * Encodes in punycode
   * Note: Requires the 'punycode' library
   */
  static encodePunycode(input: string): string {
    try {
      // If the punycode module is available
      if (typeof require !== "undefined") {
        return `xn--${punycode.encode(input)}`;
      } else {
        // Alternative for browser (not implemented)
        console.warn(
          "Punycode module not available, punycode encoding not performed"
        );
        return input;
      }
    } catch (e: any) {
      throw new Error(`Punycode encoding failed: ${e.message}`);
    }
  }

  /**
   * Encodes in ASCII with hexadecimal representation
   */
  static encodeASCIIWithHex(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const code = input.charCodeAt(i);
      result += `\\x${code.toString(16).padStart(2, "0")}`;
    }
    return result;
  }

  /**
   * Encodes in ASCII with octal representation
   */
  static encodeASCIIWithOct(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const code = input.charCodeAt(i);
      result += `\\${code.toString(8).padStart(3, "0")}`;
    }
    return result;
  }

  /**
   * Encodes all characters in percent encoding
   * Useful for WAF bypasses
   */
  static encodeAllChars(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const hex = input.charCodeAt(i).toString(16).padStart(2, "0");
      result += `%${hex}`;
    }
    return result;
  }

  /**
   * Calculates confidence level for base64 encoding
   */
  static calculateBase64Confidence(input: string): number {
    if (!NES.hasBase64Pattern(input)) return 0;

    // Isolate the potential Base64 part in URL parameters
    let testString = input;
    if (input.includes("=")) {
      const parts = input.split("=");
      testString = parts[parts.length - 1];
    }

    // The higher the ratio of base64 characters, the higher the confidence
    const base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";
    let validCharsCount = 0;

    for (let i = 0; i < testString.length; i++) {
      if (base64Chars.includes(testString[i])) {
        validCharsCount++;
      }
    }

    const ratio = validCharsCount / testString.length;

    // Length checks for Base64 - should be near multiple of 4
    const lengthMod4 = testString.length % 4;
    const lengthFactor = lengthMod4 === 0 ? 0.1 : 0;

    // Try to decode
    try {
      // Prepare string for decoding
      let decodableString = testString;

      // Replace URL-safe chars
      decodableString = decodableString.replace(/-/g, "+").replace(/_/g, "/");

      // Add padding if needed
      while (decodableString.length % 4 !== 0) {
        decodableString += "=";
      }

      const decoded = NES.decodeBase64(decodableString);

      // Analyze decoded content
      const readableChars = decoded.replace(/[^\x20-\x7E]/g, "").length;
      const readableRatio = readableChars / decoded.length;

      // If decoded text seems readable, increase confidence
      if (readableRatio > 0.7) {
        return Math.min(0.95, ratio + 0.2 + lengthFactor);
      }
    } catch (e) {
      // If decoding fails completely, decrease confidence
      return Math.max(0.1, ratio - 0.3);
    }

    return Math.min(0.8, ratio + lengthFactor);
  }
}

export { NES as NehonixEncService };
export default NES;
