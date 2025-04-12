import { NehonixSharedUtils } from "../common/NehonixCommonUtils";

export class NehonixCoreUtils extends NehonixSharedUtils {
  // =============== ENCODING DETECTION METHODS ===============

  /**
   * Checks if the string matches base64 pattern
   */
  static hasBase64Pattern(input: string): boolean {
    // Check standard Base64 format with relaxed validation for URL parameters
    const standardBase64Regex = /^[A-Za-z0-9+/]*={0,2}$/;

    // Check Base64URL format (URL-safe version)
    const urlSafeBase64Regex = /^[A-Za-z0-9_-]*={0,2}$/;

    // If we have a URL parameter, isolate the value after = for testing
    let testString = input;
    if (input.includes("=")) {
      const parts = input.split("=");
      testString = parts[parts.length - 1];
    }

    // Length validation - Base64 length should be a multiple of 4 (or close with padding)
    const validLength =
      testString.length % 4 === 0 ||
      (testString.length > 4 && (testString.length - 1) % 4 === 0) ||
      (testString.length > 4 && (testString.length - 2) % 4 === 0);

    // Exclude strings that are too short
    if (testString.length < 8) return false;

    // Base64 character set check
    const base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";
    const base64CharRatio =
      [...testString].filter((c) => base64Chars.includes(c)).length /
      testString.length;

    // If nearly all characters are in the Base64 charset, proceed with validation
    if (base64CharRatio > 0.95) {
      try {
        // For URL parameters with Base64, try decoding
        let decodableString = testString;

        // Replace URL-safe chars with standard Base64 chars for decoding attempt
        decodableString = decodableString.replace(/-/g, "+").replace(/_/g, "/");

        // Add padding if needed
        while (decodableString.length % 4 !== 0) {
          decodableString += "=";
        }

        const decoded = this.decodeB64(decodableString);

        // Check if decoding produced meaningful results
        // Meaningful results have a good ratio of ASCII printable characters
        const printableChars = decoded.replace(/[^\x20-\x7E]/g, "").length;
        const printableRatio = printableChars / decoded.length;

        // Higher confidence for strings that decode to readable text
        return printableRatio > 0.5;
      } catch {
        return false;
      }
    }

    return false;
  }

  /**
   * Raw hexadecimal detection
   * @param input
   * @returns
   */
  static hasRawHexString(input: string): boolean {
    // For URL parameters with equals sign, extract the part after '='
    let testString = input;

    if (input.includes("=")) {
      const parts = input.split("=");
      // Test the last part which is likely the encoded value
      testString = parts[parts.length - 1];
    } else if (input.includes("?") || input.includes("/")) {
      // For URL parameters without equals sign
      // Extract the last segment after ? or the last path segment
      const segments = input.split(/[?\/]/);
      testString = segments[segments.length - 1];
    }

    // Check if the string is a sequence of hexadecimal characters (even length)
    if (!/^[0-9A-Fa-f]+$/.test(testString) || testString.length % 2 !== 0)
      return false;

    // Avoid false positives for very short strings
    if (testString.length < 6) return false;

    try {
      // Decode and check if the result looks like readable text
      const decoded = this.drwp(testString);

      // Calculate the percentage of printable characters
      const printableChars = decoded.replace(/[^\x20-\x7E]/g, "").length;
      const printableRatio = printableChars / decoded.length;

      // Check for HTTP control special characters
      const hasHttpChars = /[:\/\.\?\=\&]/.test(decoded);

      // Higher confidence for longer hex strings
      const lengthBonus = Math.min(0.1, testString.length / 1000);

      // Confidence bonus if we find URL-specific characters
      return (
        (printableRatio > 0.6 || (printableRatio > 0.4 && hasHttpChars)) &&
        testString.length >= 6
      );
    } catch {
      return false;
    }
  }

  // 4. JWT detection
  static hasJWTFormat(input: string): boolean {
    // JWT format: 3 parts separated by dots
    const parts = input.split(".");
    if (parts.length !== 3) return false;

    // Check that each part looks like Base64URL
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;

    if (!parts.every((part) => base64urlRegex.test(part))) return false;

    // Additional validation: try to decode the header
    try {
      const headerStr = this.decodeB64(
        parts[0].replace(/-/g, "+").replace(/_/g, "/")
      );
      const header = JSON.parse(headerStr);

      // Check if header contains typical JWT fields
      return header && (header.alg !== undefined || header.typ !== undefined);
    } catch {
      return false;
    }
  }
}
