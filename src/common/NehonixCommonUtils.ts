/**
 * Shared utility methods for encoding detection and basic decoding operations
 */
class NehonixCommonUtils {
  // private static decodeB64 = this.dec.decodeBase64;
  // private static drwp = this.dec.decodeRawHexWithoutPrefix;

  // =============== ENCODING DETECTION METHODS ===============

  /**
   * Checks if the string contains hexadecimal encoding
   */
  static hasHexEncoding(input: string): boolean {
    // Look for hexadecimal sequences like \x20, 0x20, etc.
    return /\\x[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2}/.test(input);
  }

  /**
   * Checks if the string contains Unicode encoding
   */
  static hasUnicodeEncoding(input: string): boolean {
    // Look for Unicode sequences like \u00A9, \u{1F600}, etc.
    return /\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]+\}/.test(input);
  }

  /**
   * Checks if the string contains HTML entities
   */
  static hasHTMLEntityEncoding(input: string): boolean {
    // Look for HTML entities like &lt;, &#60;, &#x3C;, etc.
    return /&[a-zA-Z]+;|&#\d+;|&#x[0-9A-Fa-f]+;/.test(input);
  }

  /**
   * Checks if the string contains punycode
   */
  static hasPunycode(input: string): boolean {
    // Look for punycode prefixes
    return /xn--/.test(input);
  }

  /**
   * Checks if the string contains percent encoding (%)
   */
  static hasPercentEncoding(input: string): boolean {
    // Look for sequences like %20, %3F, etc.
    return /%[0-9A-Fa-f]{2}/.test(input);
  }

  /**
   * Checks if the string contains double percent encoding (%%XX)
   */
  static hasDoublePercentEncoding(input: string): boolean {
    // Look for sequences like %2520 (which is encoded %20)
    return /%25[0-9A-Fa-f]{2}/.test(input);
  }

  /**
   * Raw hexadecimal detection
   */
  static hasRawHexString(input: string): boolean {
    let testString = input;

    if (input.includes("=")) {
      const parts = input.split("=");
      testString = parts[parts.length - 1];
    } else if (input.includes("?") || input.includes("/")) {
      const segments = input.split(/[?\/]/);
      testString = segments[segments.length - 1];
    }

    // Check if the string is a sequence of hexadecimal characters (even length)
    if (!/^[0-9A-Fa-f]+$/.test(testString) || testString.length % 2 !== 0) {
      return false;
    }

    return testString.length >= 6;
  }

  /**
   * JWT detection
   */
  static hasJWTFormat(input: string): boolean {
    // JWT format: 3 parts separated by dots
    const parts = input.split(".");
    if (parts.length !== 3) return false;

    // Check that each part looks like Base64URL
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;
    return parts.every((part) => base64urlRegex.test(part));
  }

  // =============== BASIC DECODING METHODS ===============

  /**
   * Decodes raw hexadecimal string (without prefixes)
   */

  static drwp(hexString: string): string {
    // Verify the input is a valid string (even length only)
    if (!/^[0-9A-Fa-f]+$/.test(hexString) || hexString.length % 2 !== 0) {
      throw new Error(
        "Invalid hex string: length must be even or contains non-hex characters"
      );
    }

    let result = "";

    // Process the string in character pairs
    for (let i = 0; i < hexString.length; i += 2) {
      const hexPair = hexString.substring(i, i + 2);

      // Convert hexadecimal pair to character
      const charCode = parseInt(hexPair, 16);
      result += String.fromCharCode(charCode);
    }

    return result;
  }
  /**
   * Basic Base64 decoding
   */

  /**
   * Decodes base64 encoding
   */
  static decodeB64(input: string): string {
    try {
      // Convert URL-safe Base64 to standard Base64
      let base64String = input.replace(/-/g, "+").replace(/_/g, "/");

      // Add padding if needed
      while (base64String.length % 4 !== 0) {
        base64String += "=";
      }

      // Try decoding with proper error handling
      try {
        // Node.js
        if (typeof Buffer !== "undefined") {
          return Buffer.from(base64String, "base64").toString("utf-8");
        }
        // Browser
        else {
          return atob(base64String);
        }
      } catch (e) {
        console.warn("Base64 decoding failed, returning original input");
        return input;
      }
    } catch (e: any) {
      console.error(`Base64 decoding failed: ${e.message}`);
      return input; // Return original input on error instead of throwing
    }
  }
}
export { NehonixCommonUtils as NehonixSharedUtils };
export default NehonixCommonUtils;
