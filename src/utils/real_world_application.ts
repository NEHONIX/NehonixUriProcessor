import NES from "../services/NehonixEnc.service";
import { ENC_TYPE, RWA_TYPES } from "../types";

export class NehonixSafetyLayer {
  /**
   * Encodes user input based on the context in which it will be used
   * Selects the appropriate encoding method for security and compatibility
   *
   * @param input The user input to secure
   * @param context The context where the input will be used
   * @param options Optional configuration for specific encoding behaviors
   * @returns The appropriately encoded string
   */
  static __safeEncode__(
    input: string,
    context: RWA_TYPES,
    options: {
      doubleEncode?: boolean; // If true, applies encoding twice for higher security
      encodeSpaces?: boolean; // If true, encodes spaces as %20 instead of +
      preserveNewlines?: boolean; // If true, preserves newlines in the encoded output
    } = {}
  ): string {
    // Default options
    const {
      doubleEncode = false,
      encodeSpaces = false,
      preserveNewlines = false,
    } = options;

    // Select encoding based on context
    let encodedString: string;

    switch (context) {
      case "url":
        encodedString = NES.encode(input, "percentEncoding");
        if (doubleEncode) {
          encodedString = NES.encode(encodedString, "doublepercent");
        }
        break;

      case "urlParam":
        encodedString = NES.encode(input, "urlSafeBase64");
        break;

      case "html":
        encodedString = NES.encode(input, "htmlEntity");
        break;

      case "htmlAttr":
        // Special handling for HTML attributes (double quotes must be escaped)
        encodedString = NES.encode(input, "htmlEntity");
        // Ensure quotes are always encoded
        encodedString = encodedString.replace(/"/g, "&quot;");
        break;

      case "js":
        encodedString = NES.encode(input, "jsEscape");
        break;

      case "jsString":
        // More aggressive encoding for JavaScript strings
        encodedString = NES.encode(input, "unicode");
        break;

      case "css":
        encodedString = NES.encode(input, "cssEscape");
        break;

      case "cssSelector":
        // More careful escaping for CSS selectors
        encodedString = NES.encode(input, "cssEscape")
          // Ensure : and . are always escaped in selectors
          .replace(/:/g, "\\3A ")
          .replace(/\./g, "\\2E ");
        break;

      case "email":
        if (preserveNewlines) {
          encodedString = NES.encode(input, "quotedPrintable");
        } else {
          // Use base64 for email body without newline preservation
          encodedString = NES.encode(input, "base64");
        }
        break;

      case "emailSubject":
        // Email subjects should be encoded using quoted-printable
        encodedString = NES.encode(input, "quotedPrintable")
          // Remove line breaks (not allowed in subject)
          .replace(/=\r\n/g, "");
        break;

      case "command":
        // Escape special shell characters
        encodedString = input.replace(
          /([&;'"`\\|*?~<>^()[\]{}$\n\r\t#])/g,
          "\\$1"
        );
        break;

      case "xml":
        // XML encoding (similar to HTML but with a few differences)
        encodedString = input
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&apos;");
        break;

      case "json":
        // JSON string encoding
        encodedString = JSON.stringify(input).slice(1, -1);
        break;

      case "obfuscate":
        // Simple obfuscation
        encodedString = NES.encode(input, "rot13");
        break;

      case "idnDomain":
        // For internationalized domain names
        encodedString = NES.encode(input, "punycode");
        break;

      default:
        // Default to HTML entity encoding as a safe fallback
        encodedString = NES.encode(input, "htmlEntity");
    }

    return encodedString;
  }

  /**
   * Detects the most likely encoding of a string
   * Useful for analyzing potentially encoded input
   *
   * @param input The string to analyze
   * @returns Object containing the detected encoding type and confidence level
   */
  static detectEncoding(input: string): {
    encodingType: ENC_TYPE | "unknown";
    confidence: number;
  } {
    // Test for base64
    const base64Confidence = NES.calculateBase64Confidence(input);
    if (base64Confidence > 0.8) {
      return { encodingType: "base64", confidence: base64Confidence };
    }

    // Test for percent encoding
    if (/%[0-9A-Fa-f]{2}/.test(input)) {
      // Check if it's double percent encoded
      if (/%25[0-9A-Fa-f]{2}/.test(input)) {
        return { encodingType: "doublepercent", confidence: 0.9 };
      }
      return { encodingType: "percentEncoding", confidence: 0.9 };
    }

    // Test for HTML entities
    if (/&[a-zA-Z]+;|&#\d+;/.test(input)) {
      // Check if it's decimal HTML entities
      if (/&#\d+;/.test(input) && !/&[a-zA-Z]+;/.test(input)) {
        return { encodingType: "decimalHtmlEntity", confidence: 0.9 };
      }
      return { encodingType: "htmlEntity", confidence: 0.85 };
    }

    // Test for hex encoding
    if (/\\x[0-9A-Fa-f]{2}/.test(input)) {
      return { encodingType: "hex", confidence: 0.8 };
    }

    // Test for unicode encoding
    if (/\\u[0-9A-Fa-f]{4}/.test(input)) {
      return { encodingType: "unicode", confidence: 0.85 };
    }

    // Test for ROT13 (approximate check)
    if (/[n-za-mN-ZA-M]{4,}/.test(input)) {
      const rot13Test = NES.encodeROT13(input);
      // Check if ROT13 of input looks more like English
      const originalCount = (input.match(/[etaoinshrdlu]/gi) || []).length;
      const decodedCount = (rot13Test.match(/[etaoinshrdlu]/gi) || []).length;

      if (decodedCount > originalCount * 1.5) {
        return { encodingType: "rot13", confidence: 0.7 };
      }
    }

    // Test for punycode
    if (input.startsWith("xn--")) {
      return { encodingType: "punycode", confidence: 0.95 };
    }

    // Unknown encoding
    return { encodingType: "unknown", confidence: 0 };
  }
}
