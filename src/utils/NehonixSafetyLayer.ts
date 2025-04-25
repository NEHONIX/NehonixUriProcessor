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
}
