import { ENC_TYPE } from "../types";
import punycode from "punycode";
import { NehonixCoreUtils as NCU } from "../utils/NehonixCoreUtils";
import { htmlEntities } from "../utils/html.enties";
class NES {
  // private static NCU: typeof NehonixCoreUtils = NehonixCoreUtils;
  // private static decodeBase64 = NES.NCU.drwp;

  /**
   * Encodes a string according to a specific encoding type
   * @param input The string to encode
   * @param encodingType The encoding type to use
   * @returns The encoded string
   */
  static encode(input: string, encodingType: ENC_TYPE): string {
    try {
      console.log(`Selected type: ${encodingType}`);
      switch (encodingType) {
        case "percentEncoding":
          return NES.encodePercentEncoding(input);
        case "doublepercent":
          return NES.encodeDoublePercentEncoding(input);
        case "base64":
          return NES.encodeBase64(input);
        case "hex":
          return NES.encodeHex(input);
        case "unicode":
          return NES.encodeUnicode(input);
        case "htmlEntity":
          return NES.encodeHTMLEntities(input);
        case "punycode":
          return NES.encodePunycode(input);
        case "asciihex":
          return NES.encodeASCIIWithHex(input);
        case "asciioct":
          return NES.encodeASCIIWithOct(input);
        // New encoding types
        case "rot13":
          return NES.encodeROT13(input);
        case "base32":
          return NES.encodeBase32(input);
        case "urlSafeBase64":
          return NES.encodeURLSafeBase64(input);
        case "jsEscape":
          return NES.encodeJavaScriptEscape(input);
        case "cssEscape":
          return NES.encodeCSSEscape(input);
        case "utf7":
          return NES.encodeUTF7(input);
        case "quotedPrintable":
          return NES.encodeQuotedPrintable(input);
        case "decimalHtmlEntity":
          return NES.encodeDecimalHTMLEntities(input);
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
   * Encodes HTML entities in a string
   */
  static encodeHTMLEntities(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      result += htmlEntities[char] || char;
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
    if (!NCU.hasBase64Pattern(input)) return 0;

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

      const decoded = NCU.decodeB64(decodableString);

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

  /**
   * Encodes using ROT13 cipher (rotates letters by 13 positions)
   */
  static encodeROT13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const code = char.charCodeAt(0);
      // A-Z (65-90), a-z (97-122)
      const base = code < 91 ? 65 : 97;
      // Rotate by 13 positions within the alphabet
      return String.fromCharCode(((code - base + 13) % 26) + base);
    });
  }

  /**
   * Encodes in Base32
   */
  static encodeBase32(input: string): string {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let result = "";
    let bits = 0;
    let value = 0;

    for (let i = 0; i < input.length; i++) {
      value = (value << 8) | input.charCodeAt(i);
      bits += 8;

      while (bits >= 5) {
        result += alphabet[(value >> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      result += alphabet[(value << (5 - bits)) & 31];
    }

    // Add padding
    while (result.length % 8 !== 0) {
      result += "=";
    }

    return result;
  }

  /**
   * Encodes in URL-safe Base64
   * Uses - and _ instead of + and /
   */
  static encodeURLSafeBase64(input: string): string {
    // First encode to standard Base64
    const base64 = NES.encodeBase64(input);

    // Replace standard Base64 characters with URL-safe variants
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /**
   * Encodes string with JavaScript escape sequences
   * Useful for injecting into JS contexts
   */
  static encodeJavaScriptEscape(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;

      if (cp < 128) {
        // ASCII characters
        switch (input[i]) {
          case "\\":
            result += "\\\\";
            break;
          case '"':
            result += '\\"';
            break;
          case "'":
            result += "\\'";
            break;
          case "\n":
            result += "\\n";
            break;
          case "\r":
            result += "\\r";
            break;
          case "\t":
            result += "\\t";
            break;
          case "\b":
            result += "\\b";
            break;
          case "\f":
            result += "\\f";
            break;
          default:
            if (cp < 32 || cp === 127) {
              // Control characters
              result += `\\x${cp.toString(16).padStart(2, "0")}`;
            } else {
              result += input[i];
            }
        }
      } else if (cp <= 0xffff) {
        // BMP characters
        result += `\\u${cp.toString(16).padStart(4, "0")}`;
      } else {
        // Supplementary planes - use surrogate pairs
        result += `\\u${input
          .charCodeAt(i)
          .toString(16)
          .padStart(4, "0")}\\u${input
          .charCodeAt(i + 1)
          .toString(16)
          .padStart(4, "0")}`;
        i++; // Skip the second surrogate
      }
    }
    return result;
  }

  /**
   * Encodes string with CSS escape sequences
   * Useful for CSS selectors or values
   */
  static encodeCSSEscape(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;

      if (cp === 0) {
        // Unicode NULL is not allowed in CSS - replace with FFFD
        result += "\\FFFD ";
      } else if (
        cp < 33 ||
        cp === 127 ||
        /[\\!"#$%&'()*+,./:;<=>?@[\]^`{|}~]/.test(input[i])
      ) {
        // Special characters in CSS need escaping
        result += `\\${cp.toString(16).toUpperCase()} `;
      } else if (cp > 0xffff) {
        // For characters outside the BMP
        result += `\\${cp.toString(16).toUpperCase()} `;
        if (cp > 0xffff) i++; // Skip the next element for surrogate pairs
      } else {
        result += input[i];
      }
    }
    return result;
  }

  /**
   * Encodes in UTF-7
   * Useful for some legacy contexts
   */
  static encodeUTF7(input: string): string {
    let result = "";
    let inBase64 = false;
    let base64Buffer = "";

    for (let i = 0; i < input.length; i++) {
      const cp = input.charCodeAt(i);

      // ASCII characters (except for + which needs special handling)
      if (cp >= 33 && cp <= 126 && cp !== 43) {
        if (inBase64) {
          // End Base64 encoding
          result += base64Buffer.replace(/=+$/, "") + "-";
          base64Buffer = "";
          inBase64 = false;
        }
        result += input[i];
      } else {
        // Non-ASCII characters or + sign
        if (!inBase64) {
          result += "+";
          inBase64 = true;
        }

        // Use the buffer approach for handling Unicode characters
        let unicodeChar = String.fromCharCode(cp);

        // Encode the character using our base64 method
        // We need to handle the surrogate pairs properly
        base64Buffer += NES.encodeBase64(unicodeChar).replace(/=+$/, "");
      }
    }

    // Close any open base64 section
    if (inBase64) {
      result += base64Buffer + "-";
    }

    return result;
  }

  /**
   * Encodes in Quoted-Printable
   * Used in email systems
   */
  static encodeQuotedPrintable(input: string): string {
    let result = "";
    const unsafe = /[^\x20-\x7E]|[=]/g;

    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      const code = input.charCodeAt(i);

      if (char === "\r" || char === "\n") {
        result += char;
      } else if (char === " " || char === "\t") {
        // Space and tab at the end of a line must be encoded
        if (
          i === input.length - 1 ||
          input[i + 1] === "\r" ||
          input[i + 1] === "\n"
        ) {
          result += `=${code.toString(16).toUpperCase().padStart(2, "0")}`;
        } else {
          result += char;
        }
      } else if (unsafe.test(char)) {
        result += `=${code.toString(16).toUpperCase().padStart(2, "0")}`;
      } else {
        result += char;
      }

      // Add soft line breaks (QP lines should be no longer than 76 chars)
      if (result.length >= 75 && i < input.length - 1) {
        result += "=\r\n";
      }
    }

    return result;
  }

  /**
   * Encodes in decimal HTML entity format
   * Unlike the existing HTML entity encoder, this uses decimal &#123; format for all chars
   */
  static encodeDecimalHTMLEntities(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;
      result += `&#${cp};`;
      // Skip surrogate pair
      if (cp > 0xffff) i++;
    }
    return result;
  }
}

export { NES as NehonixEncService };
export default NES;
