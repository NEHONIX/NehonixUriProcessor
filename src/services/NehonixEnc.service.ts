import { ENC_TYPE } from "../types";
import punycode from "punycode";
import { NehonixCoreUtils as NCU } from "../utils/NehonixCoreUtils";
import { htmlEntities } from "../utils/html.enties";
import { AppLogger } from "../common/AppLogger";
import {
  EncodingResult,
  NestedEncodingOptions,
  NestedEncodingResponse,
} from "../types/enc.type";
class NES {
  /**
   * Encodes a string according to a specific encoding type
   * @param input The string to encode
   * @param encodingType The encoding type to use
   * @returns The encoded string
   */
  static encode(input: string, encodingType: ENC_TYPE): string {
    try {
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
        case "jwt":
          return NES.encodeJWT(input);
        case "rawHex":
          return NES.encodeRawHex(input);
        case "url":
          return NES.encodeUrl(input);
        default:
          throw new Error(`Unsupported encoding type: ${encodingType}`);
      }
    } catch (e: any) {
      throw e;
    }
  }

  // =============== ENCODING METHODS ===============

  /**
   * Encodes with percent encoding (URL)
   */
  static encodePercentEncoding(input: string, encodeSpaces = false): string {
    let encoded = encodeURIComponent(input);
    if (encodeSpaces) {
      encoded = encoded.replace(/\+/g, "%20");
    }
    return encoded;
  }

  /**
   * Encodes with double percent encoding
   */
  static encodeDoublePercentEncoding(input: string): string {
    const firstPass = NES.encodePercentEncoding(input, true);
    return firstPass.replace(/%/g, "%25");
  }

  /**
   * Encodes in base64
   */
  static encodeBase64(input: string): string {
    try {
      if (typeof Buffer !== "undefined") {
        return Buffer.from(input).toString("base64");
      } else {
        return btoa(input);
      }
    } catch (e: any) {
      if (e.name === "InvalidCharacterError") {
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
      if (cp > 0xffff) {
        result += `\\u{${cp.toString(16)}}`;
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
   */
  static encodePunycode(input: string): string {
    try {
      if (typeof require !== "undefined") {
        return `xn--${punycode.encode(input)}`;
      } else {
        AppLogger.warn(
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
    let testString = input;
    if (input.includes("=")) {
      const parts = input.split("=");
      testString = parts[parts.length - 1];
    }
    const base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";
    let validCharsCount = 0;
    for (let i = 0; i < testString.length; i++) {
      if (base64Chars.includes(testString[i])) {
        validCharsCount++;
      }
    }
    const ratio = validCharsCount / testString.length;
    const lengthMod4 = testString.length % 4;
    const lengthFactor = lengthMod4 === 0 ? 0.1 : 0;
    try {
      let decodableString = testString;
      decodableString = decodableString.replace(/-/g, "+").replace(/_/g, "/");
      while (decodableString.length % 4 !== 0) {
        decodableString += "=";
      }
      const decoded = NCU.decodeB64(decodableString);
      const readableChars = decoded.replace(/[^\x20-\x7E]/g, "").length;
      const readableRatio = readableChars / decoded.length;
      if (readableRatio > 0.7) {
        return Math.min(0.95, ratio + 0.2 + lengthFactor);
      }
    } catch (e) {
      return Math.max(0.1, ratio - 0.3);
    }
    return Math.min(0.8, ratio + lengthFactor);
  }

  /**
   * Encodes using ROT13 cipher
   */
  static encodeROT13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const code = char.charCodeAt(0);
      const base = code < 91 ? 65 : 97;
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
    while (result.length % 8 !== 0) {
      result += "=";
    }
    return result;
  }

  /**
   * Encodes in URL-safe Base64
   */
  static encodeURLSafeBase64(input: string): string {
    const base64 = NES.encodeBase64(input);
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  /**
   * Encodes string with JavaScript escape sequences
   */
  static encodeJavaScriptEscape(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;
      if (cp < 128) {
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
              result += `\\x${cp.toString(16).padStart(2, "0")}`;
            } else {
              result += input[i];
            }
        }
      } else if (cp <= 0xffff) {
        result += `\\u${cp.toString(16).padStart(4, "0")}`;
      } else {
        result += `\\u${input
          .charCodeAt(i)
          .toString(16)
          .padStart(4, "0")}\\u${input
          .charCodeAt(i + 1)
          .toString(16)
          .padStart(4, "0")}`;
        i++;
      }
    }
    return result;
  }

  /**
   * Encodes string with CSS escape sequences
   */
  static encodeCSSEscape(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;
      if (cp === 0) {
        result += "\\FFFD ";
      } else if (
        cp < 33 ||
        cp === 127 ||
        /[\\!"#$%&'()*+,./:;<=>?@[\]^`{|}~]/.test(input[i])
      ) {
        result += `\\${cp.toString(16).toUpperCase()} `;
      } else if (cp > 0xffff) {
        result += `\\${cp.toString(16).toUpperCase()} `;
        if (cp > 0xffff) i++;
      } else {
        result += input[i];
      }
    }
    return result;
  }

  /**
   * Encodes in UTF-7
   */
  static encodeUTF7(input: string): string {
    let result = "";
    let inBase64 = false;
    let base64Buffer = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.charCodeAt(i);
      if (cp >= 33 && cp <= 126 && cp !== 43) {
        if (inBase64) {
          result += base64Buffer.replace(/=+$/, "") + "-";
          base64Buffer = "";
          inBase64 = false;
        }
        result += input[i];
      } else {
        if (!inBase64) {
          result += "+";
          inBase64 = true;
        }
        let unicodeChar = String.fromCharCode(cp);
        base64Buffer += NES.encodeBase64(unicodeChar).replace(/=+$/, "");
      }
    }
    if (inBase64) {
      result += base64Buffer + "-";
    }
    return result;
  }

  /**
   * Encodes in Quoted-Printable
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
      if (result.length >= 75 && i < input.length - 1) {
        result += "=\r\n";
      }
    }
    return result;
  }

  /**
   * Encodes in decimal HTML entity format
   */
  static encodeDecimalHTMLEntities(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const cp = input.codePointAt(i)!;
      result += `&#${cp};`;
      if (cp > 0xffff) i++;
    }
    return result;
  }

  /**
   * Encodes in raw hexadecimal (no prefixes)
   */
  static encodeRawHex(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const hex = input.charCodeAt(i).toString(16).padStart(2, "0");
      result += hex;
    }
    return result;
  }

  /**
   * Encodes as a JWT with the input as the payload
   */
  static encodeJWT(input: string): string {
    try {
      const header = { alg: "none" };
      const headerEncoded = NES.encodeURLSafeBase64(JSON.stringify(header));
      const payloadEncoded = NES.encodeURLSafeBase64(input);
      return `${headerEncoded}.${payloadEncoded}.`;
    } catch (e: any) {
      throw new Error(`JWT encoding failed: ${e.message}`);
    }
  }

  /**
   * Encodes as a URL (percent-encoding with spaces as %20)
   */
  static encodeUrl(input: string): string {
    return NES.encodePercentEncoding(input, true);
  }

  /**
   * Performs multiple encodings on an input string synchronously
   * @param input The string to encode
   * @param types Array of encoding types to apply
   * @param options Configuration options for nested encoding
   * @returns Object containing encoding results
   */
  static encodeMultiple(
    input: string,
    types: ENC_TYPE[],
    options: NestedEncodingOptions = {}
  ): NestedEncodingResponse {
    // Default options
    const { sequential = false, includeIntermediate = true } = options;

    const results: EncodingResult[] = [];
    let currentInput = input;

    // Process each encoding type
    for (let i = 0; i < types.length; i++) {
      const encodingType = types[i];

      try {
        // Encode the current input using the specified encoding type
        const encodedResult = NES.encode(currentInput, encodingType);

        // Store the result
        results.push({
          original: currentInput,
          encoded: encodedResult,
          type: encodingType,
        });

        // If sequential, use this result as input for the next encoding
        if (sequential && i < types.length - 1) {
          currentInput = encodedResult;
        }
      } catch (e: any) {
        // Log the error but continue with other encodings
        AppLogger.error(`Error encoding with ${encodingType}: ${e.message}`);
        results.push({
          original: currentInput,
          encoded: `ERROR: ${e.message}`,
          type: encodingType,
        });
      }
    }

    // Prepare response object
    const response: NestedEncodingResponse = {
      input: input,
      results: includeIntermediate ? results : [],
    };

    // For sequential encoding, add the final result
    if (sequential) {
      response.finalResult =
        results.length > 0 ? results[results.length - 1].encoded : input;
    }

    // If not including intermediate results but not sequential,
    // we still want to include all direct encoding results
    if (!includeIntermediate && !sequential) {
      response.results = results;
    }

    return response;
  }

  /**
   * Performs multiple encodings on an input string asynchronously
   * @param input The string to encode
   * @param types Array of encoding types to apply
   * @param options Configuration options for nested encoding
   * @returns Promise resolving to object containing encoding results
   */
  static async encodeMultipleAsync(
    input: string,
    types: ENC_TYPE[],
    options: NestedEncodingOptions = {}
  ): Promise<NestedEncodingResponse> {
    // Default options
    const { sequential = false, includeIntermediate = true } = options;

    const results: EncodingResult[] = [];
    let currentInput = input;

    if (sequential) {
      // For sequential processing, we need to process in order
      for (let i = 0; i < types.length; i++) {
        const encodingType = types[i];

        try {
          // Encode the current input using the specified encoding type
          // Wrap in Promise.resolve to handle potential async operations
          const encodedResult = await Promise.resolve(
            NES.encode(currentInput, encodingType)
          );

          // Store the result
          results.push({
            original: currentInput,
            encoded: encodedResult,
            type: encodingType,
          });

          // Use this result as input for the next encoding
          if (i < types.length - 1) {
            currentInput = encodedResult;
          }
        } catch (e: any) {
          // Log the error but continue with other encodings
          AppLogger.error(`Error encoding with ${encodingType}: ${e.message}`);
          results.push({
            original: currentInput,
            encoded: `ERROR: ${e.message}`,
            type: encodingType,
          });
        }
      }
    } else {
      // For parallel processing, we can process all encodings concurrently
      const encodingPromises = types.map(async (encodingType) => {
        try {
          // Encode the input using the specified encoding type
          const encodedResult = await Promise.resolve(
            NES.encode(input, encodingType)
          );

          return {
            original: input,
            encoded: encodedResult,
            type: encodingType,
          };
        } catch (e: any) {
          // Log the error but continue with other encodings
          AppLogger.error(`Error encoding with ${encodingType}: ${e.message}`);
          return {
            original: input,
            encoded: `ERROR: ${e.message}`,
            type: encodingType,
          };
        }
      });

      // Wait for all encodings to complete
      results.push(...(await Promise.all(encodingPromises)));
    }

    // Prepare response object
    const response: NestedEncodingResponse = {
      input: input,
      results: includeIntermediate ? results : [],
    };

    // For sequential encoding, add the final result
    if (sequential) {
      response.finalResult =
        results.length > 0 ? results[results.length - 1].encoded : input;
    }

    // If not including intermediate results but not sequential,
    // we still want to include all direct encoding results
    if (!includeIntermediate && !sequential) {
      response.results = results;
    }

    return response;
  }
}

export { NES as NehonixEncService };
export default NES;
