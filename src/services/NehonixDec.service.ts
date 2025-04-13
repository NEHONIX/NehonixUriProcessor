import {
  DecodeResult,
  EncodingDetectionResult,
  ENC_TYPE,
  NestedEncodingResult,
  DEC_FEATURE_TYPE,
} from "../types";
import punycode from "punycode";
import { NehonixCoreUtils } from "../utils/NehonixCoreUtils";
import { NehonixEncService } from "./NehonixEnc.service";
import NehonixCommonUtils, {
  NehonixSharedUtils,
} from "../common/NehonixCommonUtils";

class NDS {
  private static throwError: boolean = true;
  // private static hasBase64Pattern = NehonixCoreUtils.hasBase64Pattern;
  // // private static hasPercentEncoding = NehonixSharedUtils.hasPercentEncoding;
  private static enc: typeof NehonixEncService = NehonixEncService;
  // private static hasDoublePercentEncoding =
  //   NehonixCoreUtils.hasDoublePercentEncoding;
  // private static hasHexEncoding = NehonixCoreUtils.hasHexEncoding;
  // private static hasUnicodeEncoding = NehonixCoreUtils.hasUnicodeEncoding;
  // private static hasRawHexString = NehonixCoreUtils.hasRawHexString;
  private static calculateBase64Confidence = NDS.enc.calculateBase64Confidence;
  // private static hasHTMLEntityEncoding = NehonixCoreUtils.hasHTMLEntityEncoding;
  // private static hasJWTFormat = NehonixCoreUtils.hasJWTFormat;
  // private static hasPunycode = NehonixCoreUtils.hasPunycode;
  // private static decodeBase64 = NehonixCoreUtils.decodeB64;
  // private static decodeRawHexWithoutPrefix = NehonixCoreUtils.drwp;

  /**
   * Automatically detects and decodes a URI based on the detected encoding type
   * @param input The URI string to decode
   * @returns The decoded string according to the most probable encoding type
   */
  static detectAndDecode(input: string): DecodeResult {
    // Special case for URLs with parameters
    if (input.includes("?") && input.includes("=")) {
      const urlParts = input.split("?");
      const basePath = urlParts[0];
      const queryString = urlParts[1];

      // Split query parameters
      const params = queryString.split("&");
      const decodedParams = params.map((param) => {
        const [key, value] = param.split("=");

        if (!value) return param; // Handle cases where parameter has no value

        // Try to detect encoding for each parameter value
        const detection = NDS.detectEncoding(value);

        if (detection.confidence > 0.8) {
          try {
            // Attempt to decode based on detected encoding type
            let decodedValue = value;

            switch (detection.mostLikely) {
              case "base64":
                // Properly handle Base64 padding
                let base64Value = value;
                while (base64Value.length % 4 !== 0) {
                  base64Value += "=";
                }
                decodedValue = NehonixSharedUtils.decodeB64(
                  base64Value.replace(/-/g, "+").replace(/_/g, "/")
                );
                break;
              case "rawHexadecimal":
                if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
                  decodedValue = NDS.decodeRawHex(value);
                }
                break;
              case "percentEncoding":
                decodedValue = NDS.decodePercentEncoding(value);
                break;
              case "doublepercent":
                decodedValue = NDS.decodeDoublePercentEncoding(value);
                break;
              // Add other encoding types as needed
            }

            // Validate the decoded value to ensure it's readable text
            const printableChars = decodedValue.replace(
              /[^\x20-\x7E]/g,
              ""
            ).length;
            const printableRatio = printableChars / decodedValue.length;

            // Only use decoded value if it's mostly printable characters
            if (printableRatio > 0.7) {
              return `${key}=${decodedValue}`;
            }
          } catch (e) {
            console.warn(`Failed to decode parameter ${key}: ${e}`);
            // Keep original if decoding fails
          }
        }

        return param; // Keep original for non-decodable params
      });

      // Reconstruct URL with decoded parameters
      const decodedQueryString = decodedParams.join("&");
      const decodedURL = `${basePath}?${decodedQueryString}`;

      if (decodedURL !== input) {
        // Find which parameter was decoded and retrieve its encoding type
        const paramEncoding =
          params
            .map((param) => {
              const [key, value] = param.split("=");
              if (value) {
                return NDS.detectEncoding(value).mostLikely;
              }
              return "none";
            })
            .find((type) => type !== "plainText" && type !== "none") ||
          "unknown";

        return {
          val: decodedURL,
          encodingType: paramEncoding,
          confidence: 0.85,
        };
      }
    }

    // Process nested encoding
    const detection = NDS.detectEncoding(input);
    let decodedValue = input;

    // Process nested encoding
    if (detection.isNested && detection.nestedTypes) {
      try {
        // Decode from outermost to innermost
        decodedValue = input;
        for (const encType of detection.nestedTypes) {
          decodedValue = NDS.decode({
            encodingType: encType as ENC_TYPE,
            input,
          });
        }

        return {
          val: decodedValue,
          encodingType: detection.mostLikely,
          confidence: detection.confidence,
          nestedTypes: detection.nestedTypes,
        };
      } catch (e: any) {
        console.error(`Error while decoding nested encodings:`, e);
      }
    }

    // For simple encodings, proceed as before
    try {
      switch (detection.mostLikely) {
        case "percentEncoding":
          decodedValue = NDS.decodePercentEncoding(input);
          break;
        case "doublepercent":
          decodedValue = NDS.decodeDoublePercentEncoding(input);
          break;
        case "base64":
          // Properly handle Base64 padding
          let base64Input = input;
          while (base64Input.length % 4 !== 0) {
            base64Input += "=";
          }
          decodedValue = NehonixSharedUtils.decodeB64(
            base64Input.replace(/-/g, "+").replace(/_/g, "/")
          );
          break;
        case "hex":
          decodedValue = NDS.decodeHex(input);
          break;
        case "rawHexadecimal":
          decodedValue = NDS.decodeRawHex(input);
          break;
        case "unicode":
          decodedValue = NDS.decodeUnicode(input);
          break;
        case "htmlEntity":
          decodedValue = NDS.decodeHTMLEntities(input);
          break;
        case "punycode":
          decodedValue = NDS.decodePunycode(input);
          break;
        case "jwt":
          decodedValue = NDS.decodeJWT(input);
          break;
        default:
          // Try as raw hex as a last resort for parameters
          if (input.includes("=")) {
            const parts = input.split("=");
            const value = parts[parts.length - 1];
            if (
              value &&
              value.length >= 6 &&
              /^[0-9A-Fa-f]+$/.test(value) &&
              value.length % 2 === 0
            ) {
              try {
                const decodedParam = NDS.decodeRawHex(value);

                // Validate decoded text quality
                const printableChars = decodedParam.replace(
                  /[^\x20-\x7E]/g,
                  ""
                ).length;
                const printableRatio = printableChars / decodedParam.length;

                if (printableRatio > 0.7) {
                  decodedValue = input.replace(value, decodedParam);
                  return {
                    val: decodedValue,
                    encodingType: "rawHexadecimal",
                    confidence: 0.8,
                  };
                }
              } catch {
                // Fall through to return original
              }
            }
          }
          decodedValue = input;
      }

      // Validate the decoded value to ensure it's readable text
      const printableChars = decodedValue.replace(/[^\x20-\x7E]/g, "").length;
      const printableRatio = printableChars / decodedValue.length;

      // If decoded value is mostly unprintable, revert to original
      if (printableRatio < 0.7 && detection.mostLikely !== "plainText") {
        console.warn(
          `Decoded value contains too many unprintable characters (${printableRatio.toFixed(
            2
          )}), reverting to original`
        );
        decodedValue = input;
      }
    } catch (e: any) {
      console.error(`Error while decoding using ${detection.mostLikely}:`, e);
      decodedValue = input;
    }

    return {
      val: decodedValue,
      encodingType: detection.mostLikely,
      confidence: detection.confidence,
    };
  }

  // Decode JWT
  static decodeJWT(input: string): string {
    const parts = input.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");

    try {
      // Décoder seulement les parties header et payload (pas la signature)
      const header = NehonixSharedUtils.decodeB64(
        parts[0].replace(/-/g, "+").replace(/_/g, "/")
      );
      const payload = NehonixSharedUtils.decodeB64(
        parts[1].replace(/-/g, "+").replace(/_/g, "/")
      );

      // Formater en JSON pour une meilleure lisibilité
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(payload);

      return JSON.stringify(
        {
          header: headerObj,
          payload: payloadObj,
          signature: "[signature]", // Ne pas décoder la signature
        },
        null,
        2
      );
    } catch (e: any) {
      throw new Error(`JWT decoding failed: ${e.message}`);
    }
  }

  // =============== DECODING METHODS ===============

  /**
   * Decodes percent encoding (URL)
   */
  static decodePercentEncoding(input: string): string {
    try {
      return decodeURIComponent(input);
    } catch (e: any) {
      // In case of error (invalid sequence), try to decode valid parts
      console.warn("Error while percent-decoding, attempting partial decoding");
      return input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
        try {
          return decodeURIComponent(match);
        } catch {
          return match;
        }
      });
    }
  }

  /**
   * Decodes double percent encoding
   */
  static decodeDoublePercentEncoding(input: string): string {
    // First decode %25XX to %XX, then decode %XX
    const firstPass = input.replace(/%25([0-9A-Fa-f]{2})/g, (match, hex) => {
      return `%${hex}`;
    });

    return NDS.decodePercentEncoding(firstPass);
  }

  /**
   * Decodes hexadecimal encoding
   */
  static decodeHex(input: string): string {
    try {
      // Replace \xXX and 0xXX sequences with their equivalent characters
      return input
        .replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
          return String.fromCharCode(parseInt(hex, 16));
        })
        .replace(/0x([0-9A-Fa-f]{2})/g, (match, hex) => {
          return String.fromCharCode(parseInt(hex, 16));
        });
    } catch (e) {
      console.error("Error in decodeHex:", e);
      return input; // Return original input on error
    }
  }

  /**
   * Decodes Unicode encoding
   */
  static decodeUnicode(input: string): string {
    try {
      // Replace \uXXXX and \u{XXXXX} with their equivalent characters
      return input
        .replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
          return String.fromCodePoint(parseInt(hex, 16));
        })
        .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (match, hex) => {
          return String.fromCodePoint(parseInt(hex, 16));
        });
    } catch (e: any) {
      throw new Error(`Unicode decoding failed: ${e.message}`);
    }
  }

  /**
   * Decodes HTML entities
   */
  static decodeHTMLEntities(input: string): string {
    const entities: { [key: string]: string } = {
      "&lt;": "<",
      "&gt;": ">",
      "&amp;": "&",
      "&quot;": '"',
      "&apos;": "'",
      "&nbsp;": " ",
      // Add other common HTML entities if needed
    };

    // Replace named entities
    let result = input;
    for (const [entity, char] of Object.entries(entities)) {
      result = result.replace(new RegExp(entity, "g"), char);
    }

    // Replace numeric entities (decimal)
    result = result.replace(/&#(\d+);/g, (match, dec) => {
      return String.fromCodePoint(parseInt(dec, 10));
    });

    // Replace numeric entities (hexadecimal)
    result = result.replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) => {
      return String.fromCodePoint(parseInt(hex, 16));
    });

    return result;
  }

  /**
   * Decodes punycode
   * Note: Requires the 'punycode' library
   */
  static decodePunycode(input: string): string {
    try {
      // If the punycode module is available
      if (typeof require !== "undefined") {
        // For URLs with international domains
        return input.replace(/xn--[a-z0-9-]+/g, (match) => {
          try {
            return punycode.decode(match.replace("xn--", ""));
          } catch {
            return match;
          }
        });
      } else {
        // Alternative for browser (less accurate)
        // For a complete browser implementation, include a punycode library
        console.warn(
          "Punycode module not available, limited punycode decoding"
        );
        return input;
      }
    } catch (e: any) {
      throw new Error(`Punycode decoding failed: ${e.message}`);
    }
  }
  /**
   * Automatically detects the encoding type(s) of a string (URI or raw text)
   * @param input The string to analyze
   * @param depth Internal recursion depth (default: 0)
   * @returns An object with detected types, confidence scores and the most likely one
   */
  static detectEncoding(input: string, depth = 0): EncodingDetectionResult {
    const MAX_DEPTH = 3;
    if (depth > MAX_DEPTH) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionScores: Record<string, number> = {};
    const utils = NehonixSharedUtils;

    const detectionChecks: {
      type: ENC_TYPE;
      fn: (s: string) => boolean;
      score: number;
    }[] = [
      { type: "doublepercent", fn: utils.isDoublePercent, score: 0.95 },
      { type: "percentEncoding", fn: utils.isPercentEncoding, score: 0.9 },
      { type: "base64", fn: utils.isBase64, score: 0.9 },
      { type: "urlSafeBase64", fn: utils.isUrlSafeBase64, score: 0.93 },
      { type: "base32", fn: utils.isBase32, score: 0.88 },
      { type: "asciihex", fn: utils.isAsciiHex, score: 0.85 },
      { type: "asciioct", fn: utils.isAsciiOct, score: 0.85 },
      { type: "hex", fn: utils.isHex, score: 0.8 },
      {
        type: "rawHexadecimal",
        fn: NehonixSharedUtils.hasRawHexString,
        score: 0.85,
      },
      { type: "unicode", fn: utils.isUnicode, score: 0.8 },
      { type: "htmlEntity", fn: utils.isHtmlEntity, score: 0.8 },
      { type: "decimalHtmlEntity", fn: utils.isDecimalHtmlEntity, score: 0.83 },
      { type: "quotedPrintable", fn: utils.isQuotedPrintable, score: 0.77 },
      { type: "punycode", fn: utils.isPunycode, score: 0.9 },
      { type: "rot13", fn: utils.isRot13.bind(utils), score: 0.8 },
      { type: "utf7", fn: utils.isUtf7, score: 0.75 },
      { type: "jsEscape", fn: utils.isJsEscape, score: 0.8 },
      { type: "cssEscape", fn: utils.isCssEscape, score: 0.78 },
      { type: "jwt", fn: NehonixSharedUtils.hasJWTFormat, score: 0.95 },
    ];

    for (const { type, fn, score } of detectionChecks) {
      try {
        if (fn(input)) {
          detectionScores[type] = score;
        }
      } catch {
        // Ignore faulty detection
      }
    }

    // Special case: check for base64 in URL parameters
    if (input.includes("?") && input.includes("=")) {
      try {
        const url = new URL(input);
        const params = new URLSearchParams(url.search);
        for (const [, value] of params.entries()) {
          if (NehonixCoreUtils.hasBase64Pattern(value)) {
            detectionScores["base64"] = Math.max(
              detectionScores["base64"] ?? 0,
              0.9
            );
            break;
          }
        }
      } catch {
        // Ignore if URL parse fails
      }
    }

    // Try recursive nested encoding detection if we're still shallow
    if (depth < MAX_DEPTH) {
      const nested = NDS.detectNestedEncoding(input, depth + 1);
      if (nested.isNested) {
        const nestedKey = `nested:${nested.outerType}+${nested.innerType}`;
        detectionScores[nestedKey] = nested.confidenceScore;
      }
    }

    // Fallback: plain text
    if (Object.keys(detectionScores).length === 0) {
      detectionScores["plainText"] = 1.0;
    }

    // Sort by confidence
    const sorted = Object.entries(detectionScores).sort((a, b) => b[1] - a[1]);

    const result: EncodingDetectionResult = {
      types: sorted.map(([type]) => type),
      mostLikely: sorted[0][0] as ENC_TYPE,
      confidence: sorted[0][1],
    };

    if (depth < MAX_DEPTH) {
      const nested = NDS.detectNestedEncoding(input, depth + 1);
      if (nested.isNested) {
        result.isNested = true;
        result.nestedTypes = [nested.outerType, nested.innerType];
      }
    }

    return result;
  }

  /**
   * Decodes a raw hexadecimal string (without prefixes)
   * @param input The hexadecimal string to decode
   * @returns The decoded string
   */
  static decodeRawHex(input: string): string {
    // For URL parameters with equals sign
    if (input.includes("=")) {
      const parts = input.split("=");
      const prefix = parts.slice(0, parts.length - 1).join("=") + "=";
      const hexString = parts[parts.length - 1];

      // Check if valid hex
      if (!/^[0-9A-Fa-f]+$/.test(hexString) || hexString.length % 2 !== 0) {
        return input; // Not a valid hex string, return as is
      }

      return prefix + NehonixSharedUtils.drwp(hexString);
    }
    // For URL with path segments or query parameters without equals
    else if (input.includes("?") || input.includes("/")) {
      const regex = /([?\/])([0-9A-Fa-f]+)(?=[?\/]|$)/g;
      return input.replace(regex, (match, delimiter, hexPart) => {
        if (!/^[0-9A-Fa-f]+$/.test(hexPart) || hexPart.length % 2 !== 0) {
          return match; // Not a valid hex string, return as is
        }

        try {
          return delimiter + NehonixSharedUtils.drwp(hexPart);
        } catch {
          return match;
        }
      });
    }
    // For raw hex string
    else {
      // Attempt to decode the entire string as hex
      if (!/^[0-9A-Fa-f]+$/.test(input) || input.length % 2 !== 0) {
        return input; // Not a valid hex string, return as is
      }

      try {
        return NehonixSharedUtils.drwp(input);
      } catch {
        return input;
      }
    }
  }

  // 3. Nested encoding detection
  private static detectNestedEncoding(
    input: string,
    depth = 0
  ): NestedEncodingResult {
    // Guard against too deep recursion
    if (depth > 3) {
      return {
        isNested: false,
        outerType: "",
        innerType: "",
        confidenceScore: 0,
      };
    }

    // Try to decode with different first-level encodings
    const encodingTypes = ["percentEncoding", "base64", "hexadecimal"];

    for (const outerType of encodingTypes) {
      try {
        // Decode first level
        const firstLevelDecoded = NDS.decode({
          input,
          encodingType: outerType as ENC_TYPE,
          maxRecursionDepth: 5 - depth,
        }); // Limit decoding depth

        // Check if the result is still encoded - but avoid recursion
        // Instead of calling detectEncoding which would call detectNestedEncoding again,
        // perform a simple check for known patterns
        let innerType = "";
        let confidence = 0;

        if (NehonixSharedUtils.hasPercentEncoding(firstLevelDecoded)) {
          innerType = "percentEncoding";
          confidence = 0.9;
        } else if (NehonixCoreUtils.hasBase64Pattern(firstLevelDecoded)) {
          innerType = "base64";
          confidence = NDS.calculateBase64Confidence(firstLevelDecoded);
        } else if (NehonixSharedUtils.hasHexEncoding(firstLevelDecoded)) {
          innerType = "hexadecimal";
          confidence = 0.7;
        }

        // If another encoding is detected with high confidence
        if (confidence > 0.7 && innerType !== "") {
          return {
            isNested: true,
            outerType,
            innerType,
            confidenceScore: confidence * 0.9, // Slight penalty
          };
        }
      } catch (e) {
        continue; // Decoding failed, try next type
      }
    }

    return {
      isNested: false,
      outerType: "",
      innerType: "",
      confidenceScore: 0,
    };
  }

  //new
  /**
   * Decodes ROT13 encoded text
   */
  static decodeRot13(input: string): string {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const code = char.charCodeAt(0);
      // For uppercase letters (A-Z)
      if (code >= 65 && code <= 90) {
        return String.fromCharCode(((code - 65 + 13) % 26) + 65);
      }
      // For lowercase letters (a-z)
      else if (code >= 97 && code <= 122) {
        return String.fromCharCode(((code - 97 + 13) % 26) + 97);
      }
      return char;
    });
  }

  /**
   * Decodes Base32 encoded text
   */
  static decodeBase32(input: string): string {
    // Base32 alphabet (RFC 4648)
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Remove padding characters and whitespace
    const cleanInput = input
      .toUpperCase()
      .replace(/=+$/, "")
      .replace(/\s/g, "");

    let bits = "";
    let result = "";

    // Convert each character to its 5-bit binary representation
    for (let i = 0; i < cleanInput.length; i++) {
      const char = cleanInput[i];
      const index = alphabet.indexOf(char);
      if (index === -1) throw new Error(`Invalid Base32 character: ${char}`);

      // Convert to 5-bit binary
      bits += index.toString(2).padStart(5, "0");
    }

    // Process 8 bits at a time to construct bytes
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      const byte = bits.substring(i, i + 8);
      result += String.fromCharCode(parseInt(byte, 2));
    }

    return result;
  }

  /**
   * Decodes URL-safe Base64 encoded text
   */
  static decodeUrlSafeBase64(input: string): string {
    // Convert URL-safe characters back to standard Base64
    const standardBase64 = input
      .replace(/-/g, "+")
      .replace(/_/g, "/")
      .replace(/=+$/, ""); // Remove padding if present

    // Add padding if needed
    let padded = standardBase64;
    while (padded.length % 4 !== 0) {
      padded += "=";
    }

    return NehonixSharedUtils.decodeB64(padded);
  }

  /**
   * Decodes JavaScript escape sequences
   */
  static decodeJsEscape(input: string): string {
    return (
      input
        // Handle \xXX hex escapes
        .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        // Handle \uXXXX unicode escapes
        .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        // Handle \u{XXXXX} unicode escapes (ES6)
        .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        // Handle simple escapes
        .replace(/\\([nrt'"`\\])/g, (_, char) => {
          const escapeMap: Record<string, string> = {
            n: "\n",
            r: "\r",
            t: "\t",
            "'": "'",
            '"': '"',
            "`": "`",
            "\\": "\\",
          };
          return escapeMap[char] || char;
        })
    );
  }

  /**
   * Decodes CSS escape sequences
   */
  static decodeCssEscape(input: string): string {
    return (
      input
        // Handle Unicode escapes with variable-length hex digits
        .replace(/\\([0-9A-Fa-f]{1,6})\s?/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        )
        // Handle simple character escapes (any non-hex character that's escaped)
        .replace(/\\(.)/g, (_, char) => char)
    );
  }

  /**
   * Decodes UTF-7 encoded text
   */
  static decodeUtf7(input: string): string {
    let result = "";
    let inBase64 = false;
    let base64Chars = "";

    for (let i = 0; i < input.length; i++) {
      if (inBase64) {
        if (input[i] === "-") {
          // End of Base64 section
          if (base64Chars.length > 0) {
            // Convert accumulated Base64 to UTF-16 and then to string
            try {
              const bytes = NehonixSharedUtils.decodeB64(base64Chars);
              // UTF-7 encodes 16-bit Unicode chars as Base64
              for (let j = 0; j < bytes.length; j += 2) {
                const charCode =
                  bytes.charCodeAt(j) | (bytes.charCodeAt(j + 1) << 8);
                result += String.fromCharCode(charCode);
              }
            } catch (e) {
              // On error, just append the raw text
              result += "+" + base64Chars + "-";
            }
          } else if (base64Chars === "") {
            // "+- is just a literal '+'
            result += "+";
          }

          inBase64 = false;
          base64Chars = "";
        } else if (
          (input[i] >= "A" && input[i] <= "Z") ||
          (input[i] >= "a" && input[i] <= "z") ||
          (input[i] >= "0" && input[i] <= "9") ||
          input[i] === "+" ||
          input[i] === "/"
        ) {
          // Valid Base64 character
          base64Chars += input[i];
        } else {
          // Invalid character ends Base64 section
          if (base64Chars.length > 0) {
            try {
              const bytes = NehonixSharedUtils.decodeB64(base64Chars);
              for (let j = 0; j < bytes.length; j += 2) {
                const charCode =
                  bytes.charCodeAt(j) | (bytes.charCodeAt(j + 1) << 8);
                result += String.fromCharCode(charCode);
              }
            } catch (e) {
              result += "+" + base64Chars;
            }
          }

          inBase64 = false;
          base64Chars = "";
          result += input[i];
        }
      } else if (input[i] === "+") {
        if (i + 1 < input.length && input[i + 1] === "-") {
          // '+-' is a literal '+'
          result += "+";
          i++; // Skip the next character
        } else {
          // Start of Base64 section
          inBase64 = true;
          base64Chars = "";
        }
      } else {
        // Regular character
        result += input[i];
      }
    }

    // Handle unclosed Base64 section
    if (inBase64 && base64Chars.length > 0) {
      result += "+" + base64Chars;
    }

    return result;
  }

  /**
   * Decodes Quoted-Printable encoded text
   */
  static decodeQuotedPrintable(input: string): string {
    // Remove soft line breaks (=<CR><LF>)
    let cleanInput = input.replace(/=(?:\r\n|\n|\r)/g, "");

    // Decode hex characters
    return cleanInput.replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  /**
   * Decodes decimal HTML entity encoded text
   */
  static decodeDecimalHtmlEntity(input: string): string {
    return input.replace(/&#(\d+);/g, (_, dec) => {
      return String.fromCharCode(parseInt(dec, 10));
    });
  }

  /**
   * Decodes ASCII hex encoded text (where ASCII values are represented as hex)
   */
  static decodeAsciiHex(input: string): string {
    // Match pairs of hex digits
    const hexPairs = input.match(/[0-9A-Fa-f]{2}/g);
    if (!hexPairs) return input;

    return hexPairs
      .map((hex) => String.fromCharCode(parseInt(hex, 16)))
      .join("");
  }

  /**
   * Decodes ASCII octal encoded text
   */
  static decodeAsciiOct(input: string): string {
    // Match 3-digit octal codes
    return input.replace(/\\([0-7]{3})/g, (_, oct) => {
      return String.fromCharCode(parseInt(oct, 8));
    });
  }

  /**
   * Auto-detects encoding and recursively decodes until plaintext
   * @param input The encoded string
   * @param maxIterations Maximum number of decoding iterations to prevent infinite loops
   * @returns Fully decoded plaintext
   */
  static decodeAnyToPlaintext(input: string, maxIterations = 10): string {
    this.throwError = false;
    let result = input;
    let lastResult = "";
    let iterations = 0;

    // Continue decoding until no change is detected or max iterations reached
    while (result !== lastResult && iterations < maxIterations) {
      lastResult = result;

      // Detect encoding
      const detection = NDS.detectEncoding(result);

      // If detected as plaintext or very low confidence, stop decoding
      if (detection.mostLikely === "plainText" || detection.confidence < 0.7) {
        break;
      }

      // Try to decode
      try {
        const decoded = NDS.decode({
          input: result,
          encodingType: detection.mostLikely as ENC_TYPE,
        });

        // Only accept the decoded result if it's not significantly smaller
        // (to avoid decoding text that looks like encoded but isn't)
        if (decoded.length > result.length * 0.5) {
          result = decoded;
        } else {
          // If the result is much smaller, check if it looks valid
          const printableRatio =
            decoded.replace(/[^\x20-\x7E]/g, "").length / decoded.length;
          if (printableRatio > 0.8) {
            result = decoded;
          } else {
            // Not valid decoded text, stop here
            break;
          }
        }
      } catch (e) {
        // Decoding failed, stop here
        break;
      }

      iterations++;
    }

    return result;
  }
  /**
   * Decodes a string according to a specific encoding type
   * @param input The string to decode
   * @param encodingType The encoding type to use
   * @returns The decoded string
   */
  static decode(props: {
    input: string;
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE;
    maxRecursionDepth?: number;
    opt?: {
      throwError?: boolean;
    };
  }): string {
    const {
      encodingType,
      input,
      maxRecursionDepth = 5,
      opt = { throwError: this.throwError },
    } = props;
    // Add recursion protection
    if (maxRecursionDepth <= 0) {
      console.warn("Maximum recursion depth reached in decode");
      return input;
    }

    try {
      switch (encodingType) {
        case "percentEncoding":
        case "url":
          return NDS.decodePercentEncoding(input);
        case "doublepercent":
          return NDS.decodeDoublePercentEncoding(input);
        case "base64":
          return NehonixSharedUtils.decodeB64(input);
        case "urlSafeBase64":
          return NDS.decodeUrlSafeBase64(input);
        case "base32":
          return NDS.decodeBase32(input);
        case "hex":
          return NDS.decodeHex(input);
        case "unicode":
          return NDS.decodeUnicode(input);
        case "htmlEntity":
          return NDS.decodeHTMLEntities(input);
        case "decimalHtmlEntity":
          return NDS.decodeDecimalHtmlEntity(input);
        case "punycode":
          return NDS.decodePunycode(input);
        case "rot13":
          return NDS.decodeRot13(input);
        case "asciihex":
          return NDS.decodeAsciiHex(input);
        case "asciioct":
          return NDS.decodeAsciiOct(input);
        case "jsEscape":
          return NDS.decodeJsEscape(input);
        case "cssEscape":
          return NDS.decodeCssEscape(input);
        case "utf7":
          return NDS.decodeUtf7(input);
        case "quotedPrintable":
          return NDS.decodeQuotedPrintable(input);
        case "jwt":
          return NDS.decodeJWT(input);
        case "rawHexadecimal":
          return NDS.decodeRawHex(input);
        case "any":
          return NDS.decodeAnyToPlaintext(input);
        default:
          if (opt.throwError) {
            throw new Error(`Unsupported encoding type: ${encodingType}`);
          } else {
            return "Error skipped";
          }
      }
    } catch (e: any) {
      console.error(`Error while decoding (${encodingType}):`, e);
      return input; // Return original input on error instead of throwing
    }
  }
}

export { NDS as NehonixDecService };
export default NDS;
