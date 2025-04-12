import {
  DecodeResult,
  EncodingDetectionResult,
  ENC_TYPE,
  NestedEncodingResult,
} from "../types";
import punycode from "punycode";
import { NehonixCoreUtils } from "../utils/NehonixCoreUtils";
import { NehonixEncService } from "./NehonixEnc.service";
import { NehonixSharedUtils } from "../common/NehonixCommonUtils";

class NDS {
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
              case "doublePercentEncoding":
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
          decodedValue = NDS.decode(decodedValue, encType as ENC_TYPE);
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
        case "doublePercentEncoding":
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
        case "hexadecimal":
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
  /**
   * Decodes a string according to a specific encoding type
   * @param input The string to decode
   * @param encodingType The encoding type to use
   * @returns The decoded string
   */
  static decode(
    input: string,
    encodingType: ENC_TYPE,
    maxRecursionDepth = 5
  ): string {
    // Add recursion protection
    if (maxRecursionDepth <= 0) {
      console.warn("Maximum recursion depth reached in decode");
      return input;
    }

    try {
      switch (encodingType.toLowerCase()) {
        case "percent":
        case "percentencoding":
        case "url":
          return NDS.decodePercentEncoding(input);
        case "doublepercent":
        case "doublepercentencoding":
          return NDS.decodeDoublePercentEncoding(input);
        case "base64":
          return NehonixSharedUtils.decodeB64(input);
        case "hexadecimal":
          return NDS.decodeHex(input);
        case "unicode":
          return NDS.decodeUnicode(input);
        case "htmlentity":
        case "html":
          return NDS.decodeHTMLEntities(input);
        case "punycode":
          return NDS.decodePunycode(input);
        default:
          throw new Error(`Unsupported encoding type: ${encodingType}`);
      }
    } catch (e: any) {
      console.error(`Error while decoding (${encodingType}):`, e);
      return input; // Return original input on error instead of throwing
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
   * Automatically detects the encoding type of a URI string
   * @param input The URI string to analyze
   * @returns An object containing the detected encoding types and their probability
   */
  static detectEncoding(input: string, depth = 0): EncodingDetectionResult {
    // Guard against too deep recursion
    if (depth > 3) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionResults: Map<string, number> = new Map();

    // Special case for URLs with parameters - check each parameter individually
    if (input.includes("?") && input.includes("=")) {
      try {
        const url = new URL(input);
        const params = new URLSearchParams(url.search);

        // Check each parameter for encoding
        for (const [key, value] of params.entries()) {
          if (NehonixCoreUtils.hasBase64Pattern(value)) {
            detectionResults.set("base64", 0.9); // High confidence for parameter-level Base64
            break; // Found one Base64 parameter, that's enough
          }

          // TODO: Add other parameter-level
        }
      } catch {
        // URL parsing failed, continue with regular checks
      }
    }

    // Regular checks
    if (NehonixSharedUtils.hasPercentEncoding(input))
      detectionResults.set("percentEncoding", 0.9);
    if (NehonixSharedUtils.hasDoublePercentEncoding(input))
      detectionResults.set("doublePercentEncoding", 0.95);
    if (NehonixCoreUtils.hasBase64Pattern(input))
      detectionResults.set("base64", NDS.enc.calculateBase64Confidence(input));
    if (NehonixCoreUtils.hasHexEncoding(input))
      detectionResults.set("hexadecimal", 0.7);
    if (NehonixCoreUtils.hasRawHexString(input))
      detectionResults.set("rawHexadecimal", 0.85);
    if (NehonixCoreUtils.hasUnicodeEncoding(input))
      detectionResults.set("unicode", 0.85);
    if (NehonixCoreUtils.hasHTMLEntityEncoding(input))
      detectionResults.set("htmlEntity", 0.8);
    if (NehonixCoreUtils.hasPunycode(input))
      detectionResults.set("punycode", 0.9);
    if (NehonixCoreUtils.hasJWTFormat(input)) detectionResults.set("jwt", 0.95);

    // Only check for nested encoding if we're not too deep in recursion
    if (depth < 2) {
      const nestedEncoding = NDS.detectNestedEncoding(input, depth + 1);
      if (nestedEncoding.isNested) {
        detectionResults.set(
          `nested:${nestedEncoding.outerType}+${nestedEncoding.innerType}`,
          nestedEncoding.confidenceScore
        );
      }
    }

    // If no encoding is detected, consider as plain text
    if (detectionResults.size === 0) {
      detectionResults.set("plainText", 1.0);
    }

    // Sort results by confidence score
    const sortedResults = [...detectionResults.entries()].sort(
      (a, b) => b[1] - a[1]
    );

    // Build result with additional information
    const result = {
      types: sortedResults.map(([type]) => type),
      mostLikely: sortedResults[0][0],
      confidence: sortedResults[0][1],
    };

    // Add nested encoding information if detected
    if (depth < 2) {
      const nestedEncoding = NDS.detectNestedEncoding(input, depth + 1);
      if (nestedEncoding.isNested) {
        Object.assign(result, {
          isNested: true,
          nestedTypes: [nestedEncoding.outerType, nestedEncoding.innerType],
        });
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
        const firstLevelDecoded = NDS.decode(
          input,
          outerType as ENC_TYPE,
          5 - depth
        ); // Limit decoding depth

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
}

export { NDS as NehonixDecService };
export default NDS;
