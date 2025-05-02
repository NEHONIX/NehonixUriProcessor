import {
  DecodeResult,
  EncodingDetectionResult,
  ENC_TYPE,
  NestedEncodingResult,
  DEC_FEATURE_TYPE,
  UriHandlerInterface,
  UrlValidationOptions,
} from "../types";
import punycode from "punycode";
import chalk from "chalk";
import { ncu, NehonixCoreUtils } from "../utils/NehonixCoreUtils";
import { NehonixSharedUtils } from "../common/NehonixCommonUtils";
import NES from "./NehonixEnc.service";
import { sr } from "../rules/security.rules";
import { htmlEntities } from "../utils/html.enties";
import { AppLogger } from "../common/AppLogger";

class NDS {
  private static throwError: boolean = true;
  private static default_checkurl_opt: UrlValidationOptions = {
    allowLocalhost: true,
    rejectDuplicatedValues: false,
    maxUrlLength: "NO_LIMIT",
    strictMode: false,
    strictParamEncoding: false,
    debug: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: false,
  };
  // private static hasBase64Pattern = NehonixCoreUtils.hasBase64Pattern;
  // // private static hasPercentEncoding = NehonixSharedUtils.hasPercentEncoding;
  // private static enc: typeof NehonixEncService = NehonixEncService;
  // private static hasDoublePercentEncoding =
  //   NehonixCoreUtils.hasDoublePercentEncoding;
  // private static hasHexEncoding = NehonixCoreUtils.hasHexEncoding;
  // private static hasUnicodeEncoding = NehonixCoreUtils.hasUnicodeEncoding;
  // private static hasRawHexString = NehonixCoreUtils.hasRawHexString;
  // private static calculateBase64Confidence = NES.calculateBase64Confidence;
  // private static hasHTMLEntityEncoding = NehonixCoreUtils.hasHTMLEntityEncoding;
  // private static hasJWTFormat = NehonixCoreUtils.hasJWTFormat;
  // private static hasPunycode = NehonixCoreUtils.hasPunycode;
  // private static decodeBase64 = NehonixCoreUtils.decodeB64;
  // private static decodeRawHexWithoutPrefix = NehonixCoreUtils.drwp;
  // In your detectEncoding function or a new function
  static detectMixedEncodings(input: string): string[] {
    const detectedEncodings = [];

    // Check for percent encoding
    if (/%[0-9A-Fa-f]{2}/.test(input)) {
      detectedEncodings.push("percentEncoding");
    }

    // Check for Base64 content
    const base64Regex = /[A-Za-z0-9+/=]{4,}/g;
    const potentialBase64 = input.match(base64Regex);
    if (potentialBase64) {
      for (const match of potentialBase64) {
        if (NehonixSharedUtils.isBase64(match)) {
          detectedEncodings.push("base64");
          break;
        }
      }
    }

    // Add more checks as needed

    return detectedEncodings;
  }
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
            let decodedValue = value;

            switch (detection.mostLikely) {
              case "base64":
                let base64Input = value;
                // Ensure proper padding
                while (base64Input.length % 4 !== 0) {
                  base64Input += "=";
                }
                base64Input = base64Input.replace(/-/g, "+").replace(/_/g, "/");
                decodedValue = NehonixSharedUtils.decodeB64(base64Input);
                // Check if the result is still Base64-encoded
                if (NehonixCoreUtils.hasBase64Pattern(decodedValue)) {
                  let nestedBase64 = decodedValue;
                  while (nestedBase64.length % 4 !== 0) {
                    nestedBase64 += "=";
                  }
                  nestedBase64 = nestedBase64
                    .replace(/-/g, "+")
                    .replace(/_/g, "/");
                  decodedValue = NehonixSharedUtils.decodeB64(nestedBase64);
                }
                // Handle case where decoded value contains '&' (e.g., 'true&')
                if (decodedValue.includes("&")) {
                  return `${key}=${decodedValue.split("&")[0]}`; // Take only the first part
                }
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
            AppLogger.warn(`Failed to decode parameter ${key}: ${e}`);
          }
        }

        return param; // Keep original for non-decodable params
      });

      // Reconstruct URL with decoded parameters
      const decodedQueryString = decodedParams.join("&");
      const decodedURL = `${basePath}?${decodedQueryString}`;

      if (decodedURL !== input) {
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
          val: () => decodedURL,
          encodingType: paramEncoding,
          confidence: 0.85,
        };
      }
    }

    // Process nested encoding
    const detection = NDS.detectEncoding(input);
    let decodedValue = input;

    if (detection.isNested && detection.nestedTypes) {
      try {
        decodedValue = input;
        for (const encType of detection.nestedTypes) {
          decodedValue = NDS.decode({
            encodingType: encType as ENC_TYPE,
            input,
          });
        }

        return {
          val: () => decodedValue,
          encodingType: detection.mostLikely,
          confidence: detection.confidence,
          nestedTypes: detection.nestedTypes,
        };
      } catch (e: any) {
        AppLogger.error(`Error while decoding nested encodings:`, e);
      }
    }

    try {
      switch (detection.mostLikely) {
        case "percentEncoding":
          decodedValue = NDS.decodePercentEncoding(input);
          break;
        case "doublepercent":
          decodedValue = NDS.decodeDoublePercentEncoding(input);
          break;
        case "base64":
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
                const printableChars = decodedParam.replace(
                  /[^\x20-\x7E]/g,
                  ""
                ).length;
                const printableRatio = printableChars / decodedParam.length;

                if (printableRatio > 0.7) {
                  decodedValue = input.replace(value, decodedParam);
                  return {
                    val: () => decodedValue,
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

      const printableChars = decodedValue.replace(/[^\x20-\x7E]/g, "").length;
      const printableRatio = printableChars / decodedValue.length;

      if (printableRatio < 0.7 && detection.mostLikely !== "plainText") {
        AppLogger.warn(
          `Decoded value contains too many unprintable characters (${printableRatio.toFixed(
            2
          )}), reverting to original`
        );
        decodedValue = input;
      }
    } catch (e: any) {
      AppLogger.error(`Error while decoding using ${detection.mostLikely}:`, e);
      decodedValue = input;
    }

    return {
      val: () => decodedValue,
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
      AppLogger.warn(
        "Error while percent-decoding, attempting partial decoding"
      );
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
  //  * Decodes double percent encoding
  //  */
  // static decodeDoublePercentEncoding(input: string): string {
  //   // First decode %25XX to %XX, then decode %XX
  //   const firstPass = input.replace(/%25([0-9A-Fa-f]{2})/g, (match, hex) => {
  //     return `%${hex}`;
  //   });

  //   return NDS.decodePercentEncoding(firstPass);
  // }

  /**
   * Decodes hexadecimal encoding
   */
  /**
   * Fix 1: Proper hex string decoding implementation
   */
  static decodeHex(input: string): string {
    // Remove any whitespace and convert to lowercase
    input = input.trim().toLowerCase();

    // Check if input is a valid hex string
    if (!/^[0-9a-f]+$/.test(input)) {
      if (this.throwError) {
        throw new Error("Invalid hex string");
      }
    }

    // Ensure even number of characters
    if (input.length % 2 !== 0) {
      throw new Error("Hex string must have an even number of characters");
    }

    try {
      let result = "";
      for (let i = 0; i < input.length; i += 2) {
        const hexByte = input.substring(i, i + 2);
        const charCode = parseInt(hexByte, 16);
        result += String.fromCharCode(charCode);
      }
      return result;
    } catch (e: any) {
      throw new Error(`Hex decoding failed: ${e.message}`);
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
    const entities: { [key: string]: string } = htmlEntities;

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
        AppLogger.warn(
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
    if (depth > MAX_DEPTH || !input || input.length < 2) {
      return {
        types: ["plainText"],
        mostLikely: "plainText",
        confidence: 1.0,
      };
    }

    const detectionScores: Record<string, number> = {};
    const utils = NehonixSharedUtils;
    const isValidUrl = ncu.isValidUrl(input, NDS.default_checkurl_opt);

    // First, check for mixed encoding patterns
    const percentEncodedSegments = input.match(/%[0-9A-Fa-f]{2}/g);
    const hasPercentEncodedParts =
      percentEncodedSegments && percentEncodedSegments.length > 0;

    // Check what percentage of the input is percent-encoded
    if (hasPercentEncodedParts) {
      const encodedCharCount = percentEncodedSegments.length * 3; // Each %XX is 3 chars
      const encodedRatio = encodedCharCount / input.length;

      if (encodedRatio > 0.8) {
        // Mostly percent-encoded
        detectionScores["percentEncoding"] = 0.9;
      } else {
        // Partially percent-encoded
        detectionScores["partialPercentEncoding"] = 0.75 + encodedRatio * 0.2;
        // Also recognize it's still partially plain text
        detectionScores["plainText"] = 0.5 + (1 - encodedRatio) * 0.4;
      }
    }

    // Special handling for URLs
    try {
      if (isValidUrl) {
        // URL parameters may have individual encodings
        const url = new URL(input);
        if (url.search && url.search.length > 1) {
          // Track URL parameter encodings
          let hasEncodedParams = false;

          for (const [_, value] of new URLSearchParams(url.search)) {
            // Check for common encodings in parameter values
            if (/%[0-9A-Fa-f]{2}/.test(value)) {
              detectionScores["percentEncoding"] = Math.max(
                detectionScores["percentEncoding"] || 0,
                0.85
              );
              hasEncodedParams = true;
            }
            if (/^[A-Za-z0-9+\/=]{4,}$/.test(value)) {
              detectionScores["base64"] = Math.max(
                detectionScores["base64"] || 0,
                0.82
              );
              hasEncodedParams = true;
            }
            if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
              detectionScores["rawHexadecimal"] = Math.max(
                detectionScores["rawHexadecimal"] || 0,
                0.8
              );
              hasEncodedParams = true;
            }
            if (/\\u[0-9A-Fa-f]{4}/.test(value)) {
              detectionScores["unicode"] = Math.max(
                detectionScores["unicode"] || 0,
                0.85
              );
              hasEncodedParams = true;
            }
            if (/\\x[0-9A-Fa-f]{2}/.test(value)) {
              detectionScores["jsEscape"] = Math.max(
                detectionScores["jsEscape"] || 0,
                0.83
              );
              hasEncodedParams = true;
            }
          }

          if (hasEncodedParams) {
            detectionScores["url"] = 0.9; // High confidence this is a URL with encoded params
          }
        }
      }
    } catch (e) {
      // URL parsing failed, continue with normal detection
    }

    // Standard encoding detection checks
    const detectionChecks: {
      type: ENC_TYPE;
      fn: (s: string) => boolean;
      score: number;
      minLength?: number; // Minimum input length for this encoding
      partialDetectionFn?: (s: string) => { isPartial: boolean; ratio: number };
    }[] = [
      { type: "doublepercent", fn: utils.isDoublePercent, score: 0.95 },
      {
        type: "percentEncoding",
        fn: utils.isPercentEncoding,
        score: 0.9,
        partialDetectionFn: (s: string) => {
          const matches = s.match(/%[0-9A-Fa-f]{2}/g);
          const isPartial = matches !== null && matches.length > 0;
          const ratio = isPartial ? (matches.length * 3) / s.length : 0;
          return { isPartial, ratio };
        },
      },
      {
        type: "base64",
        fn: utils.isBase64,
        score: 0.9,
        minLength: 4,
        partialDetectionFn: (s: string) => {
          const base64Segments = s.match(/[A-Za-z0-9+\/=]{4,}/g);
          const isPartial =
            base64Segments !== null &&
            base64Segments.some((seg) => seg.length >= 4);
          let totalBase64Length = 0;
          if (isPartial && base64Segments) {
            totalBase64Length = base64Segments.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalBase64Length / s.length };
        },
      },
      {
        type: "urlSafeBase64",
        fn: utils.isUrlSafeBase64,
        score: 0.93,
        minLength: 4,
      },
      { type: "base32", fn: utils.isBase32, score: 0.88, minLength: 8 },
      { type: "asciihex", fn: utils.isAsciiHex, score: 0.85 },
      { type: "asciioct", fn: utils.isAsciiOct, score: 0.85 },
      {
        type: "hex",
        fn: utils.isHex,
        score: 0.8,
        minLength: 6,
        partialDetectionFn: (s: string) => {
          const hexSegments = s.match(/[0-9A-Fa-f]{6,}/g);
          const isPartial = hexSegments !== null && hexSegments.length > 0;
          let totalHexLength = 0;
          if (isPartial && hexSegments) {
            totalHexLength = hexSegments.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalHexLength / s.length };
        },
      },
      {
        type: "rawHexadecimal",
        fn: utils.hasRawHexString,
        score: 0.85,
        minLength: 4,
      },
      {
        type: "unicode",
        fn: utils.isUnicode,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const unicodeMatches = s.match(/\\u[0-9A-Fa-f]{4}/g);
          const isPartial =
            unicodeMatches !== null && unicodeMatches.length > 0;
          let totalUnicodeLength = 0;
          if (isPartial && unicodeMatches) {
            totalUnicodeLength = unicodeMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalUnicodeLength / s.length };
        },
      },
      {
        type: "htmlEntity",
        fn: utils.isHtmlEntity,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const entityMatches = s.match(
            /&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g
          );
          const isPartial = entityMatches !== null && entityMatches.length > 0;
          let totalEntityLength = 0;
          if (isPartial && entityMatches) {
            totalEntityLength = entityMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalEntityLength / s.length };
        },
      },
      { type: "decimalHtmlEntity", fn: utils.isDecimalHtmlEntity, score: 0.83 },
      { type: "quotedPrintable", fn: utils.isQuotedPrintable, score: 0.77 },
      { type: "punycode", fn: utils.isPunycode, score: 0.9 },
      { type: "rot13", fn: utils.isRot13.bind(utils), score: 0.9 },
      { type: "utf7", fn: utils.isUtf7, score: 0.75 },
      {
        type: "jsEscape",
        fn: utils.isJsEscape,
        score: 0.8,
        partialDetectionFn: (s: string) => {
          const jsEscapeMatches = s.match(
            /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g
          );
          const isPartial =
            jsEscapeMatches !== null && jsEscapeMatches.length > 0;
          let totalEscapeLength = 0;
          if (isPartial && jsEscapeMatches) {
            totalEscapeLength = jsEscapeMatches.reduce(
              (sum, seg) => sum + seg.length,
              0
            );
          }
          return { isPartial, ratio: totalEscapeLength / s.length };
        },
      },
      { type: "cssEscape", fn: utils.isCssEscape, score: 0.78 },
      { type: "jwt", fn: utils.hasJWTFormat, score: 0.95, minLength: 15 },
    ];

    for (const {
      type,
      fn,
      score,
      minLength,
      partialDetectionFn,
    } of detectionChecks) {
      // Skip checks if input is too short for this encoding
      if (minLength && input.length < minLength) continue;

      try {
        // First, try full detection
        if (fn(input)) {
          detectionScores[type] = score;

          // Try to verify by decoding and checking result
          try {
            const decoded = NDS.decodeSingle(input, type);
            if (decoded && decoded !== input) {
              // Calculate how "sensible" the decoded result is
              const printableChars = decoded.replace(
                /[^\x20-\x7E]/g,
                ""
              ).length;
              const printableRatio = printableChars / decoded.length;

              if (printableRatio > 0.8) {
                // Boost confidence for successful decoding
                detectionScores[type] += 0.05;
              } else if (printableRatio < 0.5) {
                // Reduce confidence for gibberish output
                detectionScores[type] -= 0.1;
              }
            }
          } catch (_) {
            // Failed to decode, reduce confidence slightly
            detectionScores[type] -= 0.1;
          }
        }
        // Then, try partial detection if available
        else if (partialDetectionFn) {
          const partialResult = partialDetectionFn(input);
          if (partialResult.isPartial) {
            // Calculate confidence based on the ratio of encoded content
            const partialConfidence = 0.6 + partialResult.ratio * 0.3;
            detectionScores[
              `partial${type.charAt(0).toUpperCase() + type.slice(1)}`
            ] = partialConfidence;

            // If a significant portion is encoded, try to decode those parts
            if (partialResult.ratio > 0.3) {
              try {
                const partialDecode = NDS.tryPartialDecode(input, type);
                if (partialDecode.success) {
                  // Successful partial decoding boosts confidence
                  detectionScores[
                    `partial${type.charAt(0).toUpperCase() + type.slice(1)}`
                  ] += 0.05;
                }
              } catch (_) {
                // Partial decoding failed, continue
              }
            }
          }
        }
      } catch (e) {
        // Skip failed detection checks
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

    // Check for mixed encoding patterns
    if (Object.keys(detectionScores).length > 1) {
      // If we have multiple different encodings, it might be mixed
      const encodingTypes = Object.keys(detectionScores);
      if (encodingTypes.some((type) => type.startsWith("partial"))) {
        detectionScores["mixedEncoding"] = 0.85; // High confidence this is mixed encoding
      }
    }

    // Fallback: plain text if no encodings detected
    if (Object.keys(detectionScores).length === 0) {
      detectionScores["plainText"] = 1.0;
    } else {
      // Always include plainText as a possibility with appropriate confidence
      // The more encoded it seems, the less likely it's plain text
      const maxNonPlainTextScore = Math.max(
        ...Object.entries(detectionScores)
          .filter(([type]) => type !== "plainText")
          .map(([_, score]) => score)
      );

      if (maxNonPlainTextScore < 0.8) {
        // If other encoding confidence is low, plain text is still likely
        detectionScores["plainText"] = 1.0 - maxNonPlainTextScore;
      }
    }

    // Sort by confidence
    const sorted = Object.entries(detectionScores).sort((a, b) => b[1] - a[1]);

    // Build the result
    const result: EncodingDetectionResult = {
      types: sorted.map(([type]) => type),
      mostLikely: sorted[0][0] as ENC_TYPE,
      confidence: sorted[0][1],
    };

    // Add partial encoding info if detected
    const partialEncodings = sorted
      .filter(([type]) => type.startsWith("partial"))
      .map(([type, score]) => ({
        type: type.replace("partial", "").toLowerCase(),
        confidence: score,
      }));

    if (partialEncodings.length > 0) {
      result.partialEncodings = partialEncodings;
    }

    // Include nested encoding info if available
    if (depth < MAX_DEPTH) {
      const nested = NDS.detectNestedEncoding(input, depth + 1);
      if (nested.isNested) {
        result.isNested = true;
        if (nested.outerType && nested.innerType)
          result.nestedTypes = [nested.outerType, nested.innerType];
      }
    }

    return result;
  }

  /**
   * Attempts to decode parts of a string that appear to be encoded
   * @param input The potentially partially encoded string
   * @param encodingType The encoding type to try
   * @returns Object indicating success and decoded parts
   */
  static tryPartialDecode(
    input: string,
    encodingType: ENC_TYPE
  ): {
    success: boolean;
    decoded?: string;
  } {
    try {
      switch (encodingType) {
        case "percentEncoding":
          // Replace percent-encoded segments
          return {
            success: true,
            decoded: input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
              try {
                return decodeURIComponent(match);
              } catch {
                return match;
              }
            }),
          };

        case "htmlEntity":
          // Replace HTML entities
          return {
            success: true,
            decoded: input.replace(
              /&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g,
              (match) => {
                try {
                  const tempEl = document.createElement("div");
                  tempEl.innerHTML = match;
                  return tempEl.textContent || match;
                } catch {
                  return match;
                }
              }
            ),
          };

        case "unicode":
          // Replace Unicode escape sequences
          return {
            success: true,
            decoded: input.replace(/\\u[0-9A-Fa-f]{4}/g, (match) => {
              try {
                return String.fromCharCode(parseInt(match.slice(2), 16));
              } catch {
                return match;
              }
            }),
          };

        case "jsEscape":
          // Replace JavaScript escape sequences
          return {
            success: true,
            decoded: input.replace(
              /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g,
              (match) => {
                try {
                  return JSON.parse(`"${match}"`);
                } catch {
                  return match;
                }
              }
            ),
          };

        default:
          return { success: false };
      }
    } catch (e) {
      return { success: false };
    }
  }

  /**
   * Helper function to detect nested encodings
   * @param input The string to analyze
   * @param depth Current recursion depth
   * @returns Information about detected nested encodings
   */
  static detectNestedEncoding(
    input: string,
    depth = 0
  ): {
    isNested: boolean;
    outerType?: ENC_TYPE | "mixedEncoding";
    innerType?: ENC_TYPE | "mixedEncoding";
    confidenceScore: number;
  } {
    // Implementation similar to the original, with improved detection for partial encodings
    const MAX_DEPTH = 3;
    if (depth > MAX_DEPTH) {
      return { isNested: false, confidenceScore: 0 };
    }

    try {
      // First identify the most likely outer encoding
      const outerResult = NDS.detectEncoding(input, depth);
      if (outerResult.mostLikely === "plainText") {
        return { isNested: false, confidenceScore: 0 };
      }

      // Try to decode the outer layer
      let decoded: string;
      try {
        decoded = NDS.decodeSingle(input, outerResult.mostLikely);
      } catch (e) {
        return { isNested: false, confidenceScore: 0 };
      }

      if (!decoded || decoded === input) {
        return { isNested: false, confidenceScore: 0 };
      }

      // Check for inner encoding in the decoded result
      const innerResult = NDS.detectEncoding(decoded, depth + 1);
      if (innerResult.mostLikely === "plainText") {
        return { isNested: false, confidenceScore: 0 };
      }

      // Validate by trying to decode both layers
      try {
        const fullyDecoded = NDS.decodeSingle(decoded, innerResult.mostLikely);

        if (
          fullyDecoded &&
          fullyDecoded !== decoded &&
          fullyDecoded !== input
        ) {
          // Calculate confidence based on how "clean" the decoded result is
          const printableRatio =
            fullyDecoded.replace(/[^\x20-\x7E]/g, "").length /
            fullyDecoded.length;
          const confidenceBoost = printableRatio > 0.8 ? 0.1 : 0;

          return {
            isNested: true,
            outerType: outerResult.mostLikely,
            innerType: innerResult.mostLikely,
            confidenceScore: Math.min(
              0.95,
              outerResult.confidence * 0.7 +
                innerResult.confidence * 0.3 +
                confidenceBoost
            ),
          };
        }
      } catch (e) {
        // Decoding failed, probably not nested
      }

      return { isNested: false, confidenceScore: 0 };
    } catch (e) {
      return { isNested: false, confidenceScore: 0 };
    }
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
    if (!input.includes("\\")) return input;

    try {
      // Handle various JavaScript escape sequences
      return input.replace(
        /\\(x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|[0-7]{1,3}|.)/g,
        (match, escape) => {
          if (escape.startsWith("x")) {
            // Hex escape \xFF
            return String.fromCharCode(parseInt(escape.substring(1), 16));
          } else if (escape.startsWith("u")) {
            // Unicode escape \uFFFF
            return String.fromCharCode(parseInt(escape.substring(1), 16));
          } else if (/^[0-7]+$/.test(escape)) {
            // Octal escape \000
            return String.fromCharCode(parseInt(escape, 8));
          } else {
            // Single character escapes like \n, \t, etc.
            switch (escape) {
              case "n":
                return "\n";
              case "t":
                return "\t";
              case "r":
                return "\r";
              case "b":
                return "\b";
              case "f":
                return "\f";
              case "v":
                return "\v";
              case "0":
                return "\0";
              default:
                return escape; // For \", \', \\, etc.
            }
          }
        }
      );
    } catch (e) {
      AppLogger.warn("JS escape decode error:", e);
      return input;
    }
  }
  static decodeCharacterEscapes(input: string): string {
    // Handle JavaScript/C-style character escapes: \x74\x72\x75\x65
    return input.replace(
      /\\x([0-9A-Fa-f]{2})|\\([0-7]{1,3})|\\u([0-9A-Fa-f]{4})/g,
      (match, hex, octal, unicode) => {
        if (hex) {
          return String.fromCharCode(parseInt(hex, 16));
        } else if (octal) {
          return String.fromCharCode(parseInt(octal, 8));
        } else if (unicode) {
          return String.fromCharCode(parseInt(unicode, 16));
        }
        return match;
      }
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
  static decodeAnyToPlaintext(
    input: string,
    opt: UriHandlerInterface = {
      output: { encodeUrl: false },
    }
  ): DecodeResult {
    this.throwError = false;
    let result = input;
    let lastResult = "";
    let iterations = 0;
    let confidence = 0;
    let encodingType:
      | ENC_TYPE
      | "UNKNOWN_TYPE"
      | "plainText"
      | "mixedEncoding" = "UNKNOWN_TYPE";
    const maxIterations = opt.maxIterations || 12;
    const decodingHistory: Array<{
      result: string;
      type: string;
      confidence: number;
    }> = [];

    // Smart initial handling for URLs
    const isUrl = ncu.isValidUrl(result, NDS.default_checkurl_opt);
    if (isUrl) {
      const paramProcessed = NDS.handleUriParameters(
        result,
        maxIterations,
        opt
      );
      if (paramProcessed !== result) {
        result = paramProcessed;
        decodingHistory.push({
          result,
          type: "urlParameters",
          confidence: 0.9,
        });
      }
    }

    // Iterate until no changes or max iterations reached
    while (iterations < maxIterations && result !== lastResult) {
      lastResult = result;
      const detection = NDS.detectEncoding(result);

      // Stop if confident it's plain text
      if (detection.mostLikely === "plainText" && detection.confidence > 0.85) {
        confidence = detection.confidence;
        encodingType = "plainText";
        break;
      }

      // Try all detected encoding types in order of confidence
      const typesToTry = detection.types
        .map((type) => ({
          type,
          confidence:
            type === detection.mostLikely
              ? detection.confidence
              : detection.partialEncodings?.find(
                  (e) => e.type === type.replace("partial", "").toLowerCase()
                )?.confidence || 0.5,
        }))
        .filter((t) => t.confidence > 0.5)
        .sort((a, b) => b.confidence - a.confidence);

      let decodedSuccessfully = false;
      for (const { type, confidence: typeConfidence } of typesToTry) {
        try {
          let decoded: string;
          encodingType = type as ENC_TYPE;

          // Handle partial encodings
          if (type.startsWith("partial")) {
            const baseType =
              type.replace("partial", "").charAt(0).toLowerCase() +
              type.replace("partial", "").slice(1);
            decoded = NDS.decodePartial(result, baseType as ENC_TYPE);
          } else {
            decoded = NDS.decodeSingle(result, type as ENC_TYPE);
          }

          // Validate decoded result quality
          const printableChars = decoded.replace(/[^\x20-\x7E]/g, "").length;
          const totalChars = decoded.length || 1;
          const printableRatio = printableChars / totalChars;

          if (
            decoded !== result &&
            decoded.length > 0 &&
            printableRatio > 0.7
          ) {
            decodingHistory.push({
              result: decoded,
              type,
              confidence: typeConfidence,
            });
            result = decoded;
            confidence = typeConfidence;
            decodedSuccessfully = true;
            break; // Exit the loop after a successful decode
          }
        } catch (e) {
          AppLogger.warn(`Error in auto-decode (${type}): ${e}`);
          continue; // Try the next encoding type
        }
      }

      if (!decodedSuccessfully) {
        // No successful decoding, stop iteration
        break;
      }

      iterations++;
    }

    // Final validation
    const finalPrintableRatio =
      result.replace(/[^\x20-\x7E]/g, "").length / (result.length || 1);
    if (finalPrintableRatio < 0.65 && decodingHistory.length > 0) {
      const bestResult = decodingHistory
        .filter((h) => {
          const ratio =
            h.result.replace(/[^\x20-\x7E]/g, "").length /
            (h.result.length || 1);
          return ratio > 0.7;
        })
        .sort((a, b) => b.confidence - a.confidence)[0];

      if (bestResult) {
        result = bestResult.result;
        confidence = bestResult.confidence;
        encodingType = bestResult.type as any;
      } else {
        result = input;
        confidence = 0.5;
        encodingType = "UNKNOWN_TYPE";
      }
    }

    return {
      confidence,
      encodingType,
      val: () => result,
      decodingHistory,
    };
  }

  private static handleUriParameters(
    uri: string,
    maxIterations: number,
    opt: UriHandlerInterface
  ) {
    let result = uri;
    try {
      // Use URL constructor for better parsing
      const parsedUrl = new URL(uri);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
      const queryParams = new URLSearchParams(parsedUrl.search);

      if (queryParams.toString() === "") return result;

      let modified = false;
      const decodedParams: string[] = [];

      // Process each parameter
      for (const [key, value] of queryParams.entries()) {
        if (!value || value.length < 2) {
          decodedParams.push(`${key}=${value}`);
          continue;
        }

        // First try auto-detection for better accuracy
        const detection = NDS.detectEncoding(value);
        let decodedValue = value;

        // Add this special case for character escapes
        if (
          value.includes("\\x") ||
          value.includes("\\u") ||
          value.includes("\\0")
        ) {
          try {
            const unescaped = NDS.decodeCharacterEscapes(value);
            if (unescaped !== value) {
              decodedValue = unescaped;
              modified = true;
              continue;
            }
          } catch {
            // Failed to decode escapes, continue with normal processing
          }
        }
        if (
          detection.confidence > 0.6 &&
          detection.mostLikely !== "plainText"
        ) {
          try {
            // Apply the detected encoding method
            decodedValue = NDS.decodeSingle(
              value,
              detection.mostLikely as ENC_TYPE
            );

            // Verify the quality of decoded result
            const printableChars = decodedValue.replace(
              /[^\x20-\x7E]/g,
              ""
            ).length;
            const printableRatio = printableChars / decodedValue.length;

            // Check if result makes sense and has enough printable characters
            if (printableRatio < 0.7 || decodedValue.length < 1) {
              decodedValue = value; // Revert if garbage
            } else {
              modified = true;

              // Handle nested encodings recursively (with depth protection)
              if (
                decodedValue.includes("%") ||
                NehonixCoreUtils.hasBase64Pattern(decodedValue)
              ) {
                const nestedResult = NDS.decodeAnyToPlaintext(decodedValue, {
                  maxIterations: maxIterations - 1,
                });

                if (nestedResult.confidence > 0.7) {
                  decodedValue = nestedResult.val();
                  modified = true;
                }
              }
            }
          } catch (e) {
            AppLogger.warn(`Parameter decode error (${key}=${value}):`, e);
          }
        }

        decodedParams.push(`${key}=${decodedValue}`);
      }

      // Only rebuild URL if changes were made
      if (modified) {
        result = `${baseUrl}?${decodedParams.join("&")}`;
      }
    } catch (e) {
      AppLogger.warn("URL parameter processing error:", e);
    }

    return opt.output?.encodeUrl ? encodeURI(result) : result;
  }

  // static decodeSingle(input: string, encodingType: ENC_TYPE): string {
  //   try {
  //     switch (encodingType) {
  //       case "percentEncoding":
  //       case "url":
  //         return NDS.decodePercentEncoding(input);
  //       case "doublepercent":
  //         return NDS.decodeDoublePercentEncoding(input);
  //       case "base64":
  //         let base64Input = input;
  //         // Fix padding
  //         while (base64Input.length % 4 !== 0) {
  //           base64Input += "=";
  //         }
  //         // Fix URL-safe variants
  //         base64Input = base64Input.replace(/-/g, "+").replace(/_/g, "/");
  //         return NehonixSharedUtils.decodeB64(base64Input);
  //       case "urlSafeBase64":
  //         return NDS.decodeUrlSafeBase64(input);
  //       case "base32":
  //         return NDS.decodeBase32(input);
  //       case "hex":
  //         return NDS.decodeHex(input);
  //       case "rawHexadecimal":
  //         return NDS.decodeRawHex(input);
  //       case "unicode":
  //         return NDS.decodeUnicode(input);
  //       case "htmlEntity":
  //         return NDS.decodeHTMLEntities(input);
  //       case "decimalHtmlEntity":
  //         return NDS.decodeDecimalHtmlEntity(input);
  //       case "punycode":
  //         return NDS.decodePunycode(input);
  //       case "rot13":
  //         return NDS.decodeRot13(input);
  //       case "asciihex":
  //         return NDS.decodeAsciiHex(input);
  //       case "asciioct":
  //         return NDS.decodeAsciiOct(input);
  //       case "jsEscape":
  //         return NDS.decodeJsEscape(input);
  //       case "cssEscape":
  //         return NDS.decodeCssEscape(input);
  //       case "utf7":
  //         return NDS.decodeUtf7(input);
  //       case "quotedPrintable":
  //         return NDS.decodeQuotedPrintable(input);
  //       case "jwt":
  //         return NDS.decodeJWT(input);
  //       default:
  //         return input;
  //     }
  //   } catch (e) {
  //     AppLogger.warn(`Single decode error (${encodingType}):`, e);
  //     return input;
  //   }
  // }

  /**
   * Decodes a string based on the specified encoding type
   * @param input The string to decode
   * @param encodingType The encoding type to use for decoding
   * @returns The decoded string
   */
  static decodeSingle(
    input: string,
    encodingType: ENC_TYPE | "mixedEncoding" | "plainText"
  ): string {
    try {
      // Handle partial encoding types by routing to partial decoder
      if (encodingType.startsWith("partial")) {
        const baseType =
          encodingType.replace("partial", "").charAt(0).toLowerCase() +
          encodingType.replace("partial", "").slice(1);
        return NDS.decodePartial(input, baseType as ENC_TYPE);
      }

      // Handle mixed encoding type
      if (encodingType === "mixedEncoding") {
        return NDS.decodeMixed(input);
      }

      // Handle nested encoding types
      if (encodingType.startsWith("nested:")) {
        const encodingTypes = encodingType.slice(7).split("+");
        if (encodingTypes.length === 2) {
          const outerType = encodingTypes[0] as ENC_TYPE;
          const innerType = encodingTypes[1] as ENC_TYPE;
          const intermediate = NDS.decodeSingle(input, outerType);
          return NDS.decodeSingle(intermediate, innerType);
        }
      }

      // Standard encoding types
      switch (encodingType) {
        case "percentEncoding":
        case "url":
          return NDS.decodePercentEncoding(input);
        case "doublepercent":
          return NDS.decodeDoublePercentEncoding(input);
        case "base64":
          let base64Input = input;
          // Fix padding
          while (base64Input.length % 4 !== 0) {
            base64Input += "=";
          }
          // Fix URL-safe variants
          base64Input = base64Input.replace(/-/g, "+").replace(/_/g, "/");
          return NehonixSharedUtils.decodeB64(base64Input);
        case "urlSafeBase64":
          return NDS.decodeUrlSafeBase64(input);
        case "base32":
          return NDS.decodeBase32(input);
        case "hex":
          return NDS.decodeHex(input);
        case "rawHexadecimal":
          return NDS.decodeRawHex(input);
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
        default:
          return input;
      }
    } catch (e) {
      AppLogger.warn(`Single decode error (${encodingType}):`, e);
      return input;
    }
  }

  /**
   * Decodes a partially encoded string, preserving non-encoded parts
   * @param input The partially encoded string
   * @param baseEncodingType The base encoding type (without "partial" prefix)
   * @returns The decoded string with non-encoded parts preserved
   */
  static decodePartial(input: string, baseEncodingType: ENC_TYPE): string {
    try {
      switch (baseEncodingType) {
        case "percentEncoding":
          // Decode only percent-encoded segments
          return input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
            try {
              return decodeURIComponent(match);
            } catch (e) {
              // If decoding fails, return the original segment
              return match;
            }
          });

        case "base64":
          // Find and decode base64 segments
          return input.replace(/[A-Za-z0-9+\/=]{4,}/g, (match) => {
            try {
              // Only decode if it's a valid base64 string
              if (/^[A-Za-z0-9+\/=]+$/.test(match) && match.length % 4 === 0) {
                const decoded = NehonixSharedUtils.decodeB64(match);
                // Verify if the result is readable text (printable ASCII)
                const isPrintable = /^[\x20-\x7E]+$/.test(decoded);
                return isPrintable ? decoded : match;
              }
              return match;
            } catch (e) {
              return match;
            }
          });

        case "urlSafeBase64":
          // Find and decode URL-safe base64 segments
          return input.replace(/[A-Za-z0-9\-_=]{4,}/g, (match) => {
            try {
              // Only decode if it's a valid URL-safe base64 string
              if (/^[A-Za-z0-9\-_=]+$/.test(match)) {
                const standard = match.replace(/-/g, "+").replace(/_/g, "/");
                const padded =
                  standard + "=".repeat((4 - (standard.length % 4)) % 4);
                const decoded = NehonixSharedUtils.decodeB64(padded);
                // Verify if the result is readable text (printable ASCII)
                const isPrintable = /^[\x20-\x7E]+$/.test(decoded);
                return isPrintable ? decoded : match;
              }
              return match;
            } catch (e) {
              return match;
            }
          });

        case "htmlEntity":
          // Decode only HTML entity segments
          return input.replace(
            /&[a-zA-Z]+;|&#[0-9]+;|&#x[0-9a-fA-F]+;/g,
            (match) => {
              try {
                const tempEl = document.createElement("div");
                tempEl.innerHTML = match;
                return tempEl.textContent || match;
              } catch (e) {
                return match;
              }
            }
          );

        case "unicode":
          // Decode only Unicode escape sequences
          return input.replace(/\\u[0-9A-Fa-f]{4}/g, (match) => {
            try {
              return String.fromCharCode(parseInt(match.slice(2), 16));
            } catch (e) {
              return match;
            }
          });

        case "jsEscape":
          // Decode JavaScript escape sequences
          return input.replace(
            /\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\[0-7]{3}/g,
            (match) => {
              try {
                return JSON.parse(`"${match}"`);
              } catch (e) {
                return match;
              }
            }
          );

        case "rawHexadecimal":
          // Find potential hex sequences and try to decode them
          return input.replace(/[0-9A-Fa-f]{2,}/g, (match) => {
            try {
              // Only attempt to decode if it's an even length hex string
              if (match.length % 2 === 0) {
                let decoded = "";
                for (let i = 0; i < match.length; i += 2) {
                  const hexPair = match.substring(i, i + 2);
                  const charCode = parseInt(hexPair, 16);
                  // Only convert if it's a printable ASCII character
                  if (charCode >= 32 && charCode <= 126) {
                    decoded += String.fromCharCode(charCode);
                  } else {
                    // Non-printable character, abort and return original
                    return match;
                  }
                }
                return decoded;
              }
              return match;
            } catch (e) {
              return match;
            }
          });

        default:
          // For other encoding types, just return the input
          return input;
      }
    } catch (e) {
      AppLogger.warn(`Partial decode error (${baseEncodingType}):`, e);
      return input;
    }
  }

  /**
   * Attempts to decode a string with mixed encoding types
   * @param input The string with mixed encodings
   * @returns The decoded string
   */
  static decodeMixed(input: string): string {
    try {
      // First detect what type of encodings might be present
      const detection = NDS.detectEncoding(input);

      // Get all partial encoding types
      const partialTypes = detection.types
        .filter((type) => type.startsWith("partial"))
        .map(
          (type) =>
            (type.replace("partial", "").charAt(0).toLowerCase() +
              type.replace("partial", "").slice(1)) as ENC_TYPE
        );

      // If no partial types detected, try a different approach
      if (partialTypes.length === 0) {
        // Try common encoding types in sequence
        const commonTypes: ENC_TYPE[] = [
          "percentEncoding",
          "htmlEntity",
          "unicode",
          "jsEscape",
          "rawHexadecimal",
        ];

        // Apply partial decoding for each common type
        let result = input;
        for (const type of commonTypes) {
          result = NDS.decodePartial(result, type);
        }

        return result;
      }

      // Apply all detected partial decodings in sequence
      // Sort by confidence if available
      if (detection.partialEncodings) {
        partialTypes.sort((a, b) => {
          const aConf =
            detection.partialEncodings!.find((e) => e.type === a)?.confidence ||
            0;
          const bConf =
            detection.partialEncodings!.find((e) => e.type === b)?.confidence ||
            0;
          return bConf - aConf; // Highest confidence first
        });
      }

      // Apply decodings in order
      let result = input;
      for (const type of partialTypes) {
        result = NDS.decodePartial(result, type);
      }

      return result;
    } catch (e) {
      AppLogger.warn("Mixed encoding decode error:", e);
      return input;
    }
  }

  // /**
  //  * Decodes URL percent encoding
  //  * @param input The percent-encoded string
  //  * @returns The decoded string
  //  */
  // static decodePercentEncoding(input: string): string {
  //   try {
  //     return decodeURIComponent(input);
  //   } catch (e) {
  //     // Handle malformed input by attempting partial decoding
  //     return NDS.decodePartial(input, "percentEncoding");
  //   }
  // }

  /**
   * Decodes double percent encoding (e.g., %2520 -> %20 -> space)
   * @param input The double percent-encoded string
   * @returns The decoded string
   */
  static decodeDoublePercentEncoding(input: string): string {
    // First decode once to get single percent encoding
    const singleEncoded = NDS.decodePercentEncoding(input);
    // Then decode again to get plain text
    return NDS.decodePercentEncoding(singleEncoded);
  }

  /**
   * Tries various decoding strategies to find the best result
   * @param input The encoded string
   * @returns The best decoded result
   */
  static smartDecode(input: string): string {
    try {
      // First detect the encoding
      const detection = NDS.detectEncoding(input);

      // If it's a mixed encoding or has partial encodings
      if (
        detection.mostLikely === "mixedEncoding" ||
        detection.types.some((t) => t.startsWith("partial"))
      ) {
        return NDS.decodeMixed(input);
      }

      // If it's a nested encoding
      if (
        detection.isNested &&
        detection.nestedTypes &&
        detection.nestedTypes.length === 2
      ) {
        const [outerType, innerType] = detection.nestedTypes;
        const intermediate = NDS.decodeSingle(input, outerType);
        return NDS.decodeSingle(intermediate, innerType);
      }

      // Regular encoding
      return NDS.decodeSingle(input, detection.mostLikely);
    } catch (e) {
      AppLogger.warn("Smart decode error:", e);
      return input;
    }
  }

  /**
   * Enhanced URL parameter extraction and decoding
   * @param url The URL string to process
   * @returns URL with decoded parameters
   */
  static decodeUrlParameters(url: string) {
    const checkUri = ncu.checkUrl(url, NDS.default_checkurl_opt);
    if (!checkUri.isValid) {
      checkUri.cause && AppLogger.warn(checkUri.cause);
      return url;
    }
    if (!url.includes("?")) return url;

    try {
      const [baseUrl, queryString] = url.split("?", 2);
      if (!queryString) return url;

      // Split parameters manually to preserve &&
      const params = queryString.split(/&{1,2}/);
      let modified = false;
      const decodedParams: string[] = [];

      for (const param of params) {
        const [key, value] = param.includes("=")
          ? param.split("=", 2)
          : [param, ""];
        if (!value || value.length < 3) {
          decodedParams.push(param);
          continue;
        }

        const encodingTypes = [
          { type: "percentEncoding", pattern: /%[0-9A-Fa-f]{2}/ },
          { type: "base64", pattern: /^[A-Za-z0-9+/=]{4,}$/ },
          { type: "hex", pattern: /^[0-9A-Fa-f]{6,}$/ },
        ];

        let decoded = value;
        for (const { type, pattern } of encodingTypes) {
          if (pattern.test(value)) {
            try {
              decoded = NDS.decode({
                input: value,
                encodingType: type as ENC_TYPE,
              });
              if (decoded !== value && decoded.length > 0) {
                const printableRatio =
                  decoded.replace(/[^\x20-\x7E]/g, "").length / decoded.length;
                if (printableRatio > 0.8) {
                  modified = true;
                  break;
                }
              }
            } catch (e) {
              continue;
            }
          }
        }

        if (!modified && decoded === value) {
          try {
            decoded = NDS.decodeAnyToPlaintext(value, {
              maxIterations: 3,
            }).val();
            if (decoded !== value) {
              modified = true;
            }
          } catch (e) {
            // Keep original
          }
        }

        decodedParams.push(`${key}=${decoded}`);
      }

      const separator = queryString.includes("&&") ? "&&" : "&";
      return modified ? `${baseUrl}?${decodedParams.join(separator)}` : url;
    } catch (e) {
      AppLogger.warn("Error decoding URL parameters:", e);
      return url;
    }
  }

  static decodeMixedContent(input: string): string {
    // Check if input has both percent-encoded and Base64 parts
    let result = input;

    // First, handle percent encoding
    if (input.includes("%")) {
      result = NDS.decodePercentEncoding(result);
    }

    // Then, look for Base64 patterns and decode them
    const base64Pattern = /[A-Za-z0-9+/=]{4,}/g;
    const potentialBase64Matches = result.match(base64Pattern);

    if (potentialBase64Matches) {
      for (const match of potentialBase64Matches) {
        // Only try to decode if it's a valid Base64 string
        if (NehonixSharedUtils.isBase64(match)) {
          try {
            const decoded = NehonixSharedUtils.decodeB64(match);
            // Only replace if the decoded string looks reasonable
            const printableChars = decoded.replace(
              /[^\x20-\x7E\t\r\n]/g,
              ""
            ).length;
            if (printableChars / decoded.length > 0.7) {
              result = result.replace(match, decoded);
            }
          } catch {
            // Failed to decode, leave as is
          }
        }
      }
    }

    return result;
  }

  static detectAndHandleRawHexUrl(input: string): string {
    // Check if input matches a hex pattern for a URL
    if (/^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0) {
      try {
        const decoded = NDS.decodeRawHex(input);
        // Check if the decoded result looks like a URL
        if (/^https?:\/\/|^http:\/\/|^ftp:\/\/|www\./i.test(decoded)) {
          return decoded;
        }
      } catch {
        // Not a valid hex URL
      }
    }
    return input;
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

  /**
   * Main decode method with improved error handling
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
      AppLogger.warn("Maximum recursion depth reached in decode");
      return input;
    }

    try {
      // Special case for "any" encoding
      if (encodingType === "any") {
        return NDS.decodeAnyToPlaintext(input, {
          maxIterations: 5,
        }).val();
      }

      // Special case for URLs - handle parameter decoding
      if (input.includes("://") && input.includes("?")) {
        // For URLs with parameters, pre-process to decode parameters individually
        if (encodingType === "url" || encodingType === "percentEncoding") {
          const preprocessed = NDS.decodeUrlParameters(input);

          // If preprocessing made changes, return that result
          if (preprocessed !== input) {
            return preprocessed;
          }
        }
      }

      // Try to handle special case: mixed encoding types
      if (
        (input.includes("%") && /[A-Za-z0-9+/=]{4,}/.test(input)) ||
        (input.includes("\\x") && /[A-Za-z0-9+/=]{4,}/.test(input))
      ) {
        return NDS.decodeMixedContent(input);
      }

      // Regular handling for specific encoding types
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
        default:
          if (opt.throwError) {
            throw new Error(`Unsupported encoding type: ${encodingType}`);
          } else {
            return "Error skipped";
          }
      }
    } catch (e: any) {
      AppLogger.error(`Error while decoding (${encodingType}):`, e);
      if (opt.throwError) {
        throw e;
      }
      return input; // Return original input on error
    }
  }

  /**
   * Asynchronously decodes any encoded text to plaintext
   * @param input The encoded string to decode
   * @param opt Optional configuration for the decoding process
   * @returns A Promise that resolves to the DecodeResult containing the decoded string
   */
  static asyncDecodeAnyToPlainText(
    input: string,
    opt: UriHandlerInterface = {
      output: { encodeUrl: false },
    }
  ): Promise<DecodeResult> {
    return new Promise((resolve, reject) => {
      try {
        const result = NDS.decodeAnyToPlaintext(input, opt);
        resolve(result);
        // return result;
      } catch (error) {
        reject(error);
      }
    });
  }
}

export { NDS as NehonixDecService };
export default NDS;
