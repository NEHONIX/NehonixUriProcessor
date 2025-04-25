const { htmlEntities } = require("../../src/utils/html.enties");

// Worker message types
const WorkerMessageType = {
  DECODE: "decode",
  RESULT: "result",
  ERROR: "error",
};

// Mock AppLogger for Worker context
const AppLogger = {
  error: (message, error) => console.error(`[Worker] ${message}`, error),
  warn: (message, error) => console.warn(`[Worker] ${message}`, error),
};

// Mock NehonixSharedUtils (essential functions)
const NehonixSharedUtils = {
  decodeB64: (input) => {
    try {
      // Ensure proper padding
      let padded = input.replace(/-/g, "+").replace(/_/g, "/");
      while (padded.length % 4 !== 0) {
        padded += "=";
      }
      return atob(padded);
    } catch (e) {
      throw new Error(`Base64 decoding failed: ${e.message}`);
    }
  },
  isBase64: (input) => {
    const base64Regex = /^[A-Za-z0-9+/=]+$/;
    return base64Regex.test(input) && input.length % 4 === 0;
  },
  isPercentEncoding: (input) => /%[0-9A-Fa-f]{2}/.test(input),
  isDoublePercent: (input) => /%25[0-9A-Fa-f]{2}/.test(input),
  isHex: (input) => /^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0,
  isUnicode: (input) => /\\u[0-9A-Fa-f]{4}/.test(input),
  isHtmlEntity: (input) => /&[a-zA-Z0-9#]+;/.test(input),
  isUrlSafeBase64: (input) => /^[A-Za-z0-9_-]+$/i.test(input),
  isRot13: (input) => /^[a-zA-Z]+$/.test(input),
  hasJWTFormat: (input) =>
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input),
  drwp: (hexString) => {
    let result = "";
    for (let i = 0; i < hexString.length; i += 2) {
      const hexByte = hexString.substring(i, i + 2);
      result += String.fromCharCode(parseInt(hexByte, 16));
    }
    return result;
  },
};

// Mock NehonixCoreUtils (essential functions)
const NehonixCoreUtils = {
  hasBase64Pattern: (input) => /[A-Za-z0-9+/=]{4,}/.test(input),
  hasHexEncoding: (input) =>
    /^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0,
  hasRawHexString: (input) =>
    /^[0-9A-Fa-f]+$/.test(input) && input.length % 2 === 0,
  isValidUrl: (input, options) => {
    try {
      new URL(input);
      return true;
    } catch {
      return false;
    }
  },
  checkUrl: (input, options) => {
    try {
      new URL(input);
      return { isValid: true };
    } catch (e) {
      return { isValid: false, cause: e.message };
    }
  },
};

// Simplified types from NehonixDecService
const ENC_TYPE = {
  percentEncoding: "percentEncoding",
  doublepercent: "doublepercent",
  base64: "base64",
  urlSafeBase64: "urlSafeBase64",
  hex: "hex",
  rawHexadecimal: "rawHexadecimal",
  unicode: "unicode",
  htmlEntity: "htmlEntity",
  rot13: "rot13",
  jwt: "jwt",
  plainText: "plainText",
};

// NehonixDecService implementation (inlined)
const NehonixDecService = {
  default_checkurl_opt: {
    allowLocalhost: true,
    rejectDuplicatedValues: false,
    maxUrlLength: "NO_LIMIT",
    strictMode: false,
    strictParamEncoding: false,
    debug: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: false,
  },

  decodePercentEncoding: (input) => {
    try {
      return decodeURIComponent(input);
    } catch {
      return input.replace(/%[0-9A-Fa-f]{2}/g, (match) => {
        try {
          return decodeURIComponent(match);
        } catch {
          return match;
        }
      });
    }
  },

  decodeDoublePercentEncoding: (input) => {
    const firstPass = input.replace(
      /%25([0-9A-Fa-f]{2})/g,
      (match, hex) => `%${hex}`
    );
    return NehonixDecService.decodePercentEncoding(firstPass);
  },

  decodeBase64: (input) => {
    let base64Input = input;
    while (base64Input.length % 4 !== 0) {
      base64Input += "=";
    }
    return NehonixSharedUtils.decodeB64(
      base64Input.replace(/-/g, "+").replace(/_/g, "/")
    );
  },

  decodeUrlSafeBase64: (input) => {
    const standardBase64 = input.replace(/-/g, "+").replace(/_/g, "/");
    let padded = standardBase64;
    while (padded.length % 4 !== 0) {
      padded += "=";
    }
    return NehonixSharedUtils.decodeB64(padded);
  },

  decodeHex: (input) => {
    input = input.trim().toLowerCase();
    if (!/^[0-9a-f]+$/.test(input)) {
      throw new Error("Invalid hex string");
    }
    if (input.length % 2 !== 0) {
      throw new Error("Hex string must have an even number of characters");
    }
    let result = "";
    for (let i = 0; i < input.length; i += 2) {
      const hexByte = input.substring(i, i + 2);
      const charCode = parseInt(hexByte, 16);
      result += String.fromCharCode(charCode);
    }
    return result;
  },

  decodeRawHex: (input) => {
    if (input.includes("=")) {
      const parts = input.split("=");
      const prefix = parts.slice(0, parts.length - 1).join("=") + "=";
      const hexString = parts[parts.length - 1];
      if (!/^[0-9A-Fa-f]+$/.test(hexString) || hexString.length % 2 !== 0) {
        return input;
      }
      return prefix + NehonixSharedUtils.drwp(hexString);
    } else if (input.includes("?") || input.includes("/")) {
      const regex = /([?\/])([0-9A-Fa-f]+)(?=[?\/]|$)/g;
      return input.replace(regex, (match, delimiter, hexPart) => {
        if (!/^[0-9A-Fa-f]+$/.test(hexPart) || hexPart.length % 2 !== 0) {
          return match;
        }
        try {
          return delimiter + NehonixSharedUtils.drwp(hexPart);
        } catch {
          return match;
        }
      });
    } else {
      if (!/^[0-9A-Fa-f]+$/.test(input) || input.length % 2 !== 0) {
        return input;
      }
      return NehonixSharedUtils.drwp(input);
    }
  },

  decodeUnicode: (input) => {
    try {
      return input
        .replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) =>
          String.fromCodePoint(parseInt(hex, 16))
        )
        .replace(/\\u\{([0-9A-Fa-f]+)\}/g, (match, hex) =>
          String.fromCodePoint(parseInt(hex, 16))
        );
    } catch (e) {
      throw new Error(`Unicode decoding failed: ${e.message}`);
    }
  },

  decodeHTMLEntities: (input) => {
    let result = input;
    for (const [entity, char] of Object.entries(htmlEntities)) {
      result = result.replace(new RegExp(entity, "g"), char);
    }
    result = result.replace(/&#(\d+);/g, (match, dec) =>
      String.fromCodePoint(parseInt(dec, 10))
    );
    result = result.replace(/&#x([0-9A-Fa-f]+);/g, (match, hex) =>
      String.fromCodePoint(parseInt(hex, 16))
    );
    return result;
  },

  decodeRot13: (input) => {
    return input.replace(/[a-zA-Z]/g, (char) => {
      const code = char.charCodeAt(0);
      if (code >= 65 && code <= 90) {
        return String.fromCharCode(((code - 65 + 13) % 26) + 65);
      } else if (code >= 97 && code <= 122) {
        return String.fromCharCode(((code - 97 + 13) % 26) + 97);
      }
      return char;
    });
  },

  decodeJWT: (input) => {
    const parts = input.split(".");
    if (parts.length !== 3) throw new Error("Invalid JWT format");
    try {
      const header = NehonixSharedUtils.decodeB64(
        parts[0].replace(/-/g, "+").replace(/_/g, "/")
      );
      const payload = NehonixSharedUtils.decodeB64(
        parts[1].replace(/-/g, "+").replace(/_/g, "/")
      );
      const headerObj = JSON.parse(header);
      const payloadObj = JSON.parse(payload);
      return JSON.stringify(
        { header: headerObj, payload: payloadObj, signature: "[signature]" },
        null,
        2
      );
    } catch (e) {
      throw new Error(`JWT decoding failed: ${e.message}`);
    }
  },

  detectEncoding: (input, depth = 0) => {
    const MAX_DEPTH = 3;
    if (depth > MAX_DEPTH || !input || input.length < 2) {
      return { types: ["plainText"], mostLikely: "plainText", confidence: 1.0 };
    }

    const detectionScores = {};
    const isValidUrl = NehonixCoreUtils.isValidUrl(
      input,
      NehonixDecService.default_checkurl_opt
    );

    if (isValidUrl) {
      try {
        const url = new URL(input);
        if (url.search && url.search.length > 1) {
          let hasEncodedParams = false;
          for (const [_, value] of new URLSearchParams(url.search)) {
            if (/%[0-9A-Fa-f]{2}/.test(value)) {
              detectionScores["percentEncoding"] = 0.85;
              hasEncodedParams = true;
            }
            if (/^[A-Za-z0-9+\/=]{4,}$/.test(value)) {
              detectionScores["base64"] = 0.82;
              hasEncodedParams = true;
            }
            if (/^[0-9A-Fa-f]+$/.test(value) && value.length % 2 === 0) {
              detectionScores["rawHexadecimal"] = 0.8;
              hasEncodedParams = true;
            }
            if (/\\u[0-9A-Fa-f]{4}/.test(value)) {
              detectionScores["unicode"] = 0.85;
              hasEncodedParams = true;
            }
          }
          if (hasEncodedParams) {
            detectionScores["url"] = 0.9;
          }
        }
      } catch {}
    }

    const detectionChecks = [
      {
        type: "doublepercent",
        fn: NehonixSharedUtils.isDoublePercent,
        score: 0.95,
      },
      {
        type: "percentEncoding",
        fn: NehonixSharedUtils.isPercentEncoding,
        score: 0.9,
      },
      {
        type: "base64",
        fn: NehonixSharedUtils.isBase64,
        score: 0.9,
        minLength: 4,
      },
      {
        type: "urlSafeBase64",
        fn: NehonixSharedUtils.isUrlSafeBase64,
        score: 0.93,
        minLength: 4,
      },
      { type: "hex", fn: NehonixSharedUtils.isHex, score: 0.8, minLength: 6 },
      {
        type: "rawHexadecimal",
        fn: NehonixSharedUtils.hasRawHexString,
        score: 0.85,
        minLength: 4,
      },
      { type: "unicode", fn: NehonixSharedUtils.isUnicode, score: 0.8 },
      { type: "htmlEntity", fn: NehonixSharedUtils.isHtmlEntity, score: 0.8 },
      { type: "rot13", fn: NehonixSharedUtils.isRot13, score: 0.9 },
      {
        type: "jwt",
        fn: NehonixSharedUtils.hasJWTFormat,
        score: 0.95,
        minLength: 15,
      },
    ];

    for (const { type, fn, score, minLength } of detectionChecks) {
      if (minLength && input.length < minLength) continue;
      try {
        if (fn(input)) {
          detectionScores[type] = score;
          try {
            const decoded = NehonixDecService.decodeSingle(input, type);
            if (decoded && decoded !== input) {
              const printableChars = decoded.replace(
                /[^\x20-\x7E]/g,
                ""
              ).length;
              const printableRatio = printableChars / decoded.length;
              if (printableRatio > 0.8) {
                detectionScores[type] += 0.05;
              } else if (printableRatio < 0.5) {
                detectionScores[type] -= 0.1;
              }
            }
          } catch {
            detectionScores[type] -= 0.1;
          }
        }
      } catch {}
    }

    if (Object.keys(detectionScores).length === 0) {
      detectionScores["plainText"] = 1.0;
    }

    const sorted = Object.entries(detectionScores).sort((a, b) => b[1] - a[1]);
    return {
      types: sorted.map(([type]) => type),
      mostLikely: sorted[0][0],
      confidence: sorted[0][1],
    };
  },

  decodeSingle: (input, encodingType) => {
    try {
      switch (encodingType) {
        case "percentEncoding":
        case "url":
          return NehonixDecService.decodePercentEncoding(input);
        case "doublepercent":
          return NehonixDecService.decodeDoublePercentEncoding(input);
        case "base64":
          return NehonixDecService.decodeBase64(input);
        case "urlSafeBase64":
          return NehonixDecService.decodeUrlSafeBase64(input);
        case "hex":
          return NehonixDecService.decodeHex(input);
        case "rawHexadecimal":
          return NehonixDecService.decodeRawHex(input);
        case "unicode":
          return NehonixDecService.decodeUnicode(input);
        case "htmlEntity":
          return NehonixDecService.decodeHTMLEntities(input);
        case "rot13":
          return NehonixDecService.decodeRot13(input);
        case "jwt":
          return NehonixDecService.decodeJWT(input);
        default:
          return input;
      }
    } catch (e) {
      AppLogger.warn(`Single decode error (${encodingType}):`, e);
      return input;
    }
  },

  handleUriParameters: (uri, maxIterations, opt) => {
    let result = uri;
    try {
      const parsedUrl = new URL(uri);
      const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}${parsedUrl.pathname}`;
      const queryParams = new URLSearchParams(parsedUrl.search);
      if (queryParams.toString() === "") return result;

      let modified = false;
      const decodedParams = [];
      for (const [key, value] of queryParams.entries()) {
        if (!value || value.length < 2) {
          decodedParams.push(`${key}=${value}`);
          continue;
        }
        const detection = NehonixDecService.detectEncoding(value);
        let decodedValue = value;
        if (
          detection.confidence > 0.6 &&
          detection.mostLikely !== "plainText"
        ) {
          try {
            decodedValue = NehonixDecService.decodeSingle(
              value,
              detection.mostLikely
            );
            const printableChars = decodedValue.replace(
              /[^\x20-\x7E]/g,
              ""
            ).length;
            const printableRatio = printableChars / decodedValue.length;
            if (printableRatio < 0.7 || decodedValue.length < 1) {
              decodedValue = value;
            } else {
              modified = true;
            }
          } catch (e) {
            AppLogger.warn(`Parameter decode error (${key}=${value}):`, e);
          }
        }
        decodedParams.push(`${key}=${decodedValue}`);
      }
      if (modified) {
        result = `${baseUrl}?${decodedParams.join("&")}`;
      }
    } catch (e) {
      AppLogger.warn("URL parameter processing error:", e);
    }
    return opt.output?.encodeUrl ? encodeURI(result) : result;
  },

  decodeAnyToPlaintext: (input, opt = { output: { encodeUrl: false } }) => {
    let result = input;
    let lastResult = "";
    let iterations = 0;
    let confidence = 0;
    let encodingType = "UNKNOWN_TYPE";
    const maxIterations = opt.maxIterations || 10;
    const decodingHistory = [];
    const isUrl = NehonixCoreUtils.isValidUrl(
      result,
      NehonixDecService.default_checkurl_opt
    );

    if (isUrl) {
      const paramProcessed = NehonixDecService.handleUriParameters(
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

    while (iterations < maxIterations && result !== lastResult) {
      lastResult = result;
      const detection = NehonixDecService.detectEncoding(result);
      if (detection.mostLikely === "plainText" && detection.confidence > 0.85) {
        confidence = detection.confidence;
        encodingType = "plainText";
        break;
      }
      if (detection.confidence > 0.5) {
        try {
          let decoded = NehonixDecService.decodeSingle(
            result,
            detection.mostLikely
          );
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
              type: detection.mostLikely,
              confidence: detection.confidence,
            });
            result = decoded;
          } else {
            break;
          }
        } catch (e) {
          AppLogger.warn(`Error in auto-decode: ${e}`);
          break;
        }
      } else {
        break;
      }
      iterations++;
    }

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
        encodingType = bestResult.type;
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
  },
};

// Worker message handler
self.onmessage = async (event) => {
  const { type, data } = event.data;

  if (type !== WorkerMessageType.DECODE) {
    self.postMessage({
      type: WorkerMessageType.ERROR,
      error: `Invalid message type: ${type}`,
    });
    return;
  }

  const { input, maxIterations } = data;

  try {
    const result = NehonixDecService.decodeAnyToPlaintext(input, {
      maxIterations,
    });
    self.postMessage({
      type: WorkerMessageType.RESULT,
      data: result.val(),
    });
  } catch (e) {
    AppLogger.error("Worker decoding error:", e.message);
    self.postMessage({
      type: WorkerMessageType.ERROR,
      error: `Decoding failed: ${e.message}`,
    });
  }
};

// Error handling for uncaught errors
self.onerror = (error) => {
  AppLogger.error("Worker uncaught error:", error);
  self.postMessage({
    type: WorkerMessageType.ERROR,
    error: `Uncaught error: ${error.message || "Unknown error"}`,
  });
};
