import { AppLogger } from "../common/AppLogger";
import { NehonixSharedUtils } from "../common/NehonixCommonUtils";
import { sr } from "../rules/security.rules";
import {
  ComparisonRule,
  UrlCheckResult,
  UrlValidationOptions,
  ValidUrlComponents,
} from "../types";

export class NehonixCoreUtils extends NehonixSharedUtils {
  // =============== ENCODING DETECTION METHODS ===============

  /**
   * Checks a URL string and returns detailed validation results.
   * @param url The URL string to check
   * @param options Validation options
   * @returns UrlCheckResult object with detailed validation information
   */
  /**
   * Checks a URL string and returns detailed validation results.
   * @param url The URL string to check
   * @param options Validation options
   * @returns UrlCheckResult object with detailed validation information
   */
  static checkUrl(
    url: string,
    options: UrlValidationOptions = {
      strictMode: false,
      allowUnicodeEscapes: true,
      rejectDuplicateParams: true,
      httpsOnly: false,
      maxUrlLength: 2048,
      allowedTLDs: [],
      allowedProtocols: ["http", "https"],
      requireProtocol: false,
      requirePathOrQuery: false,
      strictParamEncoding: false,
      rejectDuplicatedValues: false,
      debug: false,
    }
  ): UrlCheckResult {
    const result: UrlCheckResult = {
      isValid: true,
      validationDetails: {},
      cause: "",
    };
    AppLogger.debugs_state = options.debug || false;

    // Check URL length
    if (options.maxUrlLength) {
      if (
        typeof options.maxUrlLength === "number" &&
        options.maxUrlLength > 0 &&
        url.length > options.maxUrlLength
      ) {
        const message = `URL exceeds maximum length of ${options.maxUrlLength} characters`;
        result.cause = message;
        result.validationDetails.length = {
          isValid: false,
          message,
          actualLength: url.length,
          maxLength: options.maxUrlLength,
        };
        result.isValid = false;
        return result;
      } else {
        const message = `URL length is within the allowed limit of ${options.maxUrlLength} characters`;
        result.validationDetails.length = {
          isValid: true,
          message,
          actualLength: url.length,
          maxLength: options.maxUrlLength,
        };
      }
    }

    // Check if URL is empty
    if (!url.trim()) {
      const message = "URL is empty or contains only whitespace";
      result.cause = message;
      result.validationDetails.emptyCheck = {
        isValid: false,
        message,
      };
      result.isValid = false;
      return result;
    } else {
      result.validationDetails.emptyCheck = {
        isValid: true,
        message: "URL contains valid content",
      };
    }

    try {
      // Handle protocol requirements
      let parsedUrl = url;
      const hasProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);

      if (!hasProtocol) {
        if (options.requireProtocol) {
          const message =
            "A protocol (e.g., 'http://' or 'https://') is required";
          result.cause = message;
          result.validationDetails.protocol = {
            isValid: false,
            message,
            allowedProtocols: options.allowedProtocols,
          };
          result.isValid = false;
          return result;
        }
        result.cause = "";
        parsedUrl = "https://" + url;
      }

      // Parse the URL
      let urlObj: URL | null = null;
      try {
        urlObj = new URL(url);
      } catch (error: any) {
        result.validationDetails.parsing = {
          isValid: false,
          message: `Failed to parse URL: ${error.message}`,
        };
        result.isValid = false;
        return result;
      }

      // Process custom validations
      if (options.customValidations && options.customValidations.length > 0) {
        const validationResults: {
          isValid: boolean;
          message: string;
          rule: ComparisonRule;
        }[] = [];

        // Valid string-returning URL properties
        const validUrlComponents: ValidUrlComponents[] = [
          "href",
          "origin",
          "protocol",
          "username",
          "password",
          "host",
          "hostname",
          "port",
          "pathname",
          "search",
          "hash",
        ];

        for (const [component, operator, value] of options.customValidations) {
          let leftValue: string | number | undefined;
          let isValid = false;
          let message = "";

          // Validate component
          if (component === "literal") {
            if (options.literalValue === undefined) {
              result.cause =
                "'literalValue' option is required when the left value is 'literal'";
              isValid = false;
              message =
                "Literal comparison failed: 'literalValue' option is required";
            } else {
              leftValue = options.literalValue;
            }
          }
          // Add handler for fullCustomValidation components
          else if (
            component.startsWith("fullCustomValidation.") ||
            component.startsWith("fcv.")
          ) {
            const c = component;
            const customKey =
              c.substring("fullCustomValidation.".length) ||
              c.substring("fcv.".length);

            if (
              !options.fullCustomValidation ||
              !(customKey in options.fullCustomValidation)
            ) {
              isValid = false;
              message = `Custom validation failed: Property '${customKey}' not found in fullCustomValidation object`;
            } else {
              leftValue = options.fullCustomValidation[customKey];
            }
          } else if (
            !validUrlComponents.includes(component as ValidUrlComponents)
          ) {
            isValid = false;
            message = `Invalid URL component '${component}'; expected one of: ${validUrlComponents.join(
              ", "
            )} or a fullCustomValidation property (fullCustomValidation.[key])`;
          } else {
            leftValue = urlObj[component as keyof URL] as string;
          }

          // Perform comparison if leftValue is defined
          if (leftValue !== undefined) {
            switch (operator) {
              case "===":
                isValid = leftValue === value;
                break;
              case "==":
                isValid = leftValue == value;
                break;
              case "!==":
                isValid = leftValue !== value;
                break;
              case "!=":
                isValid = leftValue != value;
                break;
              case "<=":
                isValid = leftValue <= value;
                break;
              case ">=":
                isValid = leftValue >= value;
                break;
              case "<":
                isValid = leftValue < value;
                break;
              case ">":
                isValid = leftValue > value;
                break;
            }
            message = isValid
              ? `Validation passed: ${component} ${operator} ${value}`
              : `Validation failed: ${component} ${operator} ${value} (actual: ${
                  leftValue || "NONE"
                })`;
          }

          // Debug logging
          if (options.debug) {
            AppLogger.log(
              `[DEBUG] Custom Validation: ${component} ${operator} ${value}`
            );
            AppLogger.log(
              `[DEBUG] Left Value: ${
                leftValue !== undefined ? leftValue : "undefined"
              }`
            );
            AppLogger.log(`[DEBUG] Result: ${message}`);
          }

          validationResults.push({
            isValid,
            message,
            rule: [component, operator, value],
          });

          if (!isValid) {
            result.isValid = false;
          }
        }

        result.validationDetails.customValidations = {
          isValid: validationResults.every((r) => r.isValid),
          message: validationResults.map((r) => r.message).join("; "),
          results: validationResults,
        };

        if (!result.isValid) {
          result.cause = "One or more custom validations failed";
          return result;
        }
      }

      // Protocol validation
      const protocol = urlObj.protocol.replace(":", "");
      if (options.allowedProtocols) {
        if (
          options.allowedProtocols.length > 0 &&
          !options.allowedProtocols.includes(protocol)
        ) {
          const message = `Invalid protocol detected. Expected one of (${options.allowedProtocols
            .map((p) => `"${p}"`)
            .join(", ")}), but received "${protocol}".`;
          const explanationMessage =
            "The provided protocol is not included in the list of allowed protocols. Please verify your configuration or input URL.";

          result.cause = message;
          result.validationDetails.protocol = {
            isValid: false,
            message: explanationMessage,
            detectedProtocol: protocol,
            allowedProtocols: options.allowedProtocols,
          };
          result.isValid = false;
          return result;
        } else {
          result.cause = "";
          result.validationDetails.protocol = {
            isValid: true,
            message: `Protocol '${protocol}' is allowed`,
            detectedProtocol: protocol,
            allowedProtocols: options.allowedProtocols,
          };
        }
      }

      // HTTPS-only validation
      if (options.httpsOnly && protocol !== "https") {
        const message = "Only HTTPS protocol is allowed";
        result.cause = message;
        result.validationDetails.httpsOnly = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.httpsOnly = {
          isValid: true,
          message: options.httpsOnly
            ? "HTTPS protocol is used"
            : "Protocol meets requirements",
        };
      }

      // Domain validation
      const hostParts = urlObj.hostname.split(".");
      if (
        (hostParts.length < 2 || hostParts.some((part) => part === "")) &&
        !(options.allowLocalhost && urlObj.hostname === "localhost")
      ) {
        const message = `Invalid hostname '${
          urlObj.hostname
        }'; expected a valid domain${
          options.allowLocalhost ? " or 'localhost'" : ""
        }`;
        result.cause = message;
        result.validationDetails.domain = {
          isValid: false,
          type: "INV_DOMAIN_ERR",
          error: "Invalid domain structure",
          message,
          hostname: urlObj.hostname,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.domain = {
          isValid: true,
          type: "INV_DOMAIN_ERR",
          message:
            options.allowLocalhost && urlObj.hostname === "localhost"
              ? "Localhost is valid"
              : "Domain structure is valid",
          hostname: urlObj.hostname,
        };
      }

      // TLD validation
      if (options.allowedTLDs) {
        if (options.allowedTLDs.length > 0) {
          const tld = hostParts[hostParts.length - 1].toLowerCase();
          if (!options.allowedTLDs.includes(tld)) {
            const message = `TLD '${tld}' is not allowed; expected one of: ${options.allowedTLDs.join(
              ", "
            )}`;
            result.cause = message;
            result.validationDetails.tld = {
              isValid: false,
              message,
              detectedTld: tld,
              allowedTlds: options.allowedTLDs,
            };
            result.isValid = false;
            return result;
          } else {
            result.validationDetails.tld = {
              isValid: true,
              message: `TLD '${tld}' is allowed`,
              detectedTld: tld,
              allowedTlds: options.allowedTLDs,
            };
          }
        }
      }

      // Path/query requirement validation
      if (
        options.requirePathOrQuery &&
        urlObj.pathname === "/" &&
        !urlObj.search
      ) {
        const message = "A path or query string is required";
        result.cause = message;
        result.validationDetails.pathOrQuery = {
          isValid: false,
          message,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.pathOrQuery = {
          isValid: true,
          message: "Path or query requirements are met",
        };
      }

      // Strict mode path validation
      if (options.strictMode && urlObj.pathname === "/" && urlObj.search) {
        const message =
          "A leading slash is required in the path for strict mode";
        result.cause = message;
        result.validationDetails.strictMode = {
          isValid: false,
          message:
            "In strict mode, a leading slash (e.g., '/path') is required for the path",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.strictMode = {
          isValid: true,
          message: options.strictMode
            ? "Path meets strict mode requirements"
            : "Strict mode is not enabled",
        };
      }

      // Check for unencoded spaces in query string
      if (urlObj.search.includes(" ")) {
        result.validationDetails.querySpaces = {
          isValid: false,
          message:
            "Query string contains unencoded spaces; encode spaces as '%20'",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.querySpaces = {
          isValid: true,
          message: "Query string contains no unencoded spaces",
        };
      }

      // Strict parameter encoding validation
      if (options.strictParamEncoding && urlObj.search) {
        const rawQuery = urlObj.search.substring(1);
        const params = rawQuery.split("&");
        const invalidParams: string[] = [];

        for (const param of params) {
          if (param.includes("=")) {
            const [key, value] = param.split("=", 2);
            try {
              const decodedKey = decodeURIComponent(key);
              const reEncodedKey = encodeURIComponent(decodedKey);
              if (key !== reEncodedKey && !key.includes("+")) {
                invalidParams.push(key);
              }
              if (value) {
                const decodedValue = decodeURIComponent(value);
                const reEncodedValue = encodeURIComponent(decodedValue);
                if (value !== reEncodedValue && !value.includes("+")) {
                  invalidParams.push(value);
                }
              }
            } catch {
              invalidParams.push(param);
            }
          }
        }

        if (invalidParams.length > 0) {
          result.validationDetails.paramEncoding = {
            isValid: false,
            message: `Invalid encoding in query parameters: ${invalidParams.join(
              ", "
            )}`,
            invalidParams,
          };
          result.isValid = false;
          return result;
        } else {
          result.validationDetails.paramEncoding = {
            isValid: true,
            message: "Query parameter encoding is valid",
          };
        }
      }

      // Check for duplicate query parameters
      const duplicatedState = this.detectDuplicatedValues(urlObj.href);

      if (
        options.rejectDuplicateParams &&
        duplicatedState.duplicatedKeys.length > 0
      ) {
        result.validationDetails.duplicateParams = {
          isValid: false,
          message: `Duplicate query parameter keys detected: ${duplicatedState.duplicatedKeys.join(
            ", "
          )}`,
          duplicatedKeys: duplicatedState.duplicatedKeys,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.duplicateParams = {
          isValid: true,
          message: options.rejectDuplicateParams
            ? "No duplicate query parameter keys found"
            : "Duplicate keys check is not enabled",
          duplicatedKeys: duplicatedState.duplicatedKeys,
        };
      }

      if (
        options.rejectDuplicatedValues &&
        duplicatedState.duplicatedValues.length > 0
      ) {
        result.validationDetails.duplicateValues = {
          isValid: false,
          message: `Duplicate query parameter values detected: ${duplicatedState.duplicatedValues.join(
            ", "
          )}`,
          duplicatedValues: duplicatedState.duplicatedValues,
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.duplicateValues = {
          isValid: true,
          message: options.rejectDuplicatedValues
            ? "No duplicate query parameter values found"
            : "Duplicate values check is not enabled",
          duplicatedValues: duplicatedState.duplicatedValues,
        };
      }

      // Unicode escape validation
      if (!options.allowUnicodeEscapes && /\\u[\da-f]{4}/i.test(url)) {
        result.validationDetails.unicodeEscapes = {
          isValid: false,
          message: "Unicode escape sequences (e.g., '\\uXXXX') are not allowed",
        };
        result.isValid = false;
        return result;
      } else {
        result.validationDetails.unicodeEscapes = {
          isValid: true,
          message: options.allowUnicodeEscapes
            ? "Unicode escape sequences are allowed"
            : "No unicode escape sequences detected",
        };
      }

      // Parsing success
      result.validationDetails.parsing = {
        isValid: true,
        message: "URL parsed successfully",
      };

      return result;
    } catch (error: any) {
      result.validationDetails.parsing = {
        isValid: false,
        message: `Failed to parse URL: ${error.message}`,
      };
      result.isValid = false;
      return result;
    }
  }
  /**
   * Validates a URL string according to specified options.
   * @param url The URL string to validate
   * @param options Validation options
   * @returns boolean indicating if the URL is valid
   */
  static isValidUrl(
    url: string,
    options: UrlValidationOptions = {
      strictMode: false,
      allowUnicodeEscapes: true,
      rejectDuplicateParams: true,
      httpsOnly: false,
      maxUrlLength: 2048,
      allowedTLDs: [],
      allowedProtocols: ["http", "https"],
      requireProtocol: false,
      requirePathOrQuery: false,
      strictParamEncoding: false,
    }
  ): boolean {
    const checkUri = this.checkUrl(url, options);
    return checkUri.isValid;
  }

  private static detectDuplicatedValues(uri: string) {
    // Input
    const url = new URL(uri); // e.g., "https://example.com?param1=value1&param2=value1&param1=value2"
    const parameters = Object.fromEntries(new URLSearchParams(url.search)); // { param1: "value2", param VHF

    // Step 1: Find duplicated keys in query string
    const params = new URLSearchParams(url.search);
    const keyCounts: Record<string, number> = {};
    for (const key of params.keys()) {
      keyCounts[key] = (keyCounts[key] || 0) + 1;
    }
    const duplicatedKeys = Object.keys(keyCounts).filter(
      (key) => keyCounts[key] > 1
    );

    // Step 2: Find duplicated values in parameters
    const valueToKeys: Record<string, string[]> = {};
    Object.entries(parameters).forEach(([key, value]) => {
      const valueKey = String(value ?? "null");
      if (!valueToKeys[valueKey]) valueToKeys[valueKey] = [];
      valueToKeys[valueKey].push(key);
    });
    const duplicatedValues = Object.values(valueToKeys)
      .filter((keys) => keys.length > 1)
      .flat();

    // Step 3: Combine results
    return {
      duplicatedKeys, // Keys repeated in query string
      duplicatedValues, // Keys sharing the same value
    };
  }
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

export { NehonixCoreUtils as ncu };
