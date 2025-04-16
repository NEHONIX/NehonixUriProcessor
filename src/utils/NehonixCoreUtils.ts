import { NehonixSharedUtils } from "../common/NehonixCommonUtils";
import { sr } from "../rules/security.rules";
import { UrlValidationOptions } from "../types";

export class NehonixCoreUtils extends NehonixSharedUtils {
  // =============== ENCODING DETECTION METHODS ===============

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
    // Check URL length if maximum is set
    if (options.maxUrlLength && url.length > options.maxUrlLength)
      if (options.maxUrlLength > 0 && url.length > options.maxUrlLength) {
        console.log("Maximum length ERR");
        return false;
      }

    // Check if URL is empty
    if (!url.trim()) {
      return false;
    }

    try {
      // Handle protocol requirements
      let parsedUrl = url;
      const hasProtocol = /^[a-z][a-z0-9+.-]*:\/\//i.test(url);

      if (!hasProtocol) {
        if (options.requireProtocol) {
          return false; // Protocol required but not provided
        }
        parsedUrl = "https://" + url;
      }

      // Parse the URL
      const urlObj = new URL(parsedUrl);
      const analysedUri = sr.analyzeURL(urlObj.href);

      // Protocol validation
      const protocol = urlObj.protocol.replace(":", "");
      if (options.allowedProtocols)
        if (
          options.allowedProtocols.length > 0 &&
          !options.allowedProtocols.includes(protocol)
        ) {
          return false;
        }

      // HTTPS-only validation
      if (options.httpsOnly && protocol !== "https") {
        return false;
      }

      // Domain validation
      const hostParts = urlObj.hostname.split(".");
      if (hostParts.length < 2 || hostParts.some((part) => part === "")) {
        return false;
      }

      // TLD validation
      if (options.allowedTLDs)
        if (options.allowedTLDs.length > 0) {
          const tld = hostParts[hostParts.length - 1].toLowerCase();
          if (!options.allowedTLDs.includes(tld)) {
            return false;
          }
        }

      // Path/query requirement validation
      if (
        options.requirePathOrQuery &&
        urlObj.pathname === "/" &&
        !urlObj.search
      ) {
        return false;
      }

      // Strict mode path validation
      if (options.strictMode && urlObj.pathname === "/" && urlObj.search) {
        return false; // In strict mode, query params must have a leading slash path
      }

      // Check for unencoded spaces in the query string
      if (urlObj.search.includes(" ")) {
        return false;
      }

      // Strict parameter encoding validation
      if (options.strictParamEncoding && urlObj.search) {
        const rawQuery = urlObj.search.substring(1);
        const params = rawQuery.split("&");

        for (const param of params) {
          if (param.includes("=")) {
            const [key, value] = param.split("=", 2);

            // Check if properly encoded
            try {
              const decodedKey = decodeURIComponent(key);
              const reEncodedKey = encodeURIComponent(decodedKey);

              if (key !== reEncodedKey && !key.includes("+")) {
                return false; // Key is not properly encoded
              }

              if (value) {
                const decodedValue = decodeURIComponent(value);
                const reEncodedValue = encodeURIComponent(decodedValue);

                if (value !== reEncodedValue && !value.includes("+")) {
                  return false; // Value is not properly encoded
                }
              }
            } catch {
              return false; // Malformed percent encoding
            }
          }
        }
      }

      // Check for duplicate query parameters
      let duplicatedState = this.detectDuplicatedValues(urlObj.href);

      if (options.rejectDuplicatedValues) {
        if (duplicatedState.duplicatedValues.length > 0) {
          console.warn("Duplicated values found in URI");
          return false;
        }
      }

      if (options.rejectDuplicateParams) {
        if (duplicatedState.duplicatedKeys.length > 0) {
          console.warn("Duplicated keys found in URI");
          return false;
        }
      }

      // Unicode escape validation
      if (!options.allowUnicodeEscapes) {
        const hasUnicodeEscapes = /\\u[\da-f]{4}/i.test(url);
        if (hasUnicodeEscapes) {
          return false;
        }
      }

      return true;
    } catch (error) {
      return false; // Any parsing error means invalid URL
    }
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
