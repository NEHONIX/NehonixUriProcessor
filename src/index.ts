import { NehonixEncService as enc } from "./services/NehonixEnc.service";
import { SecurityRules as sr } from "./rules/security.rules";
import NDS, { NehonixDecService as dec } from "./services/NehonixDec.service";
import { DEC_FEATURE_TYPE, ENC_TYPE } from "./types";
import { ncu } from "./utils/NehonixCoreUtils";
import NSS from "./services/NehonixSecurity.service";
import { NehonixSafetyLayer } from "./utils/NehonixSafetyLayer";

/**
 * A comprehensive library for detecting, encoding, and decoding URI strings, designed for security testing and attack analysis.
 * @author nehonix
 * @version 2.1.2
 * @since 12/04/2025
 * The `NehonixURIProcessor` class provides methods to analyze URLs, generate encoding variants for Web Application Firewall (WAF) bypass testing,
 * and automatically detect and decode various URI encodings. It supports a range of encoding types, including percent-encoding, Base64, and hexadecimal,
 * making it suitable for penetration testing, vulnerability assessment, and secure data processing.
 *
 * For detailed documentation on specific methods, see the [changelog](https://lab.nehonix.space/nehonix_viewer/_doc/NehonixUriProcessor/changelog) and method-specific guides.
 *
 * @example
 * ```typescript
 * // Check if a string is a valid URI
 * const isValid = NehonixURIProcessor.isValidUri("https://nehonix.space?test=true");
 * console.log(isValid); // true
 *
 * // Decode a Base64-encoded URI parameter
 * const decoded = NehonixURIProcessor.autoDetectAndDecode("https://nehonix.space?test=dHJ1ZQ==");
 * console.log(decoded); // https://nehonix.space?test=true
 *
 * // Generate WAF bypass variants
 * const variants = NehonixURIProcessor.generateWAFBypassVariants("<script>");
 * console.log(variants); // { percent: "%3Cscript%3E", base64: "PHNjcmlwdD4=", ... }
 * ```
 */
class NehonixURIProcessor {
  /**
   * Generates encoding variants of a string for Web Application Firewall (WAF) bypass testing.
   *
   * This method produces multiple encoded versions of the input string (e.g., percent-encoding, Base64, hexadecimal)
   * to test whether a WAF can be bypassed by obfuscating malicious payloads.
   *
   * @param input - The string to encode, typically a potentially malicious payload (e.g., `<script>`).
   * @returns An object containing different encoding variants, where keys are encoding types (e.g., `percent`, `base64`) and values are the encoded strings.
   * @example
   * ```typescript
   * const variants = NehonixURIProcessor.generateWAFBypassVariants("<script>");
   * console.log(variants);
   * // Output: { percent: "%3Cscript%3E", base64: "PHNjcmlwdD4=", hex: "3C7363726970743E", ... }
   * ```
   */
  static generateWAFBypassVariants(input: string) {
    return sr.generateWAFBypassVariants(input);
  }

  /**
   * Analyzes a URL to identify potentially vulnerable query parameters.
   *
   * This method parses the URL, extracts its query parameters, and evaluates them for common security vulnerabilities,
   * such as parameters commonly used for SQL injection, XSS, or other attacks.
   *
   * @param url - The URL to analyze (e.g., `https://nehonix.space?user=admin&pass=123`).
   * @returns An object containing the URL's components (e.g., domain, path, parameters) and a vulnerability assessment
   *          for each parameter, including potential attack vectors.
   * @example
   * ```typescript
   * const analysis = NehonixURIProcessor.analyzeURL("https://nehonix.space?user=admin");
   * console.log(analysis);
   * // Output: { url: "https://nehonix.space", params: { user: { value: "admin", risks: ["sql_injection", "xss"] } }, ... }
   * ```
   */
  static analyzeURL(...p: Parameters<typeof sr.analyzeURL>) {
    return sr.analyzeURL(...p);
  }

  /**
   * Encodes a string using the specified encoding type.
   *
   * Supports various encoding types defined in `ENC_TYPE`, such as percent-encoding, Base64, and hexadecimal.
   * Useful for preparing test payloads or obfuscating data.
   *
   * @param input - The string to encode (e.g., `hello world`).
   * @param encodingType - The encoding type to apply, as defined in `ENC_TYPE` (e.g., `percentEncoding`, `base64`).
   * @returns The encoded string (e.g., `hello%20world` for percent-encoding).
   * @throws Throws an error if the encoding type is unsupported or the input is invalid.
   * @example
   * ```typescript
   * const encoded = NehonixURIProcessor.encode("hello world", "percentEncoding");
   * console.log(encoded); // hello%20world
   *
   * const base64 = NehonixURIProcessor.encode("true", "base64");
   * console.log(base64); // dHJ1ZQ==
   * ```
   */
  static encode(input: string, encodingType: ENC_TYPE) {
    return enc.encode(input, encodingType);
  }

  /**
   * Detects the encoding type(s) of a URI string.
   *
   * Analyzes the input string to identify potential encodings (e.g., percent-encoding, Base64, hexadecimal) and their likelihood.
   * Supports recursive detection for nested encodings if a depth is specified.
   *
   * @param input - The URI string to analyze (e.g., `hello%20world` or `dHJ1ZQ==`).
   * @param [depth] - Optional recursion depth for detecting nested encodings (e.g., Base64 inside percent-encoding).
   *                  If omitted, performs a single-level analysis.
   * @returns An object containing the most likely encoding type, confidence score, and any detected nested encodings.
   * @example
   * ```typescript
   * const detection = NehonixURIProcessor.detectEncoding("hello%20world");
   * console.log(detection);
   * // Output: { mostLikely: "percentEncoding", confidence: 0.95, nestedTypes: [] }
   *
   * const nested = NehonixURIProcessor.detectEncoding("aHR0cHM6Ly9leGFtcGxlLmNvbQ==", 2);
   * console.log(nested);
   * // Output: { mostLikely: "base64", confidence: 0.9, nestedTypes: ["percentEncoding"], ... }
   * ```
   */
  static detectEncoding(input: string, depth?: number) {
    return dec.detectEncoding(input, depth);
  }

  /**
   * Automatically detects and decodes a URI string to plaintext.
   *
   * Uses advanced detection to identify the encoding type(s) and iteratively decodes the input until plaintext is reached
   * or the maximum recursion depth is met. Ideal for decoding complex or nested URI encodings.
   *
   * @version 1.1.1
   * @param input - The URI string to decode (e.g., `https://nehonix.space?test=dHJ1ZQ==`).
   * @param [maxIterations=10] - Maximum number of decoding iterations to prevent infinite loops.
   * @returns The decoded string in plaintext (e.g., `https://nehonix.space?test=true`).
   * @example
   * ```typescript
   * const decoded = NehonixURIProcessor.autoDetectAndDecode("https://nehonix.space?test=dHJ1ZQ==");
   * console.log(decoded.val()); // https://nehonix.space?test=true
   *
   * const nested = NehonixURIProcessor.autoDetectAndDecode("aHR0cHM6Ly9leGFtcGxlLmNvbQ==");
   * console.log(nested.val()); // https://nehonix.space
   * ```
   */
  static autoDetectAndDecode(
    ...props: Parameters<typeof dec.decodeAnyToPlaintext>
  ) {
    return dec.decodeAnyToPlaintext(...props);
  }

  /**
   * Automatically detects and decodes a URI string based on its encoding type.
   *
   * @deprecated Use `autoDetectAndDecode` instead for improved precision and performance.
   * @param input - The URI string to decode (e.g., `dHJ1ZQ==`).
   * @returns An object containing the decoded string, detected encoding type, and confidence score.
   * @example
   * ```typescript
   * const result = NehonixURIProcessor.detectAndDecode("dHJ1ZQ==");
   * console.log(result);
   * // Output: { val: "true", encodingType: "base64", confidence: 0.9 }
   * ```
   */
  static detectAndDecode(input: string) {
    return dec.detectAndDecode(input);
  }

  /**
   * Validates a URL string according to specified options.
   *
   * This method uses `checkUrl` to perform a comprehensive validation and returns a boolean indicating whether the URL
   * is valid based on the provided options. It supports validation of protocols, domains, TLDs, query parameters, and
   * encoding, with additional support for localhost when enabled.
   *
   * @param url - The URL string to validate (e.g., `https://nehonix.space?test=true`).
   * @param [options] - Optional configuration for validation rules.
   * @param [options.strictMode=false] - If `true`, requires a leading slash before query parameters.
   * @param [options.allowUnicodeEscapes=true] - If `true`, allows Unicode escape sequences in query parameters.
   * @param [options.rejectDuplicateParams=true] - If `true`, rejects URIs with duplicate query parameter keys.
   * @param [options.rejectDuplicatedValues=false] - If `true`, rejects URIs with duplicate query parameter values.
   * @param [options.httpsOnly=false] - If `true`, only allows `https://` URLs.
   * @param [options.maxUrlLength=2048] - Maximum allowed length for the entire URL.
   * @param [options.allowedTLDs=[]] - List of allowed top-level domains.
   * @param [options.allowedProtocols=['http', 'https']] - List of allowed protocols.
   * @param [options.requireProtocol=false] - If `true`, requires an explicit protocol in the URL.
   * @param [options.requirePathOrQuery=false] - If `true`, requires a path or query string.
   * @param [options.strictParamEncoding=false] - If `true`, validates proper URI encoding of query parameters.
   * @param [options.allowLocalhost=false] - If `true`, allows 'localhost' as a valid hostname.
   * @returns `true` if the URL is valid according to the specified options, `false` otherwise.
   * @example
   * ```typescript
   * const isValid = NehonixURIProcessor.isValidUrl("https://nehonix.space?test=true");
   * console.log(isValid); // true
   *
   * const isLocalhostValid = NehonixURIProcessor.isValidUrl("http://localhost:8080", { allowLocalhost: true });
   * console.log(isLocalhostValid); // true
   *
   * const isLocalhostInvalid = NehonixURIProcessor.isValidUrl("http://localhost:8080");
   * console.log(isLocalhostInvalid); // false
   * ```
   * @see checkUrl
   * @see UrlValidationOptions
   */

  static isValidUri(
    ...props: Parameters<typeof ncu.isValidUrl>
  ): ReturnType<typeof ncu.isValidUrl> {
    return ncu.isValidUrl(...props);
  }

  /**
   * Decodes a string using the specified encoding type.
   *
   * Supports various decoding types defined in `ENC_TYPE` or `DEC_FEATURE_TYPE`, such as percent-encoding, Base64,
   * and hexadecimal. Can handle recursive decoding for nested encodings if a depth is specified.
   *
   * @param input - The string to decode (e.g., `hello%20world`).
   * @param encodingType - The encoding type to decode, as defined in `ENC_TYPE` or `DEC_FEATURE_TYPE`
   *                       (e.g., `percentEncoding`, `base64`).
   * @param [maxRecursionDepth] - Optional maximum recursion depth for nested decoding.
   *                              If omitted, performs a single-level decode.
   * @returns The decoded string (e.g., `hello world` for percent-encoding).
   * @throws Throws an error if the encoding type is unsupported or the input is invalid.
   * @example
   * ```typescript
   * const decoded = NehonixURIProcessor.decode("hello%20world", "percentEncoding");
   * console.log(decoded); // hello world
   *
   * const base64 = NehonixURIProcessor.decode("dHJ1ZQ==", "base64");
   * console.log(base64); // true
   *
   * const nested = NehonixURIProcessor.decode("414243", "hex", 2);
   * console.log(nested); // ABC
   * ```
   */
  static decode(
    input: string,
    encodingType: ENC_TYPE | DEC_FEATURE_TYPE,
    maxRecursionDepth?: number
  ) {
    return dec.decode({
      input,
      encodingType,
      maxRecursionDepth,
    });
  }

  /**
   * Creates a URL object from a URI string.
   *
   * This method parses the provided URI string using the native `URL` API, returning a `URL` object that provides
   * structured access to the URL's components (e.g., protocol, hostname, pathname, search parameters). It is useful
   * for further URL manipulation or analysis within the `NehonixURIProcessor` ecosystem.
   *
   * @param uri - The URI string to parse (e.g., `https://nehonix.space?test=true`).
   * @returns A `URL` object representing the parsed URI.
   * @throws Throws a `TypeError` if the URI string is invalid or cannot be parsed by the `URL` constructor.
   * @example
   * ```typescript
   * const urlObj = NehonixURIProcessor.createUrl("https://nehonix.space?test=true");
   * console.log(urlObj.href); // https://nehonix.space?test=true
   * console.log(urlObj.hostname); // nehonix.space
   * console.log(urlObj.searchParams.get("test")); // true
   *
   * // Handling invalid URI
   * try {
   *   const invalidUrl = NehonixURIProcessor.createUrl("not-a-valid-url");
   * } catch (error) {
   *   console.log(error.message); // Failed to construct 'URL': Invalid URL
   * }
   * ```
   */
  static createUrl(uri: string): URL {
    return new URL(uri);
  }

  //v2.0.6
  /**
   * Checks a URL string and returns detailed validation results.
   *
   * This method performs a comprehensive validation of a URL string against configurable rules, similar to `isValidUri`,
   * but instead of returning a boolean, it provides an object with detailed results for each validation step. It checks
   * aspects such as URL length, protocol, domain structure, top-level domains (TLDs), query parameters, and encoding.
   * The returned object includes an overall validity flag and specific details about each check, making it ideal for
   * debugging, security analysis, or detailed URL validation reporting.
   *
   * @param url - The URL string to check (e.g., `https://nehonix.space?test=true`).
   * @param [options] - Optional configuration for validation rules.
   * @param [options.strictMode=false] - If `true`, requires a leading slash before query parameters (e.g., `/?query`).
   *                                    If `false`, allows query parameters without a leading slash (e.g., `?query`).
   * @param [options.allowUnicodeEscapes=true] - If `true`, allows Unicode escape sequences (e.g., `\u0068`) in query
   *                                            parameters. If `false`, rejects such sequences.
   * @param [options.rejectDuplicateParams=true] - If `true`, rejects URIs with duplicate query parameter keys
   *                                              (e.g., `?p1=a&p1=b`). If `false`, allows duplicates.
   * @param [options.rejectDuplicatedValues=false] - If `true`, rejects URIs with duplicate query parameter values
   *                                                (e.g., `?p1=a&p2=a`). If `false`, allows duplicates.
   * @param [options.httpsOnly=false] - If `true`, only allows `https://` URLs (rejects `http://`). If `false`, allows
   *                                   both `http://` and `https://` URLs.
   * @param [options.maxUrlLength=2048] - Maximum allowed length for the entire URL. Set to 0 to disable length checking.
   * @param [options.allowedTLDs=[]] - List of allowed top-level domains (e.g., `['com', 'org', 'net']`). If empty,
   *                                   all TLDs are allowed.
   * @param [options.allowedProtocols=['http', 'https']] - List of allowed protocols (e.g., `['http', 'https']`).
   *                                                      Only enforced if `requireProtocol` is `true`.
   * @param [options.requireProtocol=false] - If `true`, requires an explicit protocol in the URL (e.g., `https://`).
   *                                         If `false`, adds `https://` to URLs without a protocol.
   * @param [options.requirePathOrQuery=false] - If `true`, requires a path or query string (rejects bare domains like
   *                                            `example.com`). If `false`, allows bare domains.
   * @param [options.strictParamEncoding=false] - If `true`, validates that query parameter keys and values are properly
   *                                             URI-encoded (e.g., no invalid percent-encoding). If `false`, performs
   *                                             basic validation.
   * @returns A `UrlCheckResult` object containing:
   *          - `isValid`: A boolean indicating overall validity.
   *          - `validationDetails`: An object with details for each validation check (e.g., length, protocol, domain),
   *            including validity status, descriptive messages, and relevant metadata (e.g., detected protocol, invalid parameters).
   * @throws Does not throw errors; instead, parsing errors are reported in the `validationDetails.parsing` property.
   * @example
   * ```typescript
   * const result = NehonixURIProcessor.checkUrl("https://nehonix.space?test=true");
   * console.log(result);
   * // Output: {
   * //   isValid: true,
   * //   validationDetails: {
   * //     length: { isValid: true, message: "URL length is within limits", actualLength: 29, maxLength: 2048 },
   * //     emptyCheck: { isValid: true, message: "URL is not empty" },
   * //     protocol: { isValid: true, message: "Protocol 'https' is valid", detectedProtocol: "https", allowedProtocols: ["http", "https"] },
   * //     ...
   * //   }
   * // }
   *
   * // Invalid URL with unencoded spaces
   * const invalidResult = NehonixURIProcessor.checkUrl("https://nehonix.space?test=thank you");
   * console.log(invalidResult);
   * // Output: {
   * //   isValid: false,
   * //   validationDetails: {
   * //     length: { isValid: true, message: "URL length is within limits", actualLength: 35, maxLength: 2048 },
   * //     emptyCheck: { isValid: true, message: "URL is not empty" },
   * //     querySpaces: { isValid: false, message: "Query string contains unencoded spaces" },
   * //     ...
   * //   }
   * // }
   *
   * // URL with duplicate parameters
   * const duplicateResult = NehonixURIProcessor.checkUrl(
   *   "https://nehonix.space?p1=a&p1=b",
   *   { rejectDuplicateParams: true }
   * );
   * console.log(duplicateResult);
   * // Output: {
   * //   isValid: false,
   * //   validationDetails: {
   * //     duplicateParams: { isValid: false, message: "Duplicate query parameter keys detected", duplicatedKeys: ["p1"] },
   * //     ...
   * //   }
   * // }
   *
   * // URL with strict encoding violation
   * const encodingResult = NehonixURIProcessor.checkUrl(
   *   "https://nehonix.space?test=%25",
   *   { strictParamEncoding: true }
   * );
   * console.log(encodingResult);
   * // Output: {
   * //   isValid: false,
   * //   validationDetails: {
   * //     paramEncoding: { isValid: false, message: "Invalid parameter encoding detected", invalidParams: ["%25"] },
   * //     ...
   * //   }
   * // }
   * ```
   * @see UrlCheckResult for the structure of the returned object.
   * @see isValidUri for a boolean-based URL validation method.
   */

  static checkUrl = (
    ...p: Parameters<typeof ncu.checkUrl>
  ): ReturnType<typeof ncu.checkUrl> => ncu.checkUrl(...p);

  //v 2.2.0
  /**
   * Analyzes input for malicious patterns and returns detailed detection results

@param input — The string to analyze

@param options — Configuration options for detection

@returns — Detailed analysis result
*/

  static detectMaliciousPatterns(
    ...arg: Parameters<typeof NSS.detectMaliciousPatterns>
  ): ReturnType<typeof NSS.detectMaliciousPatterns> {
    return NSS.detectMaliciousPatterns(...arg);
  }
  /**
   * Analyzes a URL for malicious patterns with specific sensitivity per URL component
   * @param url — The URL to analyze
   * @param options — Configuration options for detection
   * @returns — Detailed analysis result
   */
  static scanUrl(
    ...arg: Parameters<typeof NSS.analyzeUrl>
  ): ReturnType<typeof NSS.analyzeUrl> {
    return NSS.analyzeUrl(...arg);
  }
  /**
   *Lightweight check to
    determine if string needs deep scanning Use as a pre-filter before doing full pattern detection
   *@param input — String to check
  * @returns — Whether input needs further scanning
   */
  static needsDeepScan = (
    ...p: Parameters<typeof NSS.needsDeepScan>
  ): ReturnType<typeof NSS.needsDeepScan> => NSS.needsDeepScan(...p);

  /**
   * Sanitizes input by removing potentially malicious patterns
   * @param input — The string to sanitize
   * @param options — Additional sanitization options
   * @returns — Sanitized string
   */
  static sanitizeInput = (
    ...p: Parameters<typeof NSS.sanitizeInput>
  ): ReturnType<typeof NSS.sanitizeInput> => NSS.sanitizeInput(...p);

  static asyncAutoDetectAndDecode(
    ...p: Parameters<typeof NDS.asyncDecodeAnyToPlainText>
  ): ReturnType<typeof NDS.asyncDecodeAnyToPlainText> {
    return NDS.asyncDecodeAnyToPlainText(...p);
  }

  static async asyncCheckUrl(
    ...p: Parameters<typeof ncu.asyncCheckUrl>
  ): ReturnType<typeof ncu.asyncCheckUrl> {
    return await ncu.asyncCheckUrl(...p);
  }

  static async asyncIsUrlValid(...p: Parameters<typeof ncu.asyncIsUrlValid>) {
    return await ncu.asyncIsUrlValid(...p);
  }
}

export { NehonixURIProcessor };
//v2
export { MaliciousPatternType } from "./services/MaliciousPatterns.service";
export type { MaliciousPatternResult } from "./services/MaliciousPatterns.service";
/**
 * Encodes user input based on the context in which it will be used
 * Selects the appropriate encoding method for security and compatibility
 *
 * @param input The user input to secure
 * @param context The context where the input will be used
 * @param options Optional configuration for specific encoding behaviors
 * @returns The appropriately encoded string
 */
export const __safeEncode__ = NehonixSafetyLayer.__safeEncode__;
export { NehonixURIProcessor as __processor__ };
export const decodeB64 = (input: string) =>
  NDS.decode({
    input,
    encodingType: "base64",
  });

//v2.3.x
export * from "./integration/react/hook/REACT.ShieldHooks";
export * from "./integration/react/provider/REACT.NehonixShield";
export * from "./integration/react/hook/REACT.NehonixDomPlugging.hooks";
export { DetectedPattern } from "./services/MaliciousPatterns.service";
