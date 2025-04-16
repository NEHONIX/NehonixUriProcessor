import { NehonixEncService as enc } from "./services/NehonixEnc.service";
import { SecurityRules as sr } from "./rules/security.rules";
import { NehonixDecService as dec } from "./services/NehonixDec.service";
import { DEC_FEATURE_TYPE, ENC_TYPE } from "./types";
import { ncu } from "./utils/NehonixCoreUtils";

/**
 * A comprehensive library for detecting, encoding, and decoding URI strings, designed for security testing and attack analysis.
 *@author nehonix
 *@since 12/04/2025
 * The `NehonixURIProcessor` class provides methods to analyze URLs, generate encoding variants for Web Application Firewall (WAF) bypass testing,
 * and automatically detect and decode various URI encodings. It supports a range of encoding types, including percent-encoding, Base64, and hexadecimal,
 * making it suitable for penetration testing, vulnerability assessment, and secure data processing.
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
  static analyzeURL(url: string) {
    return sr.analyzeURL(url);
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
   * Checks whether a string is a valid URI.
   *
   * Delegates to `NehonixCoreUtils.isValidUrl` to validate the input string against a comprehensive URI pattern using
   * the native `URL` API. Supports optional protocols (http/https), domains, ports, paths, and query parameters.
   * Enforces configurable validation rules, including protocol requirements, top-level domain restrictions, query
   * parameter uniqueness, and proper encoding of special characters. Rejects unencoded spaces in query parameters,
   * requiring percent-encoding (e.g., `%20`).
   *
   * @param url - The string to test for URI validity (e.g., `https://example.com?test=true`).
   * @param [options] - Optional configuration for validation.
   * @param [options.strictMode=false] - If `true`, requires a leading slash before query parameters (e.g., `/?query`).
   *                                    If `false`, allows query parameters without a leading slash (e.g., `?query`).
   * @param [options.allowUnicodeEscapes=true] - If `true`, allows Unicode escape sequences (e.g., `\u0068`) in query
   *                                            parameters. If `false`, rejects such sequences.
   * @param [options.rejectDuplicateParams=true] - If `true`, rejects URIs with duplicate query parameter keys
   * @param [options.rejectDuplicatedValues=false] - If `true`, rejects URIs with duplicate query parameter values
   *                                              (e.g., `?p1=a&p1=b`). If `false`, allows duplicates.
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
   * @returns `true` if the string is a valid URI according to the specified options, `false` otherwise.
   * @example
   * ```typescript
   * // Valid URI
   * const isValid = NehonixURIProcessor.isValidUri("https://example.com?test=true");
   * console.log(isValid); // true
   *
   * // Invalid URI with unencoded spaces
   * const isValidSpaces = NehonixURIProcessor.isValidUri(
   *   "https://nehonix.space?ok=thank to nehonix"
   * );
   * console.log(isValidSpaces); // false
   *
   * // Invalid URI with duplicate parameters
   * const isValidDuplicate = NehonixURIProcessor.isValidUri(
   *   "https://nehonix.space?p2=a&p2=b"
   * );
   * console.log(isValidDuplicate); // false
   *
   * // Valid URI with encoded spaces
   * const isValidEncoded = NehonixURIProcessor.isValidUri(
   *   "https://nehonix.space?ok=thank%20to%20nehonix"
   * );
   * console.log(isValidEncoded); // true
   *
   * // Valid URI with duplicates allowed
   * const isValidAllowDuplicate = NehonixURIProcessor.isValidUri(
   *   "https://nehonix.space?p2=a&p2=b",
   *   { rejectDuplicateParams: false }
   * );
   * console.log(isValidAllowDuplicate); // true
   *
   * // Valid URI with Unicode escapes
   * const isValidUnicode = NehonixURIProcessor.isValidUri(
   *   "https://nehonix.space?test=true&p2=\\u0068\\u0065\\u006c\\u006c\\u006f"
   * );
   * console.log(isValidUnicode); // true
   *
   * // Invalid URI with HTTP when httpsOnly is true
   * const isValidHttps = NehonixURIProcessor.isValidUri(
   *   "http://example.com",
   *   { httpsOnly: true }
   * );
   * console.log(isValidHttps); // false
   *
   * // Invalid URI with disallowed TLD
   * const isValidTLD = NehonixURIProcessor.isValidUri(
   *   "https://example.xyz",
   *   { allowedTLDs: ['com', 'org'] }
   * );
   * console.log(isValidTLD); // false
   *
   * // Invalid URI without protocol when required
   * const isValidNoProtocol = NehonixURIProcessor.isValidUri(
   *   "example.com",
   *   { requireProtocol: true }
   * );
   * console.log(isValidNoProtocol); // false
   *
   * // Invalid URI with strict encoding violation
   * const isValidEncoding = NehonixURIProcessor.isValidUri(
   *   "https://example.com?test=%25",
   *   { strictParamEncoding: true }
   * );
   * console.log(isValidEncoding); // false
   * ```
   */
  static isValidUri(...props: Parameters<typeof ncu.isValidUrl>): boolean {
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
   *
   * @param uri the uri to create
   * @returns an Object of the class URL
   */
  static createUrl(uri: string): URL {
    return new URL(uri);
  }
}

export { NehonixURIProcessor };
export default NehonixURIProcessor;
