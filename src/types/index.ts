import { NehonixURIProcessor } from "..";

/**
 * Supported encoding types. This enumeration defines all the encoding schemes
 * that the NehonixURIProcessor can handle. Each type represents a distinct
 * method of representing characters or data in a string format, often used
 * in URLs, web applications, and data transmission.
 */
export type ENC_TYPE =
  | "percentEncoding" // Standard URL percent encoding (e.g., %20 for space)
  | "doublepercent" // Double percent encoding (e.g., %2520 for space)
  | "base64" // Base64 encoding (e.g., converting binary data to ASCII string)
  | "hex" // Hexadecimal encoding (e.g., \x41 for 'A')
  | "unicode" // Unicode encoding (e.g., \u0041 for 'A')
  | "htmlEntity" // HTML entity encoding (e.g., &amp; for '&')
  | "punycode" // Punycode encoding (for internationalized domain names)
  | "asciihex" // ASCII characters represented by their hexadecimal values
  //new
  | "asciioct" // ASCII characters represented by their octal values
  | "rot13" // ROT13 cipher encoding (rotates letters by 13 positions)
  | "base32" // Base32 encoding (alphanumeric with padding)
  | "urlSafeBase64" // URL-safe Base64 encoding (uses - and _ instead of + and /)
  | "jsEscape" // JavaScript escape sequences for string contexts
  | "cssEscape" // CSS escape sequences for selectors and values
  | "utf7" // UTF-7 encoding for legacy systems
  | "quotedPrintable" // Quoted-Printable encoding for email systems
  | "decimalHtmlEntity" // Decimal HTML entity encoding (&#123; format)
  //new
  | "rawHexadecimal"
  | "jwt";

export type DEC_FEATURE_TYPE = "url" | "any";
/**
 * Result of encoding detection. This interface describes the outcome of an
 * attempt to identify the encoding scheme used in a given string. It provides
 * an array of all detected encoding types, the most likely type, and a
 * confidence score for that detection.
 */
export interface EncodingDetectionResult {
  /**
   * An array of all encoding types detected in the input string.
   */
  types: string[];
  /**
   * The encoding type that is considered the most likely based on analysis.
   */
  mostLikely: ENC_TYPE | "plainText";
  /**
   * A numerical value representing the confidence level of the most likely
   * encoding detection, usually between 0 and 1.
   */
  confidence: number;
  /**
   * Indicates whether nested encoding was detected (i.e., one encoding within another).
   */
  isNested?: boolean;
  /**
   * If nested encoding is detected, this array lists the inner encoding types.
   */
  nestedTypes?: string[];
}

/**
 * Result of nested encoding detection. This interface provides more specific
 * information about nested encoding scenarios, including the outer and inner
 * encoding types and a confidence score.
 */
export interface NestedEncodingResult {
  /**
   * Indicates whether nested encoding was detected.
   */
  isNested: boolean;
  /**
   * The outer layer encoding type.
   */
  outerType: string;
  /**
   * The inner layer encoding type.
   */
  innerType: string;
  /**
   * A numerical value representing the confidence level of the nested encoding detection.
   */
  confidenceScore: number;
}

/**
 * Result of URL analysis. This interface defines the structure of the output
 * from analyzing a URL, including the base URL, extracted parameters, and
 * any potential vulnerabilities detected.
 */
export interface URLAnalysisResult {
  /**
   * The base URL without parameters.
   */
  baseURL: string;
  /**
   * An object containing the extracted URL parameters and their values.
   */
  parameters: { [key: string]: string };
  /**
   * An array of strings describing potential security vulnerabilities found in the URL.
   */
  potentialVulnerabilities: string[];
}

/**
 * Result of WAF bypass variants generation. This interface represents the
 * various encoding variants generated for Web Application Firewall (WAF)
 * bypass testing.
 */
export interface WAFBypassVariants {
  /**
   * Standard percent-encoded version of the input string.
   */
  percentEncoding: string;
  /**
   * Double percent-encoded version of the input string.
   */
  doublePercentEncoding: string;
  /**
   * A version with mixed encoding types.
   */
  mixedEncoding: string;
  /**
   * A version with alternating character case.
   */
  alternatingCase: string;
  /**
   * A fully hexadecimal-encoded version of the input string.
   */
  fullHexEncoding: string;
  /**
   * A version with unicode character representations.
   */
  unicodeVariant: string;
  /**
   * A version with HTML entity representations.
   */
  htmlEntityVariant: string;
}

/**
 * Result of detectAndDecode operation. This interface describes the result of
 * automatically detecting and decoding a string, including the decoded value,
 * the detected encoding type, and the confidence level.
 */
export interface DecodeResult {
  /**
   * The decoded string value.
   */
  val: () => string;
  /**
   * The detected encoding type of the input string.
   */
  encodingType: string;
  /**
   * A numerical value representing the confidence level of the encoding detection.
   */
  confidence: number;
  /**
   * If nested encoding is detected, this array lists the inner encoding types.
   */
  nestedTypes?: string[];
  original?: string;
  attemptedDecode?: string;
  attemptedVal?: string | undefined;
}

/**
 * Interface for the NehonixURIProcessor class. This interface defines the
 * public methods and properties available in the NehonixURIProcessor class,
 * which provides functionality for encoding and decoding strings, analyzing
 * URLs, and generating WAF bypass variants.
 */
export interface INehonixURIProcessor {
  /**
   * Automatically detects and decodes a URI based on the detected encoding type.
   * @param input The URI string to decode.
   * @returns The decoded string with encoding information.
   */
  detectAndDecode(input: string): DecodeResult;

  /**
   * Decodes a string according to a specific encoding type.
   * @param input The string to decode.
   * @param encodingType The encoding type to use.
   * @param maxRecursionDepth Maximum recursion depth for nested decoding (default: 5).
   * @returns The decoded string.
   */
  decode(
    input: string,
    encodingType: ENC_TYPE,
    maxRecursionDepth?: number
  ): string;

  /**
   * Encodes a string according to a specific encoding type.
   * @param input The string to encode.
   * @param encodingType The encoding type to use.
   * @returns The encoded string.
   */
  encode(input: string, encodingType: ENC_TYPE): string;

  /**
   * Decodes percent encoding (URL).
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodePercentEncoding(input: string): string;

  /**
   * Decodes double percent encoding.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodeDoublePercentEncoding(input: string): string;

  /**
   * Decodes base64 encoding.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodeBase64(input: string): string;

  /**
   * Decodes hexadecimal encoding.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodeHex(input: string): string;

  /**
   * Decodes Unicode encoding.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodeUnicode(input: string): string;

  /**
   * Decodes HTML entities.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodeHTMLEntities(input: string): string;

  /**
   * Decodes punycode.
   * @param input The string to decode.
   * @returns The decoded string.
   */
  decodePunycode(input: string): string;

  /**
   * Decodes a raw hexadecimal string (without prefixes).
   * @param input The hexadecimal string to decode.
   * @returns The decoded string.
   */
  decodeRawHex(input: string): string;

  /**
   * Decodes a JWT token.
   * @param input The JWT token to decode.
   * @returns The decoded JWT as a formatted string.
   */
  decodeJWT(input: string): string;

  /**
   * Encodes with percent encoding (URL).
   * @param input The string to encode.
   * @param encodeSpaces Whether to encode spaces as %20 (default: false).
   * @returns The encoded string.
   */
  encodePercentEncoding(input: string, encodeSpaces?: boolean): string;

  /**
   * Encodes with double percent encoding.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeDoublePercentEncoding(input: string): string;

  /**
   * Encodes in base64.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeBase64(input: string): string;

  /**
   * Encodes in hexadecimal (format \xXX).
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeHex(input: string): string;

  /**
   * Encodes in Unicode (format \uXXXX).
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeUnicode(input: string): string;

  /**
   * Encodes in HTML entities.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeHTMLEntities(input: string): string;

  /**
   * Encodes in punycode.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodePunycode(input: string): string;

  /**
   * Encodes in ASCII with hexadecimal representation.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeASCIIWithHex(input: string): string;

  /**
   * Encodes in ASCII with octal representation.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeASCIIWithOct(input: string): string;

  /**
   * Encodes all characters in percent encoding.
   * @param input The string to encode.
   * @returns The encoded string.
   */
  encodeAllChars(input: string): string;

  /**
   * Analyzes a URL and extracts potentially vulnerable parameters.
   * @param url The URL to analyze.
   * @returns An object containing information about the URL and parameters.
   */
  analyzeURL(url: string): URLAnalysisResult;

  /**
   * Generates encoding variants of a string for WAF bypass testing.
   * @param input The string to encode.
   * @returns An object containing different encoding variants.
   */
  generateWAFBypassVariants(input: string): WAFBypassVariants;

  /**
   * Automatically detects the encoding type of a URI string.
   * @param input The URI string to analyze.
   * @param depth Current recursion depth (internal use).
   * @returns An object containing the detected encoding types and their probability.
   */
  detectEncoding(input: string, depth?: number): EncodingDetectionResult;
}

// Implementation type for the static class
export type NehonixURIProcessorType = typeof NehonixURIProcessor;

/**
 *Real-world application: Encoding user input for various contexts (RWA)
 * Defines the context in which user input will be used,
 * allowing for appropriate encoding selection
 */
export type RWA_TYPES =
  | "url" // For use in URL paths
  | "urlParam" // For use in URL query parameters
  | "html" // For insertion into HTML content
  | "htmlAttr" // For use in HTML attribute values
  | "js" // For insertion into JavaScript code
  | "jsString" // For use specifically in JavaScript string literals
  | "css" // For use in CSS content
  | "cssSelector" // For use in CSS selectors
  | "email" // For use in email content
  | "emailSubject" // For use in email subject lines
  | "command" // For use in command-line contexts
  | "xml" // For use in XML content
  | "json" // For use in JSON data
  | "obfuscate" // For obfuscating content
  | "idnDomain"; // For internationalized domain names

/**
 * Options for URI validation.
 */
export interface UrlValidationOptions {
  /**
   * If `true`, requires a leading slash before paths or query parameters (e.g., `/path` or `/?query`).
   * If `false`, allows query parameters without a leading slash (e.g., `?query`).
   * @default false
   */
  strictMode?: boolean;

  /**
   * If `true`, allows Unicode escape sequences (e.g., `\u0068`) in query parameters.
   * If `false`, rejects URIs containing Unicode escape sequences.
   * @default true
   */
  allowUnicodeEscapes?: boolean;

  /**
   * If `true`, rejects URIs with duplicate query parameter keys (e.g., `?p1=a&p1=b`).
   * If `false`, allows duplicate keys.
   * @default true
   */
  rejectDuplicateParams?: boolean;

  /**
   * If `true`, only allows https:// URLs (rejects http://).
   * If `false`, allows both http:// and https:// URLs.
   * @default false
   */
  httpsOnly?: boolean;

  /**
   * Maximum allowed length for the entire URL.
   * Set to 0 to disable length checking.
   * @default 2048
   */
  maxUrlLength?: number;

  /**
   * List of allowed top-level domains (e.g., ['com', 'org', 'net']).
   * If empty, all TLDs are allowed.
   * @default []
   */
  allowedTLDs?: string[];

  /**
   * List of allowed protocols (e.g., ['https', 'http', 'ftp']).
   * Only relevant if requireProtocol is true.
   * @default ['http', 'https']
   */
  allowedProtocols?: string[];

  /**
   * If `true`, requires the protocol to be explicitly specified in the URL.
   * If `false`, adds https:// if no protocol is specified.
   * @default false
   */
  requireProtocol?: boolean;

  /**
   * If `true`, validates that the URL has a path or query string.
   * If `false`, allows bare domains like 'example.com'.
   * @default false
   */
  requirePathOrQuery?: boolean;

  /**
   * If `true`, validates each parameter value against URI encoding standards.
   * If `false`, performs basic validation only.
   * @default false
   */
  strictParamEncoding?: boolean;
  /**
   *If `true`, it will find keys in "parameters" that map to the same value (e.g.,
   * { param1: "value1", param2: "value1", param3: "value2" }),
   *  then group keys by their values and filter for values with multiple keys
   * @default false
   */
  rejectDuplicatedValues?: boolean;
}

/**
 * Represents the detailed result of a URL validation process.
 * This interface provides a comprehensive breakdown of the validation checks performed
 * on a URL, including overall validity and specific details for each validation step.
 *
 * @interface UrlCheckResult
 */
export interface UrlCheckResult {
  /**
   * Indicates whether the URL is valid based on all validation checks.
   * `true` if all checks pass, `false` if any check fails.
   */
  isValid: boolean;

  /**
   * Contains detailed results for each validation check performed on the URL.
   * Each property corresponds to a specific validation aspect and is optional,
   * as not all validations may be relevant depending on the provided options.
   */
  validationDetails: {
    /**
     * Validation result for the URL length check.
     */
    length?: {
      /** Indicates if the URL length is within the specified limit. */
      isValid: boolean;
      /** Descriptive message about the length validation result. */
      message?: string;
      /** The actual length of the URL in characters. */
      actualLength?: number;
      /** The maximum allowed length as specified in options. */
      maxLength?: number;
    };

    /**
     * Validation result for checking if the URL is empty or contains only whitespace.
     */
    emptyCheck?: {
      /** Indicates if the URL is non-empty. */
      isValid: boolean;
      /** Descriptive message about the empty check result. */
      message?: string;
    };

    /**
     * Validation result for the URL protocol check.
     */
    protocol?: {
      /** Indicates if the protocol is valid and allowed. */
      isValid: boolean;
      /** Descriptive message about the protocol validation result. */
      message?: string;
      /** The detected protocol in the URL (e.g., 'http', 'https'). */
      detectedProtocol?: string;
      /** The list of allowed protocols specified in options. */
      allowedProtocols?: string[];
    };

    /**
     * Validation result for the HTTPS-only requirement.
     */
    httpsOnly?: {
      /** Indicates if the URL uses HTTPS when required. */
      isValid: boolean;
      /** Descriptive message about the HTTPS-only validation result. */
      message?: string;
    };

    /**
     * Validation result for the domain structure check.
     */
    domain?: {
      /** Indicates if the domain structure is valid. */
      isValid: boolean;
      /** Descriptive message about the domain validation result. */
      message?: string;
      /** The hostname extracted from the URL. */
      hostname?: string;
    };

    /**
     * Validation result for the top-level domain (TLD) check.
     */
    tld?: {
      /** Indicates if the TLD is valid and allowed. */
      isValid: boolean;
      /** Descriptive message about the TLD validation result. */
      message?: string;
      /** The detected TLD in the URL (e.g., 'com', 'org'). */
      detectedTld?: string;
      /** The list of allowed TLDs specified in options. */
      allowedTlds?: string[];
    };

    /**
     * Validation result for the path or query string requirement.
     */
    pathOrQuery?: {
      /** Indicates if the URL satisfies path or query requirements. */
      isValid: boolean;
      /** Descriptive message about the path/query validation result. */
      message?: string;
    };

    /**
     * Validation result for strict mode path requirements.
     */
    strictMode?: {
      /** Indicates if the URL satisfies strict mode path requirements. */
      isValid: boolean;
      /** Descriptive message about the strict mode validation result. */
      message?: string;
    };

    /**
     * Validation result for checking unencoded spaces in the query string.
     */
    querySpaces?: {
      /** Indicates if the query string is free of unencoded spaces. */
      isValid: boolean;
      /** Descriptive message about the query spaces validation result. */
      message?: string;
    };

    /**
     * Validation result for strict parameter encoding check.
     */
    paramEncoding?: {
      /** Indicates if query parameters are properly encoded. */
      isValid: boolean;
      /** Descriptive message about the parameter encoding validation result. */
      message?: string;
      /** List of parameters that failed encoding validation, if any. */
      invalidParams?: string[];
    };

    /**
     * Validation result for duplicate query parameter keys check.
     */
    duplicateParams?: {
      /** Indicates if there are no duplicate query parameter keys. */
      isValid: boolean;
      /** Descriptive message about the duplicate parameters validation result. */
      message?: string;
      /** List of query parameter keys that are duplicated, if any. */
      duplicatedKeys?: string[];
    };

    /**
     * Validation result for duplicate query parameter values check.
     */
    duplicateValues?: {
      /** Indicates if there are no duplicate query parameter values. */
      isValid: boolean;
      /** Descriptive message about the duplicate values validation result. */
      message?: string;
      /** List of query parameter values that are duplicated, if any. */
      duplicatedValues?: string[];
    };

    /**
     * Validation result for Unicode escape sequences check.
     */
    unicodeEscapes?: {
      /** Indicates if the URL is free of disallowed Unicode escape sequences. */
      isValid: boolean;
      /** Descriptive message about the Unicode escapes validation result. */
      message?: string;
    };

    /**
     * Validation result for URL parsing.
     */
    parsing?: {
      /** Indicates if the URL was parsed successfully. */
      isValid: boolean;
      /** Descriptive message about the parsing validation result. */
      message?: string;
    };
  };
}
