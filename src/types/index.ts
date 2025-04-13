import { NehonixURIProcessor } from "../main";

/**
 * Supported encoding types. This enumeration defines all the encoding schemes
 * that the NehonixURIProcessor can handle. Each type represents a distinct
 * method of representing characters or data in a string format, often used
 * in URLs, web applications, and data transmission.
 */
export type ENC_TYPE =
  | "percent" // Standard URL percent encoding (e.g., %20 for space)
  | "percentEncoding" // Alias for 'percent'
  | "url" // Alias for 'percent'
  | "doublepercent" // Double percent encoding (e.g., %2520 for space)
  | "doublePercentEncoding" // Alias for 'doublepercent'
  | "base64" // Base64 encoding (e.g., converting binary data to ASCII string)
  | "hex" // Hexadecimal encoding (e.g., \x41 for 'A')
  | "hexadecimal" // Alias for 'hex'
  | "unicode" // Unicode encoding (e.g., \u0041 for 'A')
  | "htmlEntity" // HTML entity encoding (e.g., &amp; for '&')
  | "html" // Alias for 'htmlEntity'
  | "punycode" // Punycode encoding (for internationalized domain names)
  | "asciihex" // ASCII characters represented by their hexadecimal values.
  | "asciioct"; // ASCII characters represented by their octal values.

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
  mostLikely: string;
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
  val: string;
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
