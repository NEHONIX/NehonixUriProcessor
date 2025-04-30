import { MaliciousPatternOptions } from "../services/MaliciousPatterns.service";
import { URLAnalysisResult, WAFBypassVariants } from "./index";

/**
 * Represents a comparison of different URI encoding variants for security testing.
 * Used by the compareUriVariants method to evaluate encoding effectiveness against WAFs.
 */
export interface UriVariantComparison {
  /**
   * The encoded variant of the URI.
   */
  variant: string;

  /**
   * The encoding type used to generate this variant.
   */
  encoding: string;

  /**
   * Whether this variant is likely to pass common security filters.
   */
  isSafe: boolean;
}

/**
 * Comprehensive security report for a URI, including vulnerability analysis,
 * encoding variants, and security recommendations.
 */
export interface UriSecurityReport {
  /**
   * Analysis of the URL structure and potential vulnerabilities.
   */
  analysis: URLAnalysisResult;

  /**
   * Comparison of different encoding variants for WAF testing.
   */
  variants: UriVariantComparison[];

  /**
   * Actionable security recommendations based on the analysis.
   */
  recommendations: string[];
}

/**
 * Options for the autoDetectAndDecodeAsync method.
 */
export interface AsyncDecodeOptions {
  /**
   * Maximum number of decoding iterations to prevent infinite loops.
   * @default 10
   */
  maxIterations?: number;

  /**
   * Whether to use a Web Worker for decoding (browser only).
   * @default false
   */
  useWorker?: boolean;
}

// /**
//  * Options for malicious pattern detection in URIs.
//  */
export interface WAFMaliciousPatternOptions {
  /**
   * If true, detects common SQL injection patterns.
   * @default true
   */
  detectSqlInjection?: boolean;

  /**
   * If true, detects common XSS attack patterns.
   * @default true
   */
  detectXss?: boolean;

  /**
   * If true, detects path traversal attempts.
   * @default true
   */
  detectPathTraversal?: boolean;

  /**
   * If true, detects command injection attempts.
   * @default true
   */
  detectCommandInjection?: boolean;

  /**
   * Custom patterns to detect (as regular expressions).
   */
  customPatterns?: RegExp[];
}

/**
 * Extended URL validation options for v2.2.0.
 */
export default interface ExtendedUrlValidationOptions {
  /**
   * If true, enables detection of malicious patterns in URL parameters.
   * @default false
   */
  detectMaliciousPatterns?: boolean;

  /**
   * If true, allows non-ASCII characters in URIs (normalized with punycode).
   * @default false
   */
  allowInternationalChars?: boolean;

  /**
   * Specific options for malicious pattern detection.
   */
  maliciousPatternOptions?: MaliciousPatternOptions;
}

export type MaliciousComponentType =
  | "protocol"
  | "hostname"
  | "path"
  | "query"
  | "fragment";
