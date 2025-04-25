import { MaliciousComponentType } from "../types/v2.2.0";

/**
 * Interface defining detection result with detailed information
 */
export interface MaliciousPatternResult {
  isMalicious: boolean;
  detectedPatterns: DetectedPattern[];
  score: number;
  confidence: "low" | "medium" | "high";
  recommendation: string;
  contextAnalysis?: ContextAnalysisResult; // New field
}

/**
 * New interface for contextual analysis results
 */
export interface ContextAnalysisResult {
  relatedPatterns: RelatedPatternGroup[];
  entropyScore: number;
  anomalyScore: number;
  encodingLayers: number;
}

/**
 * Interface for related pattern groups
 */
export interface RelatedPatternGroup {
  patterns: MaliciousPatternType[];
  description: string;
  riskMultiplier: number;
}

/**
 * Interface defining a detected malicious pattern
 */
export interface DetectedPattern {
  type: MaliciousPatternType;
  pattern: string;
  location: string;
  severity: "low" | "medium" | "high";
  confidence: "low" | "medium" | "high";
  description: string;
  matchedValue?: string;
  contextScore?: number; // New field for context-based scoring
}

/**
 * Enum defining various malicious pattern types
 */
export enum MaliciousPatternType {
  SQL_INJECTION = "sql_injection",
  XSS = "cross_site_scripting",
  COMMAND_INJECTION = "command_injection",
  PATH_TRAVERSAL = "path_traversal",
  OPEN_REDIRECT = "open_redirect",
  SSRF = "server_side_request_forgery",
  CRLF_INJECTION = "crlf_injection",
  ENCODED_PAYLOAD = "encoded_payload",
  SERIALIZATION = "serialization_payload",
  TEMPLATE_INJECTION = "template_injection",
  SUSPICIOUS_PARAMETER = "suspicious_parameter",
  DATA_URI = "data_uri",
  SUSPICIOUS_IP = "suspicious_ip",
  SUSPICIOUS_TLD = "suspicious_tld",
  SUSPICIOUS_DOMAIN = "suspicious_domain",
  PROTOCOL_CONFUSION = "protocol_confusion",
  HOMOGRAPH_ATTACK = "homograph_attack", // NEW: Domain spoofing using similar-looking chars
  MULTI_ENCODING = "multi_encoding", // NEW: Multiple encoding layers
  UNICODE_EVASION = "unicode_evasion", // NEW: Unicode character abuse
  FRAGMENT_PAYLOAD = "fragment_payload", // NEW: Payload split across parameters
  HEADER_INJECTION = "header_injection", // NEW: HTTP header injection
  NOSQL_INJECTION = "nosql_injection", // NEW: NoSQL injection patterns
  GRAPHQL_INJECTION = "graphql_injection", // NEW: GraphQL injection
  DOM_BASED_ATTACK = "dom_based_attack", // NEW: DOM-based attacks
  FILE_INCLUSION = "file_inclusion", // NEW: Remote/Local file inclusion
  RFI = "remote_file_inclusion",
  PHISHING = "phishing", //new

  // New pattern types
  PROTOTYPE_POLLUTION = "prototype_pollution",
  JWT_MANIPULATION = "jwt_manipulation",
  CSS_INJECTION = "css_injection",
  HOST_HEADER_INJECTION = "host_header_injection",
  DESERIALIZATION = "deserialization",
  DOM_CLOBBERING = "dom_clobbering",
  CLICKJACKING = "clickjacking",
  CORS_MISCONFIGURATION = "cors_misconfiguration",
  SUBDOMAIN_TAKEOVER = "subdomain_takeover",
  HTTP_PARAMETER_POLLUTION = "http_parameter_pollution",
  WEB_CACHE_POISONING = "web_cache_poisoning",
  ANOMALY = "anomaly",
  ZERO_DAY = "zero_day",
}

/**
 * Interface for malicious pattern detection options
 */
export interface MaliciousPatternOptions {
  /**
   * Minimum score required to mark input as malicious (default: 50)
   */
  minScore?: number;
  /**
   * Enable verbose logging for debugging
   */
  debug?: boolean;
  /**
   * List of pattern types to ignore
   */
  ignorePatterns?: MaliciousPatternType[];
  /**
   * Adjust sensitivity for detections (0.1-2.0)
   * Lower values mean less sensitive, higher values mean more sensitive
   */
  sensitivity?: number;
  /**
   * Custom patterns to include in detection
   */
  customPatterns?: Array<{
    pattern: RegExp;
    type: MaliciousPatternType;
    severity: "low" | "medium" | "high";
    description: string;
  }>;
  /**
   * Enable contextual analysis for improved detection
   */
  enableContextualAnalysis?: boolean;
  /**
   * Enable entropy analysis for obfuscated payloads
   */
  enableEntropyAnalysis?: boolean;
  /**
   * Enable statistical analysis
   */
  enableStatisticalAnalysis?: boolean;
  /**
   * Component-specific sensitivity multipliers
   */
  componentSensitivity?: Record<MaliciousComponentType, number>;
  /**
   * Character set to focus on for pattern matching (default: latin)
   */
  characterSet?: "latin" | "unicode" | "all";
}

/**
 * Enhanced service for detecting various malicious patterns in URLs and general input
 * NehonixNMPS => NMPS
 *
 */
