import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
  DetectedPattern,
} from "../../services/MaliciousPatterns.service";
import { NSB } from "../../services/NehonixSecurityBooster.service";
import { UrlValidationOptions } from "../../types";

/**
 * Interface for performance metrics (from NSB)
 */
export interface PerformanceMetrics {
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate?: number;
  totalAnalysisTime: number;
  analysisCount: number;
  avgAnalysisTime?: number;
}

//

/**
 * Interface for the Nehonix Shield configuration
 */
export interface NehonixShieldConfig {
  // Core settings
  enableBackgroundScanning: boolean;
  scanInterval: number; // in milliseconds
  interceptRequests: boolean;
  enableDeepScan: boolean;

  // Scanning options
  scanOptions: {
    analyseOptions: MaliciousPatternOptions;
    global: {
      ignoreCase: boolean;
      checkEncoding: boolean;
      maxEncodingLayers: 3;
      analyzeContext: boolean;
      confidence: "low" | "medium" | "high";
    };
  };

  // Response handling
  blockMaliciousRequests: boolean;
  blockMaliciousResponses: boolean;

  // Callbacks
  onDetection?: (result: MaliciousPatternResult) => void;
  onBlock?: (result: MaliciousPatternResult, request: Request) => void;

  // Whitelist/Blacklist
  blacklistedPatterns?: string[];
  urlUtils: UrlValidationOptions & {
    allowedProtocol?: string[];
    trustedDomains?: string[];
  };
}

/**
 * Interface for the Shield analysis results
 */
export interface ShieldAnalysisResult {
  analysisResults: MaliciousPatternResult[];
  lastScanTimestamp: number;
  totalScanned: number;
  totalBlocked: number;
  activeThreats: DetectedPattern[];
  performanceMetrics: {
    avgScanTime: number;
    totalScanTime: number;
    scanCount: number;
  };
}

/**
 * Interface for the Nehonix Shield Context
 */
export interface NehonixShieldContextT {
  config: NehonixShieldConfig;
  updateConfig: (config: Partial<NehonixShieldConfig>) => void;
  analysisResults: ShieldAnalysisResult;
  isScanning: boolean;
  pauseScanning: () => void;
  resumeScanning: () => void;
  forceScan: () => Promise<void>;
  clearResults: () => void;
}
/**
 * Configuration for the DOM Processor
 */
export interface DomProcessorConfig {
  enabled: boolean;
  processingMode: "idle-callback" | "worker" | "chunk";
  chunkSize: number;
  idleTimeout: number;
  throttleInterval: number;
  targetElements: {
    [key: string]: boolean;
    a: boolean;
    script: boolean;
    iframe: boolean;
    img: boolean;
    form: boolean;
    input: boolean;
    button: boolean;
    source: boolean;
    embed: boolean;
    object: boolean;
  };
  attributesToScan: {
    [key: string]: boolean;
    href: boolean;
    src: boolean;
    action: boolean;
    formaction: boolean;
    data: boolean;
    onclick: boolean;
    onload: boolean;
    onerror: boolean;
    style: boolean;
  };
  scanDepth: "light" | "medium" | "deep";
  ignoreInlineContent: boolean;
  scanShadowDOM: boolean;
  ignoreHiddenElements: boolean;
  parseCss: boolean;
  detectObfuscation: boolean;
  iframeSandboxPolicy: "strict" | "moderate" | "permissive";
  scanXSS: boolean;
  scanCSRF: boolean;
  scanClickjacking: boolean;
  whitelistedDomains: string[];
  blacklistedPatterns: string[];
  onDetectionCallbacks: {
    [elementType: string]: (result: ElementDetectionResult) => void;
  };
  analyzeOptions: {
    debug: boolean;
    checkEncoding: boolean;
    ignoreCase: boolean;
    maxEncodingLayers: number;
  };
}

/**
 * Statistics for the DOM Processor
 */
export interface DomProcessorStats {
  elementsScanned: number;
  threatsDetected: number;
  lastScanTimestamp: number;
  scanDuration: number;
  scanningActive: boolean;
  elementTypeStats: {
    [elementType: string]: number;
  };
  threatsByType: {
    [threatType: string]: number;
  };
  blockedElements: Array<{
    elementType: string;
    timestamp: number;
    threatTypes: string[];
  }>;
  pendingElements: number;
  avgProcessingTimePerElement: number;
  totalProcessingTime: number;
}

/**
 * Result of a DOM element scan
 */
export interface ElementScanResult {
  element: Element;
  elementType: string;
  results: MaliciousPatternResult[];
  scannedAttributes: Record<string, MaliciousPatternResult>;
  duration: number;
  timestamp: number;
  hasMaliciousContent: boolean;
  error?: string;
}

/**
 * Detection result for callback functions
 */
export interface ElementDetectionResult {
  element: Element;
  results: MaliciousPatternResult[];
  elementType: string;
}

/**
 * DOM Processor Context Type
 */
export interface DomProcessorContextT {
  config: DomProcessorConfig;
  updateConfig: (newConfig: Partial<DomProcessorConfig>) => void;
  stats: DomProcessorStats;
  scanDOM: () => void;
  stopScanning: () => void;
  resetStats: () => void;
  getSecurityReport: () => Record<string, any>;
  isScanning: boolean;
}

/**
 * Combined security suite context
 */
export interface SecuritySuiteContext {
  shield: NehonixShieldContextT;
  domProcessor: DomProcessorContextT;
  forceFullScan: () => void;
  resetAllStats: () => void;
  getComprehensiveReport: () => Record<string, any>;
  getSecurityStatus: () => {
    isSecure: boolean;
    activeThreats: Array<any>;
    lastScanTime: number;
    scanning: boolean;
  };
  updateConfig: (
    shieldConfig?: Partial<NehonixShieldConfig>,
    domConfig?: Partial<DomProcessorConfig>
  ) => void;
  pauseAllScanning: () => void;
  resumeAllScanning: () => void;
  stats: {
    elementsScanned: number;
    urlsScanned: number;
    threatsDetected: number;
    lastScanTimestamp: number;
    scanDuration: number;
    scanningActive: boolean;
    elementTypeStats: Record<string, number>;
    threatsByType: Record<string, number>;
    blockedElements: Array<any>;
    performance: {
      avgElementScanTime: number;
      avgUrlScanTime: number;
    };
  };
  isScanning: boolean;
}