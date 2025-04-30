import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
  DetectedPattern,
} from "../../services/MaliciousPatterns.service";
import { NSB } from "../../services/NehonixSecurityBooster.service";

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
  trustedDomains?: string[];
  blacklistedPatterns?: string[];
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
