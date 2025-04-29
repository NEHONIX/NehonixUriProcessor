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

/**
 * Interface for NSB context
 */
export interface ShieldContextType {
  scanUrl: (
    url: string,
    options?: MaliciousPatternOptions
  ) => Promise<MaliciousPatternResult>;
  provideFeedback: (
    url: string,
    result: MaliciousPatternResult,
    isCorrect: boolean
  ) => void;
  getPerformanceMetrics: () => PerformanceMetrics;
  scanInput: (
    ...p: Parameters<typeof NSB.analyzeUrl>
  ) => ReturnType<typeof NSB.analyzeUrl>;
}

/**
 * Extended Shield Context Type
 */
export interface ExtendedShieldContextType extends ShieldContextType {
  analyzeDom: (options?: DomAnalysisOptions) => Promise<MaliciousPatternResult>;
  analyzeRequests: (options?: RequestAnalysisOptions) => void;
  stopRequestAnalysis: () => void;
  blockingEnabled: boolean;
  setBlockingEnabled: (enabled: boolean) => void;
  lastAnalysisResult: MaliciousPatternResult | null;
  isAnalyzing: boolean;
}

/**
 * DOM Analysis Options
 */
export interface DomAnalysisOptions extends MaliciousPatternOptions {
  targetSelector?: string;
  includeAttributes?: boolean;
  includeScripts?: boolean;
  includeLinks?: boolean;
  scanIframes?: boolean;
}

/**
 * Request Analysis Options
 */
export interface RequestAnalysisOptions extends MaliciousPatternOptions {
  includeXHR?: boolean;
  includeFetch?: boolean;
  includeImages?: boolean;
  includeScripts?: boolean;
  blockOnMalicious?: boolean;
}

/**
 * NSB provider props
 */
export interface NsbProviderProps {
  children: React.ReactNode;
  defaultOptions?: MaliciousPatternOptions;
  autoBlocking?: boolean;
}

//v2.3.4
// DOM Element analysis result
export interface DomAnalysisResult {
  element: HTMLElement;
  result: MaliciousPatternResult;
}

// Enhanced Shield Options
export interface EnhancedShieldOptions extends MaliciousPatternOptions {
  blockOnMalicious: boolean;
  blockThreshold: number;
  showAlerts: boolean;
  alertDuration: number;
  scanDom: boolean;
  scanRequests: boolean;
  deepScan: boolean;
  whitelistedDomains: string[];
  alertPosition: "top-right" | "top-left" | "bottom-right" | "bottom-left";
  autoCleanDOM: boolean;
  scanInterval: number;
  reportToServer: boolean;
}

export interface EnhancedShieldContextType extends ShieldContextType {
  scanDom: (
    options?: Partial<EnhancedShieldOptions>
  ) => Promise<DomAnalysisResult[]>;
  interceptRequests: (enable: boolean) => void;
  setShieldOptions: (options: Partial<EnhancedShieldOptions>) => void;
  currentOptions: EnhancedShieldOptions;
  maliciousElements: DomAnalysisResult[];
  blockedRequests: string[];
  clearAlerts: () => void;
  resetStats: () => void;
}


// Provider Props
export interface EnhancedShieldProviderProps {
  children: React.ReactNode;
  options?: Partial<EnhancedShieldOptions>;
}

/**
 * Alert component for displaying security notifications
 */
export interface AlertProps {
  message: string;
  type: "warning" | "error" | "info";
  details?: DetectedPattern[];
  onDismiss: () => void;
  position: "top-right" | "top-left" | "bottom-right" | "bottom-left";
}

