import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
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
