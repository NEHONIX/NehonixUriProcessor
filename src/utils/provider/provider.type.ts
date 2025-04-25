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
