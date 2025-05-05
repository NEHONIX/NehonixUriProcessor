import { DetectedPattern, MaliciousPatternOptions, MaliciousPatternResult } from "../../services/MaliciousPatterns.service";
import type{Request, Response} from "express"

export interface NsbMiddlewareOptions extends MaliciousPatternOptions {
  blockOnMalicious?: boolean;
  logDetails?: boolean;
  automaticBlocking?: boolean;
  customBlockHandler?: (
    req: Request,
    res: Response,
    result: MaliciousPatternResult
  ) => void;
  scoreThreshold?: number;
  bypassHeader?: string;
  bypassToken?: string;
  enableRateLimit?: boolean;
  rateLimit?: {
    windowMs?: number;
    maxRequests?: number;
    message?: string | object;
  };
  scanComponents?: ("url" | "headers" | "query" | "body")[];
  ipBlacklist?: string[];
  ipWhitelist?: string[];
  transformResponse?: boolean;
  secureHeaders?: boolean;
}


/**
 * Security event interface for logging security-related actions
 */
export interface SecurityEvent {
  timestamp: number;
  type: "block" | "warning" | "suspicious" | "rate_limit" | "bypass";
  ip: string;
  url?: string;
  method?: string;
  score?: number;
  patterns?: DetectedPattern[];
  details?: any;
}


/**
 * Database adapter interface for persistent storage
 */
export interface SecurityDatabaseAdapterType {
  trackSuspiciousIP: (ip: string, details: any) => Promise<void>;
  getSuspiciousIPs: () => Promise<
    Array<{ ip: string; count: number; lastSeen: number; details?: any }>
  >;
  blockIP: (ip: string, reason: string) => Promise<boolean>;
  isIPBlocked: (ip: string) => Promise<boolean>;
  saveSecurityEvent: (event: SecurityEvent) => Promise<void>;
  getSecurityEvents: (options: {
    startDate: Date;
    endDate: Date;
  }) => Promise<SecurityEvent[]>;
}