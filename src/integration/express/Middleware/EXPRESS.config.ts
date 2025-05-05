import { Request } from "express";
import { DetectedPattern } from "../../../services/MaliciousPatterns.service";
import { NsbMiddlewareOptions } from "../../types/types.express.middleware";

/**
 * Default options for the middleware
 */
export const defaultOptions: NsbMiddlewareOptions = {
  blockOnMalicious: true,
  logDetails: true,
  automaticBlocking: false,
  scoreThreshold: 80,
  enableRateLimit: false,
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    message: "Too many requests, please try again later",
  },
  scanComponents: ["url", "query"],
  transformResponse: false,
  secureHeaders: true,
};

/**
 * Stores IPs that have been flagged as suspicious
 */
export const suspiciousIPs: Map<string, { count: number; lastSeen: number }> =
  new Map();

/**
 * Rate limiting storage
 */
export const rateLimitStore: Map<string, { count: number; resetTime: number }> =
  new Map();

/**
 * Deduplicates patterns
 */
export function deduplicatePatterns(
  patterns: DetectedPattern[]
): DetectedPattern[] {
  const seen: Map<string, DetectedPattern> = new Map();
  patterns.forEach((pattern) => {
    const key = `${pattern.type}:${pattern.matchedValue}:${pattern.location}`;
    if (!seen.has(key)) {
      seen.set(key, pattern);
    }
  });
  return Array.from(seen.values());
}

/**
 * Gets client IP from request
 */
export function getClientIP(req: Request): string {
  const forwardedFor = req.get("X-Forwarded-For");
  if (forwardedFor) {
    // Get the first IP in the chain
    return forwardedFor.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "0.0.0.0";
}
