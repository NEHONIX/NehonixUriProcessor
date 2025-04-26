import { Request, Response, NextFunction } from "express";
import { NSB } from "../../services/NehonixSecurityBooster.service";
import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
} from "../../services/MaliciousPatterns.service";
import { DetectedPattern } from "../../services/MaliciousPatterns.service";
import { AppLogger } from "../../common/AppLogger";

/**
 * Interface for NSB Express middleware options
 */
interface NsbMiddlewareOptions extends MaliciousPatternOptions {
  blockOnMalicious?: boolean;
  logDetails?: boolean;
}

/**
 * NSB Express middleware for securing incoming requests
 * @param options - Middleware options
 * @returns Express middleware function
 */
export const nehonixShieldMiddleware = (options: NsbMiddlewareOptions = {}) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const fullUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
      const result = await NSB.analyzeUrl(fullUrl, options);

      if (options.logDetails) {
        AppLogger.info(`NSB Analysis for ${fullUrl}:`, result);
      }

      if (result.isMalicious && options.blockOnMalicious) {
        return res.status(403).json({
          error: "Malicious request detected",
          details: result.detectedPatterns,
          recommendation: result.recommendation,
        });
      }

      (req as any).nehonixShield = result;
      next();
    } catch (error) {
      AppLogger.error("Nehonix Shield Middleware Error:", error);
      next(error);
    }
  };
};

/**
 * Utility to analyze specific request components
 * @param req - Express request object
 * @param components - Components to analyze (url, headers, query, body)
 * @param options - NSB analysis options
 * @returns Analysis result
 */
export const scanRequest = async (
  req: Request,
  components: ("url" | "headers" | "query" | "body")[] = ["url"],
  options: MaliciousPatternOptions = {}
): Promise<MaliciousPatternResult> => {
  const results: MaliciousPatternResult[] = [];

  if (components.includes("url")) {
    const fullUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
    const urlResult = await NSB.analyzeUrl(fullUrl, options);
    results.push(urlResult);
  }

  if (components.includes("headers")) {
    const hostHeader = req.get("Host") || "";
    if (hostHeader) {
      const headerResult = await NSB.analyzeUrl(
        `http://${hostHeader}`,
        options
      );
      results.push(headerResult);
    }
  }

  if (components.includes("query")) {
    const queryString = new URLSearchParams(req.query as any).toString();
    if (queryString) {
      const queryResult = await NSB.analyzeUrl(
        `http://mock.nehonix.space?${queryString}`,
        options
      );
      results.push(queryResult);
    }
  }

  if (components.includes("body") && req.body) {
    const bodyString = JSON.stringify(req.body);
    if (bodyString) {
      const bodyResult = await NSB.analyzeUrl(
        `http://mock.nehonix.space?data=${encodeURIComponent(bodyString)}`,
        options
      );
      results.push(bodyResult);
    }
  }

  return combineResults(results);
};

/**
 * Combines multiple analysis results
 */
function combineResults(
  results: MaliciousPatternResult[]
): MaliciousPatternResult {
  const combined: MaliciousPatternResult = {
    isMalicious: false,
    detectedPatterns: [],
    score: 0,
    confidence: "low",
    recommendation: "No issues detected.",
    contextAnalysis: {
      relatedPatterns: [],
      entropyScore: 0,
      anomalyScore: 0,
      encodingLayers: 0,
    },
  };

  results.forEach((result) => {
    combined.isMalicious = combined.isMalicious || result.isMalicious;
    combined.detectedPatterns.push(...result.detectedPatterns);
    combined.score += result.score;
    combined.contextAnalysis!.entropyScore +=
      result.contextAnalysis?.entropyScore || 0;
    combined.contextAnalysis!.anomalyScore +=
      result.contextAnalysis?.anomalyScore || 0;
    combined.contextAnalysis!.encodingLayers +=
      result.contextAnalysis?.encodingLayers || 0;
    if (result.confidence === "high") {
      combined.confidence = "high";
    } else if (
      result.confidence === "medium" &&
      combined.confidence !== "high"
    ) {
      combined.confidence = "medium";
    }
  });

  combined.detectedPatterns = deduplicatePatterns(combined.detectedPatterns);
  combined.score = Math.min(combined.score, 200);
  combined.recommendation = results.some((r) => r.isMalicious)
    ? "Malicious patterns detected. Review and mitigate."
    : combined.recommendation;

  return combined;
}

/**
 * Deduplicates patterns
 */
function deduplicatePatterns(patterns: DetectedPattern[]): DetectedPattern[] {
  const seen: Map<string, DetectedPattern> = new Map();
  patterns.forEach((pattern) => {
    const key = `${pattern.type}:${pattern.matchedValue}:${pattern.location}`;
    if (!seen.has(key)) {
      seen.set(key, pattern);
    }
  });
  return Array.from(seen.values());
}
