import { Request, Response, NextFunction, Router } from "express";
import { NSB } from "../../../services/NehonixSecurityBooster.service";
import {
  MaliciousPatternResult,
  MaliciousPatternOptions,
  DetectedPattern,
} from "../../../services/MaliciousPatterns.service";
import { AppLogger } from "../../../common/AppLogger";
import {
  NsbMiddlewareOptions,
  SecurityDatabaseAdapterType,
  SecurityEvent,
} from "../../types/types.express.middleware";
import {
  deduplicatePatterns,
  defaultOptions,
  getClientIP,
  rateLimitStore,
  suspiciousIPs,
} from "./EXPRESS.config";
import {
  activeDatabase,
  defaultDatabase,
  getDatabaseAdapter,
  NLM,
  setDatabaseAdapter,
} from "./NEHONIX.LocalMemory";
import { combineResults } from "./EXPRESS.combineResults";
import {
  applySecureHeaders,
  generateRequestId,
  generateTimelineData,
  sanitizeOutputData,
} from "./helpers/EXPRESS.helper";
import { nehonixShield } from "./EXPRESS.nShield";
import { createSecurityReportingRouter } from "./EXPRESS.routes";

/**
 * Enhanced NSB Express middleware for securing incoming requests
 * @param options - Middleware options
 * @returns Express middleware function
 */
export const nehonixShieldMiddleware = (options: NsbMiddlewareOptions = {}) => {
  // Merge with default options
  const mergedOptions = { ...defaultOptions, ...options };

  return async (req: Request, res: Response, next: NextFunction) => {
    const clientIP = getClientIP(req);

    try {
      // Check if IP is blacklisted (either in options or database)
      if (
        mergedOptions.ipBlacklist?.includes(clientIP) ||
        (await activeDatabase.isIPBlocked(clientIP))
      ) {
        // Log security event
        await activeDatabase.saveSecurityEvent({
          timestamp: Date.now(),
          type: "block",
          ip: clientIP,
          url: `${req.protocol}://${req.get("host")}${req.originalUrl}`,
          method: req.method,
        });

        return res.status(403).json({
          error: "Access denied",
          message: "Your IP address has been blacklisted",
          requestId: generateRequestId(),
        });
      }

      // IP whitelist bypass
      if (mergedOptions.ipWhitelist?.includes(clientIP)) {
        return next();
      }

      // Rate limiting check
      if (
        mergedOptions.enableRateLimit &&
        !checkRateLimit(req, res, mergedOptions)
      ) {
        return;
      }

      // Bypass token check
      if (
        mergedOptions.bypassHeader &&
        mergedOptions.bypassToken &&
        req.get(mergedOptions.bypassHeader) === mergedOptions.bypassToken
      ) {
        return next();
      }

      // Secure headers if enabled
      if (mergedOptions.secureHeaders) {
        applySecureHeaders(res);
      }

      // Analyze request components
      const result = await scanRequest(
        req,
        mergedOptions.scanComponents || ["url", "body"],
        mergedOptions
      );

      if (mergedOptions.logDetails) {
        const fullUrl = `${req.protocol}://${req.get("host")}${
          req.originalUrl
        }`;
        AppLogger.info(`NSB Analysis for ${fullUrl}:`, result);
      }

      // Check if request is malicious based on score or detection
      const isBlocked =
        (result.isMalicious && mergedOptions.blockOnMalicious) ||
        result.score >= (mergedOptions.scoreThreshold || 80);

      if (isBlocked) {
        // Create security event
        const securityEvent: SecurityEvent = {
          timestamp: Date.now(),
          type: "block",
          ip: clientIP,
          url: `${req.protocol}://${req.get("host")}${req.originalUrl}`,
          method: req.method,
          score: result.score,
          patterns: result.detectedPatterns,
        };

        // Update suspicious IP tracking with detailed information
        await trackSuspiciousIP(clientIP, {
          lastBlockReason: result.detectedPatterns
            .map((p) => p.type)
            .join(", "),
          lastBlockedUrl: req.originalUrl,
          lastBlockedMethod: req.method,
          score: result.score,
        });

        // Log security event to database
        await activeDatabase.saveSecurityEvent(securityEvent);

        // If automatic blocking is enabled and score is very high, add to permanent block list
        if (mergedOptions.automaticBlocking && result.score >= 150) {
          await activeDatabase.blockIP(
            clientIP,
            `Automatic block - high threat score: ${result.score}`
          );
        }

        // Use custom handler if provided
        if (mergedOptions.customBlockHandler) {
          return mergedOptions.customBlockHandler(req, res, result);
        }

        // Default blocking response
        return res.status(403).json({
          error: "Security violation detected",
          details: result.detectedPatterns,
          recommendation: result.recommendation,
          requestId: generateRequestId(),
        });
      }

      // Add analysis result to request object
      (req as any).nehonixShield = result;

      // Transform responses if enabled
      if (mergedOptions.transformResponse) {
        const originalSend = res.send;
        res.send = function (body) {
          // Apply output transformations to prevent data leakage
          const sanitizedBody =
            typeof body === "string" ? sanitizeOutputData(body) : body;
          return originalSend.call(this, sanitizedBody);
        };
      }

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
 * @parascanRequestm options - NSB analysis options
 * @returns Analysis result
 */
export const scanRequest = async (
  req: Request,
  components: ("url" | "headers" | "query" | "body")[] = ["url"],
  options: MaliciousPatternOptions & {
    blockOnMalicious?: boolean;
  } = {}
): Promise<MaliciousPatternResult> => {
  const results: MaliciousPatternResult[] = [];

  if (components.includes("url")) {
    const fullUrl = `${req.protocol}://${req.get("host")}${req.originalUrl}`;
    const urlResult = await NSB.analyzeUrl(fullUrl, options);
    results.push(urlResult);
  }

  if (components.includes("headers")) {
    const headersToCheck = [
      "host",
      "user-agent",
      "referer",
      "origin",
      "x-forwarded-for",
      "x-forwarded-host",
      "x-forwarded-proto",
      "x-forwarded-port",
      "x-forwarded-ssl",
    ];

    for (const header of headersToCheck) {
      const headerValue = req.get(header);
      if (headerValue) {
        try {
          const headerResult = await NSB.analyzeUrl(
            `http://mock.nehonix.space/${header}/${encodeURIComponent(
              headerValue
            )}`,
            options
          );
          results.push(headerResult);
        } catch (err) {
          AppLogger.warn(`Failed to analyze header ${header}:`, err);
        }
      }
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
 * Tracks suspicious IPs for potential automatic blocking
 */
async function trackSuspiciousIP(ip: string, details: any = {}): Promise<void> {
  await activeDatabase.trackSuspiciousIP(ip, details);
}

/**
 * Cleans up old suspicious IP records
 */
export function cleanupSuspiciousIPs(): void {
  const now = Date.now();
  const expirationTime = 24 * 60 * 60 * 1000; // 24 hours

  for (const [ip, record] of suspiciousIPs.entries()) {
    if (now - record.lastSeen > expirationTime) {
      suspiciousIPs.delete(ip);
    }
  }
}

/**
 * Checks rate limiting for a request
 */
function checkRateLimit(
  req: Request,
  res: Response,
  options: NsbMiddlewareOptions
): boolean {
  if (!options.enableRateLimit || !options.rateLimit) return true;

  const ip = getClientIP(req);
  const now = Date.now();
  const windowMs = options.rateLimit.windowMs || 15 * 60 * 1000;
  const maxRequests = options.rateLimit.maxRequests || 100;

  // Get or create rate limit record
  let record = rateLimitStore.get(ip);
  if (!record) {
    record = { count: 0, resetTime: now + windowMs };
    rateLimitStore.set(ip, record);
  }

  // Reset if window expired
  if (now > record.resetTime) {
    record.count = 0;
    record.resetTime = now + windowMs;
  }

  // Increment count
  record.count += 1;

  // Check if limit exceeded
  if (record.count > maxRequests) {
    const message =
      options.rateLimit.message || "Too many requests, please try again later";
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);

    res.setHeader("Retry-After", retryAfter.toString());
    res.status(429).send(message);
    return false;
  }

  return true;
}

/**
 *
 * This function aggregates all security events from the database and generates a detailed
 * security report with threat analysis, recommendations, and visualizable timeline data.
 * The report's detail level and included sections are customizable through options.
 *
 * @param options Report generation options
 * @returns Detailed security report
 * @example
 * ```typescript
 * // Generate a basic report for the last 30 days
 * const basicReport = await generateSecurityReport({
 *   days: 30,
 *   detailLevel: 'basic'
 * });
 *
 * // Generate a comprehensive report with all details
 * const fullReport = await generateSecurityReport({
 *   days: 7,
 *   detailLevel: 'comprehensive',
 *   includeIPs: true,
 *   includePatterns: true,
 *   includeRecommendations: true
 * });
 * ```
 */
export async function generateSecurityReport(
  options: {
    days?: number;
    includeIPs?: boolean;
    includePatterns?: boolean;
    includeRecommendations?: boolean;
    detailLevel?: "basic" | "detailed" | "comprehensive";
  } = {}
): Promise<object> {
  const {
    days = 7,
    includeIPs = true,
    includePatterns = true,
    includeRecommendations = true,
    detailLevel = "detailed",
  } = options;

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);

  // Get security events from the database
  const securityEvents = await activeDatabase.getSecurityEvents({
    startDate,
    endDate,
  });

  // Calculate statistics
  const totalEvents = securityEvents.length;
  const eventsByType = new Map<string, number>();
  const patternTypes = new Map<string, number>();
  const blockedIPs = new Set<string>();
  const suspiciousIPs = new Set<string>();
  const topUrls = new Map<string, number>();

  // Process all events
  securityEvents.forEach((event) => {
    // Count by event type
    const currentTypeCount = eventsByType.get(event.type) || 0;
    eventsByType.set(event.type, currentTypeCount + 1);

    // Track unique IPs by category
    if (event.type === "block") {
      blockedIPs.add(event.ip);
    }
    if (event.type === "suspicious") {
      suspiciousIPs.add(event.ip);
    }

    // Track attack patterns
    if (event.patterns) {
      event.patterns.forEach((pattern) => {
        const patternKey = pattern.type;
        const currentPatternCount = patternTypes.get(patternKey) || 0;
        patternTypes.set(patternKey, currentPatternCount + 1);
      });
    }

    // Track affected URLs
    if (event.url) {
      const urlPath = new URL(event.url).pathname;
      const currentUrlCount = topUrls.get(urlPath) || 0;
      topUrls.set(urlPath, currentUrlCount + 1);
    }
  });

  // Get suspicious IPs data
  const suspiciousIPsData = includeIPs
    ? await activeDatabase.getSuspiciousIPs()
    : [];

  // Sort pattern types by frequency
  const sortedPatternTypes = Array.from(patternTypes.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([pattern, count]) => ({ pattern, count }));

  // Sort URLs by frequency
  const sortedUrls = Array.from(topUrls.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([url, count]) => ({ url, count }));

  // Generate recommendations based on the detected patterns
  const recommendations: string[] = [];
  if (includeRecommendations) {
    if (patternTypes.has("sql_injection")) {
      recommendations.push(
        "Implement prepared statements for all database queries to prevent SQL injection"
      );
    }
    if (patternTypes.has("xss")) {
      recommendations.push(
        "Use content security policy and output encoding to prevent cross-site scripting"
      );
    }
    if (patternTypes.has("path_traversal")) {
      recommendations.push(
        "Validate file paths against a whitelist and use path normalization to prevent directory traversal"
      );
    }
    if (
      eventsByType.get("rate_limit") &&
      (eventsByType.get("rate_limit") || 0) > 100
    ) {
      recommendations.push(
        "Consider implementing more aggressive rate limiting or adding CAPTCHA for suspicious IPs"
      );
    }
    if (blockedIPs.size > 10) {
      recommendations.push(
        "Consider implementing a web application firewall (WAF) for additional protection"
      );
    }
  }

  // Build the base report
  const report: any = {
    generatedAt: new Date().toISOString(),
    period: {
      start: startDate.toISOString(),
      end: endDate.toISOString(),
      days,
    },
    summary: {
      totalSecurityEvents: totalEvents,
      blockedRequests: eventsByType.get("block") || 0,
      warnings: eventsByType.get("warning") || 0,
      suspiciousActivities: eventsByType.get("suspicious") || 0,
      rateLimitHits: eventsByType.get("rate_limit") || 0,
      uniqueBlockedIPs: blockedIPs.size,
      uniqueSuspiciousIPs: suspiciousIPs.size,
    },
  };

  // Add detailed information based on detail level
  if (detailLevel === "detailed" || detailLevel === "comprehensive") {
    report.threatAnalysis = {
      topThreats: sortedPatternTypes,
      topTargetedEndpoints: sortedUrls,
      geographicDistribution: {}, // Would be populated if using a real IP database
    };

    if (includeRecommendations) {
      report.recommendations = recommendations;
    }
  }

  // Add comprehensive details
  if (detailLevel === "comprehensive") {
    if (includeIPs) {
      report.suspiciousIPsDetails = suspiciousIPsData
        .sort((a, b) => b.count - a.count)
        .slice(0, 100); // Limit to top 100 IPs
    }

    if (includePatterns) {
      // Add sample attack patterns for educational purposes
      report.sampleAttackPatterns = securityEvents
        .filter((event) => event.patterns && event.patterns.length > 0)
        .slice(0, 20)
        .map((event) => ({
          timestamp: new Date(event.timestamp).toISOString(),
          patterns: event.patterns,
          score: event.score,
        }));
    }

    // Add timeline data for visualization
    const timeline = generateTimelineData(securityEvents, days);
    report.timeline = timeline;
  }

  return report;
}

/**
 * Function to block an IP address with a custom reason
 */
export async function blockIP(ip: string, reason: string): Promise<boolean> {
  return await activeDatabase.blockIP(ip, reason);
}

/**
 * Creates a custom database adapter for specific storage solutions
 * @param implementation The implementation of the database adapter
 * @returns A configured SecurityDatabaseAdapter
 */
export function createDatabaseAdapter(
  implementation: Partial<SecurityDatabaseAdapterType>
): SecurityDatabaseAdapterType {
  // Create a wrapper that falls back to the default implementation
  return {
    trackSuspiciousIP:
      implementation.trackSuspiciousIP ||
      defaultDatabase.trackSuspiciousIP.bind(defaultDatabase),
    getSuspiciousIPs:
      implementation.getSuspiciousIPs ||
      defaultDatabase.getSuspiciousIPs.bind(defaultDatabase),
    blockIP:
      implementation.blockIP || defaultDatabase.blockIP.bind(defaultDatabase),
    isIPBlocked:
      implementation.isIPBlocked ||
      defaultDatabase.isIPBlocked.bind(defaultDatabase),
    saveSecurityEvent:
      implementation.saveSecurityEvent ||
      defaultDatabase.saveSecurityEvent.bind(defaultDatabase),
    getSecurityEvents:
      implementation.getSecurityEvents ||
      defaultDatabase.getSecurityEvents.bind(defaultDatabase),
  };
}
