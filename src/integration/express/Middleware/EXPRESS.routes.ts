import { Router } from "express";
import { rateLimitStore, suspiciousIPs } from "./EXPRESS.config";

/**
 * Security reporting router for analytics dashboard
 */
export function createSecurityReportingRouter(): Router {
  const router = Router();

  // Get suspicious IPs report
  router.get("/suspicious-ips", (req, res) => {
    const report = Array.from(suspiciousIPs.entries()).map(([ip, data]) => ({
      ip,
      hitCount: data.count,
      lastSeen: new Date(data.lastSeen).toISOString(),
    }));

    res.json({
      total: report.length,
      timestamp: new Date().toISOString(),
      data: report,
    });
  });

  // Get rate limit status
  router.get("/rate-limits", (req, res) => {
    const report = Array.from(rateLimitStore.entries()).map(([ip, data]) => ({
      ip,
      requestCount: data.count,
      resetTime: new Date(data.resetTime).toISOString(),
    }));

    res.json({
      total: report.length,
      timestamp: new Date().toISOString(),
      data: report,
    });
  });

  return router;
}
