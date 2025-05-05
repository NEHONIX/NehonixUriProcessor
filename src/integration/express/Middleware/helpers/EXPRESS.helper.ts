import { Response } from "express";
import { SecurityEvent } from "../../../types/types.express.middleware";
/**
 * Applies secure headers to responses
 */
export function applySecureHeaders(res: Response): void {
  // Security headers
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains"
  );

  // Remove fingerprinting headers
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");
}

/**
 * Generates a unique request ID
 */
export function generateRequestId(): string {
  return `nehonix_shield-${Date.now()}-${Math.random()
    .toString(36)
    .substring(2, 15)}`;
}

/**
 * Sanitizes output data to prevent information leakage
 */
export function sanitizeOutputData(data: string): string {
  return data
    .replace(/\/[\/\w-]+\/[\w-]+\/[\w-.]+/g, "[PATH]") // Hide file paths
    .replace(/(\d{1,3}\.){3}\d{1,3}/g, "[IP]") // Hide IP addresses
    .replace(/[a-zA-Z0-9+/]{20,}/g, "[BASE64]"); // Hide potential base64 data
}

/**
 * Generates timeline data for the security report
 */
export function generateTimelineData(
  events: SecurityEvent[],
  days: number
): Array<{
  date: string;
  blocks: number;
  warnings: number;
  suspicious: number;
}> {
  const timeline: Array<{
    date: string;
    blocks: number;
    warnings: number;
    suspicious: number;
  }> = [];

  // Create date buckets
  const endDate = new Date();
  for (let i = 0; i < days; i++) {
    const date = new Date();
    date.setDate(endDate.getDate() - (days - 1 - i));

    timeline.push({
      date: date.toISOString().split("T")[0],
      blocks: 0,
      warnings: 0,
      suspicious: 0,
    });
  }

  // Fill the timeline with event counts
  events.forEach((event) => {
    const eventDate = new Date(event.timestamp).toISOString().split("T")[0];
    const timelineEntry = timeline.find((entry) => entry.date === eventDate);

    if (timelineEntry) {
      if (event.type === "block") {
        timelineEntry.blocks++;
      } else if (event.type === "warning") {
        timelineEntry.warnings++;
      } else if (event.type === "suspicious") {
        timelineEntry.suspicious++;
      }
    }
  });

  return timeline;
}
