import { MaliciousPatternResult } from "../../../services/MaliciousPatterns.service";
import { deduplicatePatterns } from "./EXPRESS.config";

/**
 * Combines multiple analysis results
 */
export function combineResults(
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
