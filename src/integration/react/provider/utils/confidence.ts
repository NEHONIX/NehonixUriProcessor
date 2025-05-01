// Utility function to convert string confidence to numeric value
export const mapConfidenceToNumber = (
  confidence: "low" | "medium" | "high"
): number => {
  switch (confidence) {
    case "low":
      return 0.3;
    case "medium":
      return 0.6;
    case "high":
      return 0.9;
    default:
      return 0; // Fallback for unexpected values
  }
};
