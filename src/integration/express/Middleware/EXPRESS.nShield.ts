import { nehonixShieldMiddleware } from "./express.middleware";

/**
 * Creates pre-configured middleware functions
 */
export const nehonixShield = {
  /**
   * Standard security middleware with balanced settings
   */
  standard: nehonixShieldMiddleware({
    blockOnMalicious: true,
    logDetails: true,
    scanComponents: ["url", "query", "headers"],
    scoreThreshold: 70,
    secureHeaders: true,
  }),

  /**
   * Strict security middleware with aggressive blocking
   */
  strict: nehonixShieldMiddleware({
    blockOnMalicious: true,
    logDetails: true,
    automaticBlocking: true,
    scanComponents: ["url", "query", "headers", "body"],
    scoreThreshold: 50,
    secureHeaders: true,
    enableRateLimit: true,
    transformResponse: true,
  }),

  /**
   * Monitor-only mode that logs but doesn't block
   */
  monitor: nehonixShieldMiddleware({
    blockOnMalicious: false,
    logDetails: true,
    scanComponents: ["url", "query", "headers", "body"],
    secureHeaders: true,
  }),

  /**
   * Creates a custom middleware instance
   */
  custom: nehonixShieldMiddleware,
};
