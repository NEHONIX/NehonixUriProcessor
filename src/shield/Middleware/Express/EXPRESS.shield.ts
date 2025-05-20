import { Request, Response, NextFunction } from "express";
import { randomBytes } from "crypto";
import { parse as parseUrl } from "url";
import ipRangeCheck from "ip-range-check";
import { ncu } from "../../../utils/NehonixCoreUtils";

/**
 * Content Security Policy middleware
 * Helps prevent XSS, clickjacking, and other code injection attacks
 */
export const setupCSP = (req: Request, res: Response, next: NextFunction) => {
  // Generate a nonce for inline scripts (if needed)
  const nonce = randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce;

  // Set CSP header with appropriate directives
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'self'; 
     script-src 'self' 'nonce-${nonce}' https://trusted-cdn.com; 
     style-src 'self' https://trusted-cdn.com; 
     img-src 'self' data: https://trusted-cdn.com; 
     font-src 'self' https://trusted-cdn.com; 
     connect-src 'self' https://api.yourdomain.com; 
     frame-ancestors 'none'; 
     form-action 'self';
     base-uri 'self';
     object-src 'none'`
  );

  next();
};

/**
 * CSRF Protection middleware
 * Validates that requests with cookies are from your site
 */
export const csrfProtection = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Skip for non-state-changing methods
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const csrfToken = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"];
  const storedToken = req.cookies["csrf-token"];

  if (!csrfToken || !storedToken || csrfToken !== storedToken) {
    return res.status(403).json({ error: "CSRF token validation failed" });
  }

  next();
};

/**
 * Trusted Proxy Configuration
 * Ensures X-Forwarded-* headers are only trusted from known proxies
 */
export const configureTrustedProxy = (
  req: any,
  res: Response,
  next: NextFunction
) => {
  const trustedProxies = process?.env?.TRUSTED_PROXIES?.split(",") || [];
  const clientIp = req.ip || req.connection.remoteAddress || "";

  // Only trust X-Forwarded-* headers if request comes from trusted proxy
  if (trustedProxies.includes(clientIp)) {
    req.trusted = true;
  } else {
    req.trusted = false;
    // Don't trust headers that might be spoofed
    delete req.headers["x-forwarded-for"];
    delete req.headers["x-forwarded-proto"];
    delete req.headers["x-forwarded-host"];
  }

  next();
};

/**
 * Secure Cookie Settings
 * Enhances cookie security beyond the basics
 */
export const secureCoookieSettings = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Override res.cookie to enforce secure settings
  const originalCookie = res.cookie;
  res.cookie = function (name: string, value: any, options: any = {}) {
    const secureOptions = {
      ...options,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    };

    return (originalCookie as any).call(this, name, value, secureOptions);
  };

  next();
};

/**
 * Request Validation middleware
 * Validates incoming requests for required fields and proper formatting
 */
export const validateRequest = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Check for suspicious patterns in URL
  const url = req.originalUrl;
  const checkUrl = ncu.asyncCheckUrl(url);

  checkUrl.then((result) => {
    if (!result.isValid) {
      return res.status(400).json({
        error: "Suspicious or invalid URL pattern.",
        provider: "nehonix.shield",
        result,
      });
    }
  });

  // Check for overly large payloads (additional check beyond express.json limit)
  const contentLength =
    parseInt(req.headers["content-length"] as string, 10) || 0;
  if (contentLength > 1000000) {
    // 1MB
    return res.status(413).json({ error: "Payload too large" });
  }

  next();
};

/**
 * IP Filtering middleware
 * Blocks requests from suspicious or banned IP addresses
 */
export const ipFilter = (req: Request, res: Response, next: NextFunction) => {
  const clientIp = req.ip || req.connection.remoteAddress || "";

  // Get banned IPs and ranges from environment or configuration
  const bannedIPs = process.env.BANNED_IPS?.split(",") || [];
  const bannedRanges = process.env.BANNED_IP_RANGES?.split(",") || [];

  // Check if IP is in banned list
  if (bannedIPs.includes(clientIp)) {
    return res.status(403).json({ error: "Access denied" });
  }

  // Check if IP is in banned range
  for (const range of bannedRanges) {
    if (ipRangeCheck(clientIp, range.trim())) {
      return res.status(403).json({ error: "Access denied" });
    }
  }

  next();
};

/**
 * Security Headers middleware
 * Sets additional security headers beyond what Helmet provides
 */
export const additionalSecurityHeaders = (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  // Permissions Policy (formerly Feature Policy)
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
  );

  // Clear Site Data on logout routes
  if (req.path.includes("/logout")) {
    res.setHeader("Clear-Site-Data", '"cache", "cookies", "storage"');
  }

  // Cross-Origin Resource Policy
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  // Cross-Origin Opener Policy
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");

  next();
};

/**
 * Apply all security middleware to an Express application
 */
export const applySecurityMiddleware = (app: any) => {
  // Apply all security middleware
  app.use(configureTrustedProxy);
  app.use(setupCSP);
  app.use(secureCoookieSettings);
  app.use(validateRequest);
  app.use(ipFilter);
  app.use(additionalSecurityHeaders);
  app.use(csrfProtection);

  return app;
};
