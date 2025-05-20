import { Request, Response, NextFunction } from "express";
import { randomBytes } from "crypto";
import ipRangeCheck from "ip-range-check";
import { ShieldRule } from "./types/ShieldTypes";
import { RuleEngine } from "./RuleEngine";
import { ncu } from "../../utils/NehonixCoreUtils";

export class NehonixShield {
  private ruleEngine: RuleEngine;
  private trustedProxies: string[];
  private bannedIPs: string[];
  private bannedRanges: string[];
  private maxPayloadSize: number;

  constructor(config: {
    trustedProxies?: string[];
    bannedIPs?: string[];
    bannedRanges?: string[];
    maxPayloadSize?: number;
    customRules?: ShieldRule[];
  }) {
    this.trustedProxies = config.trustedProxies || [];
    this.bannedIPs = config.bannedIPs || [];
    this.bannedRanges = config.bannedRanges || [];
    this.maxPayloadSize = config.maxPayloadSize || 1000000;
    this.ruleEngine = new RuleEngine(config.customRules || []);
  }

  public setupCSP = (req: Request, res: Response, next: NextFunction) => {
    const nonce = randomBytes(16).toString("base64");
    res.locals.cspNonce = nonce;

    const cspDirectives = this.ruleEngine.getCSPDirectives(nonce);
    res.setHeader("Content-Security-Policy", cspDirectives);
    next();
  };

  public csrfProtection = (req: Request, res: Response, next: NextFunction) => {
    if (this.ruleEngine.shouldSkipCSRF(req)) {
      return next();
    }

    const csrfToken = req.headers["x-csrf-token"] || req.headers["x-xsrf-token"];
    const storedToken = req.cookies["csrf-token"];

   if(typeof csrfToken === "string"){
      if (!this.ruleEngine.validateCSRFToken(csrfToken, storedToken)) {
      return res.status(403).json({ error: "CSRF token validation failed" });
      } else {
        for (const crf of csrfToken) {
           if (!this.ruleEngine.validateCSRFToken(crf, storedToken)) {
      return res.status(403).json({ error: "CSRF token validation failed" });
    }
        }
    }
}
    next();
  };

  public configureTrustedProxy = (req: any, res: Response, next: NextFunction) => {
    const clientIp = req.ip || req.connection.remoteAddress || "";
    req.trusted = this.trustedProxies.includes(clientIp);

    if (!req.trusted) {
      delete req.headers["x-forwarded-for"];
      delete req.headers["x-forwarded-proto"];
      delete req.headers["x-forwarded-host"];
    }

    next();
  };

  public secureCoookieSettings = (req: Request, res: Response, next: NextFunction) => {
    const originalCookie = res.cookie;
    res.cookie = (name: string, value: any, options: any = {}) => {
      const secureOptions = this.ruleEngine.getSecureCookieOptions(options);
      return (originalCookie as any).call(res, name, value, secureOptions);
    };
    next();
  };

  public validateRequest = async (req: Request, res: Response, next: NextFunction) => {
    const url = new URL(`http://mock.nehonix.space/${req.url}`);
    const urlCheckResult = await ncu.asyncCheckUrl(url.toString());

    if (!urlCheckResult.isValid) {
      return res.status(400).json({
        error: "Suspicious or invalid URL pattern",
        provider: "nehonix.shield",
        result: urlCheckResult,
        url: url.toString()
      });
    }

    const contentLength = parseInt(req.headers["content-length"] as string, 10) || 0;
    if (contentLength > this.maxPayloadSize) {
      return res.status(413).json({ error: "Payload too large" });
    }

    if (!await this.ruleEngine.validateRequest(req)) {
      return res.status(400).json({ error: "Request validation failed" });
    }

    next();
  };

  public ipFilter = (req: Request, res: Response, next: NextFunction) => {
    const clientIp = req.ip || req.connection.remoteAddress || "";

    if (this.bannedIPs.includes(clientIp)) {
      return res.status(403).json({ error: "Access denied" });
    }

    for (const range of this.bannedRanges) {
      if (ipRangeCheck(clientIp, range.trim())) {
        return res.status(403).json({ error: "Access denied" });
      }
    }

    if (!this.ruleEngine.validateIP(clientIp)) {
      return res.status(403).json({ error: "IP validation failed" });
    }

    next();
  };

  public additionalSecurityHeaders = (req: Request, res: Response, next: NextFunction) => {
    const headers = this.ruleEngine.getSecurityHeaders(req);
    Object.entries(headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    next();
  };

  public applyMiddleware(app: any) {
    app.use(this.configureTrustedProxy);
    app.use(this.setupCSP);
    app.use(this.secureCoookieSettings);
    app.use(this.validateRequest);
    app.use(this.ipFilter);
    app.use(this.additionalSecurityHeaders);
    app.use(this.csrfProtection);
    return app;
  }

  public loadRules(rules: ShieldRule[]) {
    this.ruleEngine.loadRules(rules);
  }
}
