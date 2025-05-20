import { Request } from "express";
import { ShieldRule, RuleType, ActionType, CookieOptions } from "./types/ShieldTypes";

export class RuleEngine {
  private rules: ShieldRule[];

  constructor(rules: ShieldRule[] = []) {
    this.rules = this.sortRulesByPriority(rules);
  }

  private sortRulesByPriority(rules: ShieldRule[]): ShieldRule[] {
    return [...rules].sort((a, b) => b.priority - a.priority);
  }

  public loadRules(rules: ShieldRule[]) {
    this.rules = this.sortRulesByPriority(rules);
  }

  public getCSPDirectives(nonce: string): string {
    type CSPDirectives = {
      [key: string]: string[];
    };

    const defaultDirectives: CSPDirectives = {
      'default-src': ["'self'"],
      'script-src': ["'self'", `'nonce-${nonce}'`],
      'style-src': ["'self'"],
      'img-src': ["'self'", 'data:'],
      'font-src': ["'self'"],
      'connect-src': ["'self'"],
      'frame-ancestors': ["'none'"],
      'form-action': ["'self'"],
      'base-uri': ["'self'"],
      'object-src': ["'none'"]
    };

    const cspRules = this.rules.filter(rule => rule.type === RuleType.CSP);
    
    cspRules.forEach(rule => {
      if (rule.action.type === ActionType.MODIFY) {
        const directive = rule.action.value?.directive;
        const sources = rule.action.value?.sources;
        
        if (directive && Array.isArray(sources)) {
          if (defaultDirectives[directive]) {
            defaultDirectives[directive] = [...defaultDirectives[directive], ...sources];
          } else {
            defaultDirectives[directive] = [...sources];
          }
        }
      }
    });

    return Object.entries(defaultDirectives)
      .map(([directive, sources]) => `${directive} ${Array.isArray(sources) ? sources.join(' ') : "'none'"}`)
      .join('; ');
  }

  public shouldSkipCSRF(req: Request): boolean {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      return true;
    }

    const csrfRules = this.rules.filter(rule => rule.type === RuleType.CSRF);
    return csrfRules.some(rule => {
      if (rule.condition.type === "match_path") {
        return new RegExp(rule.condition.value).test(req.path) && 
               rule.action.type === ActionType.ALLOW;
      }
      return false;
    });
  }

  public validateCSRFToken(token: string | undefined, storedToken: string | undefined): boolean {
    return !!(token && storedToken && token === storedToken);
  }

  public getSecureCookieOptions(options: CookieOptions): CookieOptions {
    const secureOptions: CookieOptions = {
      ...options,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict"
    };

    const cookieRules = this.rules.filter(rule => rule.type === RuleType.COOKIE);
    cookieRules.forEach(rule => {
      if (rule.action.type === ActionType.MODIFY) {
        Object.assign(secureOptions, rule.action.value);
      }
    });

    return secureOptions;
  }

  public async validateRequest(req: Request): Promise<boolean> {
    const requestRules = this.rules.filter(rule => rule.type === RuleType.REQUEST);
    
    for (const rule of requestRules) {
      const matches = await this.evaluateCondition(rule.condition, req);
      if (matches && rule.action.type === ActionType.DENY) {
        return false;
      }
    }

    return true;
  }

  public validateIP(ip: string): boolean {
    const ipRules = this.rules.filter(rule => rule.type === RuleType.IP);
    
    for (const rule of ipRules) {
      if (rule.condition.type === "match_ip") {
        const matches = this.matchIP(ip, rule.condition.value);
        if (matches && rule.action.type === ActionType.DENY) {
          return false;
        }
      }
    }

    return true;
  }

  private matchIP(ip: string, pattern: string): boolean {
    // Support for CIDR notation and IP ranges
    if (pattern.includes('/') || pattern.includes('-')) {
      return this.isIPInRange(ip, pattern);
    }
    return ip === pattern;
  }

  private isIPInRange(ip: string, range: string): boolean {
    // Implementation would use ip-range-check or similar library
    return false; // Placeholder
  }

  public getSecurityHeaders(req: Request): Record<string, string> {
    const headers: Record<string, string> = {
      'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=()',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cross-Origin-Opener-Policy': 'same-origin'
    };

    if (req.path.includes('/logout')) {
      headers['Clear-Site-Data'] = '"cache", "cookies", "storage"';
    }

    const headerRules = this.rules.filter(rule => rule.type === RuleType.HEADER);
    headerRules.forEach(rule => {
      if (rule.action.type === ActionType.ADD_HEADER) {
        headers[rule.action.value.name] = rule.action.value.value;
      } else if (rule.action.type === ActionType.REMOVE_HEADER) {
        delete headers[rule.action.value];
      }
    });

    return headers;
  }

  private async evaluateCondition(condition: any, req: Request): Promise<boolean> {
    switch (condition.type) {
      case "match_path":
        return new RegExp(condition.value).test(req.path);
      case "match_method":
        return condition.value === req.method;
      case "match_header":
        return req.headers[condition.value.name] === condition.value.value;
      case "custom":
        return await condition.value(req);
      default:
        return false;
    }
  }
}
