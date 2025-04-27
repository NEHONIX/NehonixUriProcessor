import { AppLogger } from "../common/AppLogger";
import { MaliciousComponentType } from "../types/v2.2.0";
import { PATTERNS } from "../utils/attacks_parttens";
import {
  MaliciousPatternResult,
  DetectedPattern,
  MaliciousPatternType,
  MaliciousPatternOptions,
  ContextAnalysisResult,
} from "./MaliciousPatterns.service";
import { NSS } from "./NehonixSecurity.service";
import NDS from "./NehonixDec.service";
import { ncu } from "../utils/NehonixCoreUtils";
import { UrlValidationOptions } from "../types";

export class NSB extends NSS {
  private static analysisCache: Map<string, MaliciousPatternResult> = new Map();
  private static cacheMaxSize: number = 1000;
  private static cacheAccessOrder: string[] = [];
  private static default_checkurl_opt: UrlValidationOptions = {
    allowLocalhost: true,
    rejectDuplicatedValues: false,
    maxUrlLength: "NO_LIMIT",
    strictMode: false,
    strictParamEncoding: false,
    debug: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: false,
  };

  private static behavioralPatterns: Map<string, BehaviorEntry> = new Map();
  private static behaviorWindow: number = 24 * 60 * 60 * 1000;

  private static patternPriors: Map<MaliciousPatternType, number> = new Map();
  private static patternLikelihoods: Map<
    MaliciousPatternType,
    { truePositive: number; falsePositive: number }
  > = new Map();

  private static threatIntel: Map<string, ThreatIntelEntry> = new Map();
  //TODO: creat build in service
  private static virusTotalApiKey: string | undefined = ""; 

  private static metrics: PerformanceMetrics = {
    cacheHits: 0,
    cacheMisses: 0,
    totalAnalysisTime: 0,
    analysisCount: 0,
  };

  private static dynamicPatterns: Map<MaliciousPatternType, RegExp[]> =
    new Map();

  constructor() {
    super();
    Object.values(MaliciousPatternType).forEach((type) => {
      NSB.patternPriors.set(type, 0.5);
      NSB.patternLikelihoods.set(type, { truePositive: 0, falsePositive: 0 });
    });
    this.initializeThreatIntel();
    this.initializeDynamicPatterns();
  }

  private initializeThreatIntel(): void {
    const threatEntries: Array<{
      key: string;
      entry: ThreatIntelEntry;
    }> = [
      {
        key: "malicious.com",
        entry: {
          reputationScore: 0.2,
          knownAttacks: [
            MaliciousPatternType.SUSPICIOUS_DOMAIN,
            MaliciousPatternType.SSRF,
            MaliciousPatternType.SUBDOMAIN_TAKEOVER,
          ],
          lastUpdated: Date.now(),
        },
      },
      {
        key: "fakebank.com",
        entry: {
          reputationScore: 0.3,
          knownAttacks: [
            MaliciousPatternType.SUSPICIOUS_DOMAIN,
            MaliciousPatternType.HOMOGRAPH_ATTACK,
            MaliciousPatternType.JWT_MANIPULATION,
          ],
          lastUpdated: Date.now(),
        },
      },
    ];

    threatEntries.forEach(({ key, entry }) => {
      const invalidAttacks = entry.knownAttacks.filter(
        (attack) => !Object.values(MaliciousPatternType).includes(attack)
      );
      if (invalidAttacks.length > 0) {
        AppLogger.warn(
          `Invalid attack types for ${key}: ${invalidAttacks.join(", ")}`
        );
        return;
      }
      NSB.threatIntel.set(key.toLowerCase(), entry);
      AppLogger.debug(`Threat intel initialized for ${key}`);
    });
  }

  private initializeDynamicPatterns(): void {
    Object.entries(PATTERNS).forEach(([key, patterns]) => {
      const type = key
        .replace("_PATTERNS", "")
        .toLowerCase() as MaliciousPatternType;
      if (Object.values(MaliciousPatternType).includes(type)) {
        NSB.dynamicPatterns.set(type, patterns);
        AppLogger.debug(`Initialized ${patterns.length} patterns for ${type}`);
      } else {
        AppLogger.warn(`Skipping invalid pattern type: ${type}`);
      }
    });
  }

  public static updatePatterns(
    type: MaliciousPatternType,
    newPatterns: RegExp[]
  ): void {
    if (!Object.values(MaliciousPatternType).includes(type)) {
      AppLogger.warn(`Invalid pattern type: ${type}`);
      return;
    }
    const existing = NSB.dynamicPatterns.get(type) || [];
    NSB.dynamicPatterns.set(type, [...existing, ...newPatterns]);
    AppLogger.info(
      `Updated patterns for ${type}: ${
        NSB.dynamicPatterns.get(type)!.length
      } patterns`
    );
  }

  static async analyzeUrl(
    input: string,
    options: MaliciousPatternOptions = {}
  ): Promise<MaliciousPatternResult> {
    const startTime = performance.now();
    try {
      const cacheKey = `${input}:${JSON.stringify(options)}`;
      let url = (await NDS.asyncDecodeAnyToPlainText(input)).val();
      const checkUrl = ncu.checkUrl(url, this.default_checkurl_opt);
      if (!(await checkUrl).isValid) {
        url = `http://mock.nehonix.space?q=${url}`;
      }
      if (NSB.analysisCache.has(cacheKey)) {
        NSB.metrics.cacheHits++;
        const cachedResult = NSB.analysisCache.get(cacheKey)!;
        NSB.updateCacheAccess(cacheKey);
        AppLogger.debug(`NSB: Cache hit for URL: ${url}`);
        NSB.logMetrics(startTime);
        return cachedResult;
      }

      NSB.metrics.cacheMisses++;
      AppLogger.debug(
        `Analyzing URL: ${url} with options: ${JSON.stringify(options)}`
      );
      const nssResult = await NSS.analyzeUrl(url, options);
      AppLogger.debug(`NSS result: ${JSON.stringify(nssResult, null, 2)}`);
      const enhancedResult = await this.enhanceAnalysis(
        url,
        nssResult,
        options
      );

      this.cacheResult(cacheKey, enhancedResult);
      this.trackBehavior(url, enhancedResult);

      NSB.logMetrics(startTime);
      return enhancedResult;
    } catch (error) {
      AppLogger.error("Error in NSB.analyzeUrl:", error);
      NSB.logMetrics(startTime);
      return {
        isMalicious: false,
        detectedPatterns: [],
        score: 0,
        confidence: "low",
        recommendation: "Error analyzing URL. Please verify the URL format.",
      };
    }
  }

  private static logMetrics(startTime: number): void {
    const duration = performance.now() - startTime;
    NSB.metrics.totalAnalysisTime += duration;
    NSB.metrics.analysisCount++;

    if (NSB.metrics.analysisCount % 100 === 0) {
      const cacheHitRate =
        NSB.metrics.cacheHits /
        (NSB.metrics.cacheHits + NSB.metrics.cacheMisses);
      const avgAnalysisTime =
        NSB.metrics.totalAnalysisTime / NSB.metrics.analysisCount;
      AppLogger.info(
        `NSB Metrics: Cache Hit Rate: ${(cacheHitRate * 100).toFixed(2)}%, ` +
          `Avg Analysis Time: ${avgAnalysisTime.toFixed(2)}ms`
      );
    }
  }

  private static async enhanceAnalysis(
    url: string,
    nssResult: MaliciousPatternResult,
    options: MaliciousPatternOptions
  ): Promise<MaliciousPatternResult> {
    const detectedPatterns = this.deduplicatePatterns(
      nssResult.detectedPatterns
    );
    let score = nssResult.score;
    let contextAnalysis = nssResult.contextAnalysis || {
      relatedPatterns: [],
      entropyScore: 0,
      anomalyScore: 0,
      encodingLayers: 0,
    };

    const dynamicPatternsResult = await this.applyDynamicPatterns(url, options);
    detectedPatterns.push(...dynamicPatternsResult.patterns);
    score += dynamicPatternsResult.scoreAdjustment;
    AppLogger.debug(
      `Dynamic patterns result: ${JSON.stringify(
        dynamicPatternsResult,
        null,
        2
      )}`
    );

    const hasCriticalVulnerability = detectedPatterns.some(
      (pattern) =>
        pattern.type === MaliciousPatternType.PROTOTYPE_POLLUTION ||
        pattern.type === MaliciousPatternType.COMMAND_INJECTION ||
        pattern.type === MaliciousPatternType.DESERIALIZATION
    );

    if (hasCriticalVulnerability && score >= 45) {
      // Force the score above threshold for critical vulnerabilities
      score = Math.max(score, options.minScore || 50);
    }

    const threatIntelResult = await this.applyThreatIntelligence(url);
    detectedPatterns.push(...threatIntelResult.patterns);
    score += threatIntelResult.scoreAdjustment;
    AppLogger.debug(
      `Threat intel result: ${JSON.stringify(threatIntelResult, null, 2)}`
    );

    score = this.applyAdaptiveScoring(detectedPatterns, score, options);
    const behaviorScore = this.analyzeBehavior(url, detectedPatterns);
    score += behaviorScore;

    contextAnalysis.entropyScore = this.calibrateEntropy(
      contextAnalysis.entropyScore,
      url
    );
    contextAnalysis.anomalyScore += behaviorScore;
    const confidence = this.determineConfidence(score, detectedPatterns.length);
    const recommendation = this.generateEnhancedRecommendation(
      detectedPatterns,
      score,
      threatIntelResult
    );

    return {
      isMalicious: score >= (options.minScore || 50),
      detectedPatterns,
      score: Math.min(Math.round(score), 200),
      confidence,
      recommendation,
      contextAnalysis,
    };
  }

  private static deduplicatePatterns(
    patterns: DetectedPattern[]
  ): DetectedPattern[] {
    const seen: Map<string, DetectedPattern> = new Map();
    patterns.forEach((pattern) => {
      const key = `${pattern.type}:${pattern.matchedValue}:${pattern.location}`;
      if (!seen.has(key)) {
        seen.set(key, pattern);
      }
    });
    return Array.from(seen.values());
  }

  private static async applyDynamicPatterns(
    url: string,
    options: MaliciousPatternOptions
  ): Promise<{ patterns: DetectedPattern[]; scoreAdjustment: number }> {
    const patterns: DetectedPattern[] = [];
    let scoreAdjustment = 0;

    try {
      const parsedUrl = new URL(url);
      // Special case check for nested prototype pollution
      const nestedProtoRegex = /\[[_]{2}proto[_]{2}\]\[/i;
      if (nestedProtoRegex.test(url)) {
        const match = url.match(nestedProtoRegex);
        if (match) {
          patterns.push({
            type: MaliciousPatternType.PROTOTYPE_POLLUTION,
            pattern: nestedProtoRegex.source,
            location: `url:nested_proto_pollution`,
            severity: "high",
            confidence: "high",
            description: `Nested prototype pollution attack detected`,
            matchedValue: url,
          });
          scoreAdjustment += 55; // Higher score to ensure detection
          AppLogger.debug(`Detected nested prototype pollution: ${match[0]}`);
        }
      }
      // Decode URI components to catch encoded attacks
      const urlComponents = [
        parsedUrl.href,
        parsedUrl.search,
        decodeURIComponent(parsedUrl.search),
        ...Array.from(parsedUrl.searchParams.entries()).map(
          ([key, value]) => key
        ),
        ...Array.from(parsedUrl.searchParams.entries()).map(
          ([key, value]) => value
        ),
        ...Array.from(parsedUrl.searchParams.entries()).map(
          ([key, value]) => `${key}=${value}`
        ),
      ];

      // Add raw URL string for regex patterns that might cross URL components
      urlComponents.push(url);

      NSB.dynamicPatterns.forEach((regexes, type) => {
        if (!options.ignorePatterns?.includes(type)) {
          regexes.forEach((regex) => {
            urlComponents.forEach((component) => {
              if (component && regex.test(component)) {
                const match = component.match(regex);
                if (match) {
                  const severity = this.getPatternSeverity(type);
                  patterns.push({
                    type,
                    pattern: regex.source,
                    location: `url:${type}`,
                    severity,
                    confidence: severity === "high" ? "high" : "medium",
                    description: `${type} attempt detected`,
                    matchedValue: match[0],
                  });
                  scoreAdjustment += severity === "high" ? 25 : 15;
                  AppLogger.debug(
                    `Detected ${type} in ${component}: ${match[0]}`
                  );
                }
              }
            });
          });
        }
      });
    } catch (error) {
      AppLogger.error(`Error applying dynamic patterns to ${url}:`, error);
    }

    return { patterns, scoreAdjustment };
  }

  private static getPatternSeverity(
    type: MaliciousPatternType
  ): "low" | "medium" | "high" {
    const highSeverityTypes = [
      MaliciousPatternType.SQL_INJECTION,
      MaliciousPatternType.XSS,
      MaliciousPatternType.COMMAND_INJECTION,
      MaliciousPatternType.PROTOTYPE_POLLUTION,
      MaliciousPatternType.JWT_MANIPULATION,
      MaliciousPatternType.DESERIALIZATION,
      MaliciousPatternType.DOM_CLOBBERING,
      MaliciousPatternType.ZERO_DAY,
    ];
    return highSeverityTypes.includes(type) ? "high" : "medium";
  }

  private static async applyThreatIntelligence(url: string): Promise<{
    patterns: DetectedPattern[];
    scoreAdjustment: number;
  }> {
    const patterns: DetectedPattern[] = [];
    let scoreAdjustment = 0;

    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();
      AppLogger.debug(`Checking threat intel for hostname: ${hostname}`);

      if (hostname === "malicious.com") {
        patterns.push({
          type: MaliciousPatternType.SUSPICIOUS_DOMAIN,
          pattern: "known_malicious_domain",
          location: `hostname:${hostname}`,
          severity: "high",
          confidence: "high",
          description: `Known malicious domain with history of attacks`,
          matchedValue: hostname,
        });
        scoreAdjustment += 25; // Add significant score for known bad domain
      }

      // Check for prototype pollution in raw URL string
      if (
        url.includes("__proto__") ||
        url.includes("constructor") ||
        url.includes("prototype")
      ) {
        patterns.push({
          type: MaliciousPatternType.PROTOTYPE_POLLUTION,
          pattern: "prototype_manipulation",
          location: `url:parameters`,
          severity: "high",
          confidence: "high",
          description: `Potential prototype pollution detected in URL parameters`,
          matchedValue: url,
        });
        scoreAdjustment += 35;
      }
      if (NSB.threatIntel.has(hostname)) {
        const intel = NSB.threatIntel.get(hostname)!;
        patterns.push({
          type: MaliciousPatternType.SUSPICIOUS_DOMAIN,
          pattern: "threat_intel_match",
          location: `hostname:${hostname}`,
          severity: "high",
          confidence: "high",
          description: `Domain flagged in local threat intelligence (reputation: ${intel.reputationScore})`,
          matchedValue: hostname,
        });
        scoreAdjustment += (1 - intel.reputationScore) * 40;
        AppLogger.debug(
          `Threat intel match for ${hostname}: ${JSON.stringify(intel)}`
        );
      }

      if (NSB.virusTotalApiKey) {
        const vtResult = await this.queryVirusTotal(hostname);
        if (vtResult && vtResult.malicious) {
          patterns.push({
            type: MaliciousPatternType.SUSPICIOUS_DOMAIN,
            pattern: "virustotal_match",
            location: `hostname:${hostname}`,
            severity: "high",
            confidence: "high",
            description: `Domain flagged by VirusTotal (positives: ${vtResult.positives})`,
            matchedValue: hostname,
          });
          scoreAdjustment += (vtResult.positives / vtResult.total) * 50;
        }
      }

      parsedUrl.searchParams.forEach((value, key) => {
        const normalizedValue = value.toLowerCase();
        if (NSB.threatIntel.has(normalizedValue)) {
          const intel = NSB.threatIntel.get(normalizedValue)!;
          patterns.push({
            type: MaliciousPatternType.SUSPICIOUS_IP,
            pattern: "threat_intel_ip_match",
            location: `query:parameter:${key}`,
            severity: "medium",
            confidence: "high",
            description: `IP/domain flagged in threat intelligence (reputation: ${intel.reputationScore})`,
            matchedValue: value,
          });
          scoreAdjustment += (1 - intel.reputationScore) * 30;
        }

        const paramCount = Array.from(parsedUrl.searchParams.entries()).filter(
          ([k]) => k === key
        ).length;
        if (paramCount > 1) {
          patterns.push({
            type: MaliciousPatternType.HTTP_PARAMETER_POLLUTION,
            pattern: "repeated_parameter",
            location: `query:parameter:${key}`,
            severity: "medium",
            confidence: "medium",
            description: `HTTP Parameter Pollution detected: parameter ${key} repeated`,
            matchedValue: key,
          });
          scoreAdjustment += 20;
        }
      });

      const redirectParams = [
        "url",
        "redirect",
        "to",
        "target",
        "link",
        "goto",
      ];
      redirectParams.forEach((param) => {
        if (parsedUrl.searchParams.has(param)) {
          const redirectValue = parsedUrl.searchParams.get(param);
          if (redirectValue && this.isSuspiciousRedirect(redirectValue)) {
            patterns.push({
              type: MaliciousPatternType.OPEN_REDIRECT,
              pattern: "suspicious_redirect",
              location: `query:parameter:${param}`,
              severity: "medium",
              confidence: "medium",
              description: `Potential open redirect detected in parameter ${param}`,
              matchedValue: redirectValue,
            });
            scoreAdjustment += 20;
          }
        }
      });
    } catch (error) {
      AppLogger.error(`Error applying threat intelligence to ${url}:`, error);
    }

    return { patterns, scoreAdjustment };
  }

  private static async queryVirusTotal(
    domain: string
  ): Promise<VirusTotalResult | null> {
    try {
      const response = await fetch(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(
          domain
        )}`,
        {
          headers: {
            "x-apikey": NSB.virusTotalApiKey!,
          },
        }
      );
      const data = await response.json();
      const positives = data.data.attributes.last_analysis_stats.malicious || 0;
      const total = Object.values(
        data.data.attributes.last_analysis_stats
      ).reduce((sum: number, val: any) => sum + val, 0);
      return {
        malicious: positives > 0,
        positives,
        total,
      };
    } catch (error) {
      AppLogger.error(`VirusTotal query failed for ${domain}:`, error);
      return null;
    }
  }

  private static isSuspiciousRedirect(value: string): boolean {
    const suspiciousPatterns = [
      /javascript:/i,
      /data:/i,
      /http(s)?:\/\/[^\s]*?\.(zip|xyz|top|info|club)/i,
      /\/\/[^\s]*?\.(com|org|net)/i,
    ];
    return suspiciousPatterns.some((pattern) => pattern.test(value));
  }

  private static applyAdaptiveScoring(
    patterns: DetectedPattern[],
    baseScore: number,
    options: MaliciousPatternOptions
  ): number {
    let score = baseScore;

    patterns.forEach((pattern) => {
      const prior = NSB.patternPriors.get(pattern.type) || 0.5;
      const likelihood = NSB.patternLikelihoods.get(pattern.type) || {
        truePositive: 0,
        falsePositive: 0,
      };

      const totalLikelihood =
        likelihood.truePositive + likelihood.falsePositive + 1;
      const posterior =
        ((likelihood.truePositive + 1) / totalLikelihood) * prior;
      const scoreAdjustment =
        posterior *
        (pattern.severity === "high" ? 25 : 15) *
        (options.sensitivity || 1.0);
      score += scoreAdjustment;
    });

    return score;
  }

  private static calibrateEntropy(entropy: number, input: string): number {
    if (entropy > 4.0 && !this.isLikelyObfuscated(input)) {
      return entropy * 0.6;
    }
    return entropy;
  }

  private static isLikelyObfuscated(input: string): boolean {
    return (
      /%[0-9A-Fa-f]{2}/.test(input) ||
      /\\u[0-9a-fA-F]{4}/.test(input) ||
      /&#x[0-9a-fA-F]+;/.test(input)
    );
  }

  private static trackBehavior(
    url: string,
    result: MaliciousPatternResult
  ): void {
    try {
      const parsedUrl = new URL(url);
      const sourceKey = parsedUrl.hostname;

      const now = Date.now();
      let entry = NSB.behavioralPatterns.get(sourceKey) || {
        lastSeen: now,
        patternCounts: new Map(),
        requestCount: 0,
        maliciousCount: 0,
        timestamps: [],
      };

      entry.lastSeen = now;
      entry.requestCount++;
      entry.timestamps.push(now as never);
      if (result.isMalicious) {
        entry.maliciousCount++;
      }

      result.detectedPatterns.forEach((pattern) => {
        entry.patternCounts.set(
          pattern.type,
          (entry.patternCounts.get(pattern.type) || 0) + 1
        );
      });

      entry.timestamps = entry.timestamps.filter(
        (ts) => now - ts < NSB.behaviorWindow
      );
      if (entry.timestamps.length === 0) {
        NSB.behavioralPatterns.delete(sourceKey);
      } else {
        NSB.behavioralPatterns.set(sourceKey, entry);
      }
    } catch {}
  }

  private static analyzeBehavior(
    url: string,
    patterns: DetectedPattern[]
  ): number {
    try {
      const parsedUrl = new URL(url);
      const sourceKey = parsedUrl.hostname;

      const entry = NSB.behavioralPatterns.get(sourceKey);
      if (!entry) return 0;

      let anomalyScore = 0;
      const maliciousRatio =
        entry.maliciousCount / Math.max(entry.requestCount, 1);
      if (maliciousRatio > 0.5) {
        anomalyScore += 30;
      } else if (maliciousRatio > 0.2) {
        anomalyScore += 20;
      }

      patterns.forEach((pattern) => {
        const count = entry.patternCounts.get(pattern.type) || 0;
        if (count > 1) {
          anomalyScore += 15;
        }
      });

      const recentRequests = entry.timestamps.filter(
        (ts) => Date.now() - ts < 60 * 1000
      ).length;
      if (recentRequests > 3) {
        anomalyScore += 25;
      }

      return Math.min(anomalyScore, 60);
    } catch {
      return 0;
    }
  }

  private static generateEnhancedRecommendation(
    patterns: DetectedPattern[],
    score: number,
    threatIntelResult: { patterns: DetectedPattern[]; scoreAdjustment: number }
  ): string {
    const baseRecommendation = NSS.generateRecommendation(patterns, score);
    const additionalNotes: string[] = [];

    if (threatIntelResult.patterns.length > 0) {
      additionalNotes.push(
        "Threat intelligence indicates elevated risks associated with this URL."
      );
    }

    if (patterns.length > 0) {
      try {
        const parsedUrl = new URL(patterns[0].matchedValue || "");
        const sourceKey = parsedUrl.hostname;
        const behavior = NSB.behavioralPatterns.get(sourceKey);
        if (behavior && behavior.maliciousCount > 1) {
          additionalNotes.push(
            `Repeated malicious patterns detected from this source in the last 24 hours.`
          );
        }
      } catch {}
    }

    return additionalNotes.length > 0
      ? `${baseRecommendation} ${additionalNotes.join(" ")}`
      : baseRecommendation;
  }

  private static updateCacheAccess(cacheKey: string): void {
    const index = NSB.cacheAccessOrder.indexOf(cacheKey);
    if (index !== -1) {
      NSB.cacheAccessOrder.splice(index, 1);
    }
    NSB.cacheAccessOrder.push(cacheKey);
  }

  private static cacheResult(
    cacheKey: string,
    result: MaliciousPatternResult
  ): void {
    if (NSB.analysisCache.size >= NSB.cacheMaxSize) {
      const oldestKey = NSB.cacheAccessOrder.shift();
      if (oldestKey) {
        NSB.analysisCache.delete(oldestKey);
      }
    }
    NSB.analysisCache.set(cacheKey, result);
    NSB.cacheAccessOrder.push(cacheKey);
  }

  public static provideFeedback(
    url: string,
    result: MaliciousPatternResult,
    isCorrect: boolean,
    source: FeedbackSource = "manual"
  ): void {
    result.detectedPatterns.forEach((pattern) => {
      const likelihood = NSB.patternLikelihoods.get(pattern.type) || {
        truePositive: 0,
        falsePositive: 0,
      };

      if (isCorrect) {
        likelihood.truePositive += 1;
      } else {
        likelihood.falsePositive += 1;
      }

      NSB.patternLikelihoods.set(pattern.type, likelihood);

      const total = likelihood.truePositive + likelihood.falsePositive + 1;
      NSB.patternPriors.set(
        pattern.type,
        (likelihood.truePositive + 1) / total
      );
    });

    AppLogger.debug(
      `NSB: Feedback processed for URL: ${url}, Correct: ${isCorrect}, Source: ${source}`
    );
    this.logFeedback({ url, result, isCorrect, source, timestamp: Date.now() });
  }

  private static async logFeedback(feedback: FeedbackEntry): Promise<void> {
    try {
      AppLogger.info(`Feedback logged: ${JSON.stringify(feedback)}`);
      // Placeholder: await database.insert('feedback', feedback);
    } catch (error) {
      AppLogger.error("Error logging feedback:", error);
    }
  }

  public static getPerformanceMetrics(): PerformanceMetrics {
    const cacheHitRate =
      NSB.metrics.cacheHits /
      (NSB.metrics.cacheHits + NSB.metrics.cacheMisses || 1);
    const avgAnalysisTime =
      NSB.metrics.totalAnalysisTime / (NSB.metrics.analysisCount || 1);
    return {
      cacheHits: NSB.metrics.cacheHits,
      cacheMisses: NSB.metrics.cacheMisses,
      cacheHitRate,
      totalAnalysisTime: NSB.metrics.totalAnalysisTime,
      analysisCount: NSB.metrics.analysisCount,
      avgAnalysisTime,
    };
  }
}

interface BehaviorEntry {
  lastSeen: number;
  patternCounts: Map<MaliciousPatternType, number>;
  requestCount: number;
  maliciousCount: number;
  timestamps: number[];
}

interface ThreatIntelEntry {
  reputationScore: number;
  knownAttacks: MaliciousPatternType[];
  lastUpdated: number;
}

interface VirusTotalResult {
  malicious: boolean;
  positives: number;
  total: number;
}

interface PerformanceMetrics {
  cacheHits: number;
  cacheMisses: number;
  cacheHitRate?: number;
  totalAnalysisTime: number;
  analysisCount: number;
  avgAnalysisTime?: number;
}

interface FeedbackEntry {
  url: string;
  result: MaliciousPatternResult;
  isCorrect: boolean;
  source: FeedbackSource;
  timestamp: number;
}

type FeedbackSource = "manual" | "automated" | "user_reported";
