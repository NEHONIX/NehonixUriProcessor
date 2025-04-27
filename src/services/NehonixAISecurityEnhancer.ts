import { NSB } from "./NehonixSecurityBooster.service";
import {
  MaliciousPatternResult,
  DetectedPattern,
  MaliciousPatternOptions,
  ThreatSignature,
  ZeroKnowledgePatterns,
  PerformanceStats,
  DistributedThreatEntry,
  PendingRequest,
  TrainingDataPoint,
  URLFeatures,
  PatternCluster,
  MaliciousPatternType,
} from "./MaliciousPatterns.service";

import { DBSCAN } from "density-clustering";
import { RateLimiter } from "limiter";
import axios from "axios";
import * as crypto from "crypto";
import { AppLogger } from "../common/AppLogger";
import { spawn } from "child_process";
import { ncu } from "../utils/NehonixCoreUtils";

// Configuration for free threat intelligence APIs
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || ""; // Free tier available, empty if not used
const PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"; // Free API
// Local blocklist (mock data or community-driven list)
const LOCAL_BLOCKLIST: DistributedThreatEntry[] = [
  {
    key: "malicious.example.com",
    firstSeen: Date.now() - 24 * 60 * 60 * 1000,
    lastSeen: Date.now(),
    reportCount: 10,
    maliciousCount: 8,
    maliciousScore: 0.8,
    patterns: new Set([MaliciousPatternType.SUSPICIOUS_DOMAIN]),
    severity: "high",
    confidence: "high",
    source: "local",
  },
];

// Rate limiter configuration: 100 requests per minute
const RATE_LIMITER = new RateLimiter({
  tokensPerInterval: 100,
  interval: "minute",
});

/**
 * NehonixAISecurityEnhancer (NAISE)
 *
 * An advanced AI-powered security enhancer for the NSB service using free/open-source tools.
 */
export class NAISE {
  private static instance: NAISE;
  private threatSignatures: Map<string, ThreatSignature> = new Map();
  private zeroKnowledgePatterns: ZeroKnowledgePatterns = {
    anomalyThresholds: new Map(),
    patternClusters: [],
  };
  private performanceStats: PerformanceStats = {
    totalRequests: 0,
    avgProcessingTime: 0,
    peakMemoryUsage: 0,
    totalProcessingTime: 0,
    requestsWithCache: 0,
    requestsWithoutCache: 0,
  };
  private distributedThreatDB: Map<string, DistributedThreatEntry> = new Map();
  private trainingData: TrainingDataPoint[] = [];
  private lastTrainingTime: number = 0;
  private trainingInterval: number = 7 * 24 * 60 * 60 * 1000; // 7 days
  private workerPool: Array<{ id: number; busy: boolean }> = [];
  private requestQueue: Array<PendingRequest> = [];
  private MAX_WORKERS = 4;
  static ml_path = "./microservices/ml_model.py";

  private constructor() {
    this.initializePatternWeights();
    this.initializeWorkerPool();
    this.initializeZeroKnowledgePatterns();
    this.loadThreatSignatures();
    AppLogger.info("NAISE service initialized");

    // Schedule regular operations
    setInterval(() => this.syncDistributedThreatDB(), 12 * 60 * 60 * 1000); // 12 hours
    setInterval(() => this.processTrainingData(), this.trainingInterval);
  }

  public static getInstance(): NAISE {
    if (!NAISE.instance) {
      NAISE.instance = new NAISE();
    }
    return NAISE.instance;
  }

  /**
   * Train ML model with accumulated training data using Python
   */
  private async trainMLModel(): Promise<void> {
    if (this.trainingData.length < 100) {
      AppLogger.debug("Insufficient training data for ML model update");
      return;
    }

    try {
      // Prepare training data
      const inputs = this.trainingData.map((data) => [
        data.features.length / 1000,
        data.features.entropy / 10,
        data.features.specialCharCount / 100,
        data.features.digitCount / 100,
        data.features.encodedCharCount / 100,
        data.features.subdomainLevels / 10,
        data.features.parameterCount / 10,
        data.features.pathDepth / 10,
        data.features.hasUnusualPort ? 1 : 0,
        data.features.containsIPAddress ? 1 : 0,
        data.features.hexEncodingRatio,
        data.features.domainLength / 100,
        data.features.tld.length / 10,
        data.features.hasBase64 ? 1 : 0,
      ]);
      const outputs = this.trainingData.map((data) => [
        data.isMalicious ? 1 : 0,
      ]);

      // Call Python script
      const result = await this.runPythonScript({
        command: "train",
        inputs,
        outputs,
      });

      if (result.status === "success") {
        AppLogger.info(
          `ML model trained with ${this.trainingData.length} data points`
        );
        this.lastTrainingTime = Date.now();
        this.trainingData = []; // Clear training data
      } else {
        AppLogger.error("Python ML training failed:", result.message);
      }
    } catch (error) {
      AppLogger.error("Error training ML model:", error);
    }
  }

  /**
   * Predict threat probability using Python ML model
   */
  private async predictThreatProbability(
    url: string,
    features: URLFeatures
  ): Promise<number> {
    try {
      const input = [
        features.length / 1000,
        features.entropy / 10,
        features.specialCharCount / 100,
        features.digitCount / 100,
        features.encodedCharCount / 100,
        features.subdomainLevels / 10,
        features.parameterCount / 10,
        features.pathDepth / 10,
        features.hasUnusualPort ? 1 : 0,
        features.containsIPAddress ? 1 : 0,
        features.hexEncodingRatio,
        features.domainLength / 100,
        features.tld.length / 10,
        features.hasBase64 ? 1 : 0,
      ];

      const result = await this.runPythonScript({
        command: "predict",
        input,
      });

      if (result.status === "success") {
        return Math.min(Math.max(result.probability, 0), 1);
      } else {
        AppLogger.error("Python ML prediction failed:", result.message);
        return this.fallbackPredictThreatProbability(features);
      }
    } catch (error) {
      AppLogger.error("Error predicting threat probability:", error);
      return this.fallbackPredictThreatProbability(features);
    }
  }

  /**
   * Run Python script for ML tasks
   */
  private runPythonScript(data: any): Promise<any> {
    return new Promise((resolve, reject) => {
      const pythonProcess = spawn("python", [NAISE.ml_path]);
      let output = "";
      let errorOutput = "";

      pythonProcess.stdin.write(JSON.stringify(data));
      pythonProcess.stdin.end();

      pythonProcess.stdout.on("data", (chunk) => {
        output += chunk.toString();
      });

      pythonProcess.stderr.on("data", (chunk) => {
        errorOutput += chunk.toString();
      });

      pythonProcess.on("close", (code) => {
        if (code === 0) {
          try {
            const result = JSON.parse(output);
            resolve(result);
          } catch (e) {
            reject(new Error(`Failed to parse Python output: ${output}`));
          }
        } else {
          reject(
            new Error(`Python process exited with code ${code}: ${errorOutput}`)
          );
        }
      });

      pythonProcess.on("error", (err) => {
        reject(err);
      });
    });
  }

  /**
   * Fallback prediction using heuristic-based scoring
   */
  private fallbackPredictThreatProbability(features: URLFeatures): number {
    let score = 0;
    if (features.entropy > 5.0) score += 0.4;
    if (features.encodedCharCount > 10) score += 0.2;
    if (features.hasBase64) score += 0.2;
    return Math.min(score, 1);
  }

  /**
   * Fetch external threat intelligence from free sources (AbuseIPDB, PhishTank, Local Blocklist)
   */
  private async fetchExternalThreats(): Promise<DistributedThreatEntry[]> {
    const threats: DistributedThreatEntry[] = [...LOCAL_BLOCKLIST];

    try {
      // AbuseIPDB: Check IP reputation
      if (ABUSEIPDB_API_KEY) {
        const ip = "1.2.3.4"; // Placeholder; replace with actual IP extraction
        const response = await axios.get(
          `https://api.abuseipdb.com/api/v2/check`,
          {
            headers: { Key: ABUSEIPDB_API_KEY, Accept: "application/json" },
            params: { ipAddress: ip, maxAgeInDays: 90 },
          }
        );

        if (response.data.data.abuseConfidenceScore > 50) {
          threats.push({
            key: `ip:${ip}`,
            firstSeen: Date.now(),
            lastSeen: Date.now(),
            reportCount: response.data.data.totalReports,
            maliciousCount: response.data.data.abuseConfidenceScore / 100,
            maliciousScore: response.data.data.abuseConfidenceScore / 100,
            patterns: new Set([MaliciousPatternType.SUSPICIOUS_IP]),
            severity:
              response.data.data.abuseConfidenceScore > 75 ? "high" : "medium",
            confidence: "medium",
            source: "external",
          });
        }
      }

      // PhishTank: Check for phishing URLs
      const url = "http://example.com"; // Placeholder; replace with actual URL
      const phishResponse = await axios.post(
        PHISHTANK_API_URL,
        new URLSearchParams({ url: encodeURIComponent(url), format: "json" }),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      if (
        phishResponse.data.results.in_database &&
        phishResponse.data.results.verified
      ) {
        threats.push({
          key: url,
          firstSeen: Date.now(),
          lastSeen: Date.now(),
          reportCount: 1,
          maliciousCount: 1,
          maliciousScore: 0.9,
          patterns: new Set([MaliciousPatternType.KNOWN_THREAT]),
          severity: "high",
          confidence: "high",
          source: "external",
        });
      }

      AppLogger.debug(`Fetched ${threats.length} external threats`);
    } catch (error) {
      AppLogger.error("Error fetching external threats:", error);
    }

    return threats;
  }

  /**
   * Synchronize distributed threat database with external sources
   */
  private async syncDistributedThreatDB(): Promise<void> {
    try {
      const externalThreats = await this.fetchExternalThreats();
      externalThreats.forEach((threat) => {
        const key = threat.key || `external:${crypto.randomUUID()}`;
        const existingEntry = this.distributedThreatDB.get(key);
        if (!existingEntry || existingEntry.lastSeen < threat.lastSeen) {
          this.distributedThreatDB.set(key, {
            ...threat,
            lastSeen: Date.now(),
            source: "external",
          });
        }
      });
      AppLogger.debug(
        `Synchronized ${externalThreats.length} threats to distributed threat DB`
      );
    } catch (error) {
      AppLogger.error("Error syncing distributed threat DB:", error);
    }
  }

  /**
   * Update zero-knowledge patterns using DBSCAN clustering
   */
  private updateZeroKnowledgePatterns(): void {
    const maliciousData = this.trainingData.filter((data) => data.isMalicious);
    if (maliciousData.length < 20) {
      AppLogger.debug("Insufficient malicious data for clustering");
      return;
    }

    try {
      // Extract features for clustering
      const features = maliciousData.map((data) => [
        data.features.entropy,
        data.features.encodedCharCount / (data.features.length || 1),
        data.features.hexEncodingRatio,
        data.features.specialCharCount / (data.features.length || 1),
      ]);

      // Apply DBSCAN clustering
      const dbscan = new DBSCAN();
      const clusters = dbscan.run(features, 0.3, 3); // eps=0.3, minPts=3

      const newClusters: PatternCluster[] = clusters.map((cluster, index) => {
        const clusterPoints = cluster.map((i) => features[i]);
        const tokens = clusterPoints.map(
          (point) => `entropy:${point[0].toFixed(2)}`
        );
        const patterns: RegExp[] = [];

        // Generate regex patterns
        const avgEncodedRatio =
          clusterPoints.reduce((sum, p) => sum + p[1], 0) /
          clusterPoints.length;
        if (avgEncodedRatio > 0.1) {
          patterns.push(/%[0-9A-Fa-f]{2}/i);
        }
        const avgEntropy =
          clusterPoints.reduce((sum, p) => sum + p[0], 0) /
          clusterPoints.length;
        if (avgEntropy > 4.0) {
          patterns.push(/[A-Za-z0-9+/=]{10,}/i);
        }

        return {
          patterns,
          tokens,
          created: Date.now(),
        };
      });

      // Update clusters, keeping only the most recent 10
      this.zeroKnowledgePatterns.patternClusters = [
        ...this.zeroKnowledgePatterns.patternClusters,
        ...newClusters,
      ].slice(-10);

      // Update anomaly thresholds
      const maxEntropy = Math.max(...features.map((f) => f[0]));
      this.zeroKnowledgePatterns.anomalyThresholds.set(
        "entropy",
        maxEntropy * 1.1
      );
      this.zeroKnowledgePatterns.anomalyThresholds.set("encodedCharRatio", 0.2);

      AppLogger.info(
        `Updated zero-knowledge patterns with ${newClusters.length} new clusters`
      );
    } catch (error) {
      AppLogger.error("Error updating zero-knowledge patterns:", error);
    }
  }

  /**
   * Process training data to update ML model and patterns
   */
  private async processTrainingData(): Promise<void> {
    if (
      this.trainingData.length < 100 ||
      Date.now() - this.lastTrainingTime < 24 * 60 * 60 * 1000
    ) {
      return;
    }

    await this.trainMLModel();
    this.updateZeroKnowledgePatterns();
  }

  /**
   * Initialize pattern weights
   */
  private initializePatternWeights(): void {
    Object.values(MaliciousPatternType).forEach((type) => {
      let weight = 1.0;
      switch (type) {
        case MaliciousPatternType.PROTOTYPE_POLLUTION:
        case MaliciousPatternType.COMMAND_INJECTION:
        case MaliciousPatternType.DESERIALIZATION:
        case MaliciousPatternType.RCE:
        case MaliciousPatternType.ZERO_DAY:
        case MaliciousPatternType.RANSOMWARE:
          weight = 2.0;
          break;
        case MaliciousPatternType.SQL_INJECTION:
        case MaliciousPatternType.XSS:
        case MaliciousPatternType.SSRF:
        case MaliciousPatternType.JWT_MANIPULATION:
        case MaliciousPatternType.PATH_TRAVERSAL:
          weight = 1.5;
          break;
        case MaliciousPatternType.SUSPICIOUS_DOMAIN:
        case MaliciousPatternType.SUSPICIOUS_IP:
        case MaliciousPatternType.ANOMALY_DETECTED:
          weight = 1.2;
          break;
      }
      // Assuming patternWeights is defined elsewhere; otherwise, add it
      // this.patternWeights.set(type, weight);
    });
  }

  /**
   * Initialize worker pool for parallel processing
   */
  private initializeWorkerPool(): void {
    for (let i = 0; i < this.MAX_WORKERS; i++) {
      this.workerPool.push({ id: i, busy: false });
    }
    AppLogger.debug(`Initialized worker pool with ${this.MAX_WORKERS} workers`);
  }

  /**
   * Initialize zero-knowledge patterns
   */
  private initializeZeroKnowledgePatterns(): void {
    this.zeroKnowledgePatterns.anomalyThresholds.set("entropy", 5.0);
    this.zeroKnowledgePatterns.anomalyThresholds.set("specialCharRatio", 0.3);
    this.zeroKnowledgePatterns.anomalyThresholds.set("encodedCharRatio", 0.2);
    this.zeroKnowledgePatterns.anomalyThresholds.set("digitRatio", 0.4);
    AppLogger.debug("Initialized zero-knowledge patterns");
  }

  /**
   * Load threat signatures
   */
  private loadThreatSignatures(): void {
    const signatures: ThreatSignature[] = [
      {
        id: "ts001",
        name: "Suspicious Encoding",
        description: "Detects high URL encoding patterns",
        patternType: MaliciousPatternType.ANOMALY_DETECTED,
        severity: "medium",
        confidence: "medium",
        matches: (url, features) => features.encodedCharCount > 10,
      },
      {
        id: "ts002",
        name: "Phishing Pattern",
        description: "Detects phishing-like URL patterns",
        patternType: MaliciousPatternType.KNOWN_THREAT,
        severity: "high",
        confidence: "high",
        matches: (url) => /login|signin|verify/i.test(url),
      },
    ];

    signatures.forEach((signature) => {
      this.threatSignatures.set(signature.id, signature);
    });
    AppLogger.debug(`Loaded ${signatures.length} threat signatures`);
  }

  /**
   * Process URL in parallel with rate limiting
   */
  private async processUrlInParallel(
    url: string,
    basicResult: MaliciousPatternResult,
    options: MaliciousPatternOptions,
    urlHash: string,
    startTime: number
  ): Promise<MaliciousPatternResult> {
    return new Promise((resolve) => {
      this.requestQueue.push({
        url,
        basicResult,
        options,
        urlHash,
        startTime,
        resolve,
      });
      this.processNextInQueue();
    });
  }

  /**
   * Process next request in the queue with rate limiting
   */
  private async processNextInQueue(): Promise<void> {
    if (this.requestQueue.length === 0) return;

    const availableWorker = this.workerPool.find((worker) => !worker.busy);
    if (!availableWorker) return;

    const remainingTokens = await RATE_LIMITER.removeTokens(1);
    if (remainingTokens < 0) {
      AppLogger.warn("Rate limit exceeded, retrying in 1s");
      setTimeout(() => this.processNextInQueue(), 1000);
      return;
    }

    availableWorker.busy = true;
    const request = this.requestQueue.shift()!;
    try {
      const result = await this.processUrlSequentially(
        request.url,
        request.basicResult,
        request.options,
        request.urlHash,
        request.startTime
      );
      request.resolve(result);
    } catch (error) {
      AppLogger.error("Error processing URL:", error);
      request.resolve(request.basicResult);
    } finally {
      availableWorker.busy = false;
      this.processNextInQueue();
    }
  }

  /**
   * Process URL sequentially
   */
  private async processUrlSequentially(
    url: string,
    basicResult: MaliciousPatternResult,
    options: MaliciousPatternOptions,
    urlHash: string,
    startTime: number
  ): Promise<MaliciousPatternResult> {
    let enhancedResult = { ...basicResult };

    // Apply AI pattern detection
    const aiResults = await this.applyAIPatternDetection(url, enhancedResult);
    enhancedResult.detectedPatterns.push(...aiResults.patterns);
    enhancedResult.score += aiResults.scoreAdjustment;

    // Apply zero-day detection
    const zeroResults = this.applyZeroDayDetection(url, enhancedResult);
    enhancedResult.detectedPatterns.push(...zeroResults.patterns);
    enhancedResult.score += zeroResults.scoreAdjustment;

    // Update final result properties
    enhancedResult.confidence = this.determineConfidence(enhancedResult);
    enhancedResult.isMalicious =
      enhancedResult.score >= (options.minScore || 50);
    enhancedResult.recommendation = this.enhanceRecommendation(enhancedResult);

    // Add contextual analysis if not present
    if (!enhancedResult.contextAnalysis) {
      enhancedResult.contextAnalysis = {
        relatedPatterns: [],
        entropyScore: this.calculateEntropyScore(url),
        anomalyScore: this.calculateAnomalyScore(url, enhancedResult),
        encodingLayers: this.detectEncodingLayers(url),
      };
    }

    // Add to training data
    this.addToTrainingData(url, enhancedResult);

    this.updatePerformanceStats(startTime);
    return enhancedResult;
  }

  /**
   * Apply AI-based pattern detection
   */
  private async applyAIPatternDetection(
    url: string,
    result: MaliciousPatternResult
  ): Promise<{ patterns: DetectedPattern[]; scoreAdjustment: number }> {
    const patterns: DetectedPattern[] = [];
    let scoreAdjustment = 0;

    try {
      const features = this.extractUrlFeatures(url);
      const threatProbability = await this.predictThreatProbability(
        url,
        features
      );
      if (threatProbability > 0.7) {
        patterns.push({
          type: MaliciousPatternType.ANOMALY_DETECTED,
          pattern: "ml_prediction",
          location: "ai:ml_model",
          severity: "high",
          confidence: "medium",
          description: `Machine learning model detected high threat probability (${(
            threatProbability * 100
          ).toFixed(2)}%)`,
          matchedValue: url,
        });
        scoreAdjustment += threatProbability * 30;
      }

      this.threatSignatures.forEach((signature, key) => {
        if (signature.matches(url, features)) {
          patterns.push({
            type: signature.patternType,
            pattern: signature.name,
            location: `ai:signature:${key}`,
            severity: signature.severity,
            confidence: signature.confidence,
            description: signature.description,
            matchedValue: url,
          });
          scoreAdjustment +=
            signature.severity === "high"
              ? 35
              : signature.severity === "medium"
              ? 20
              : 10;
        }
      });
    } catch (error) {
      AppLogger.error("Error in AI pattern detection:", error);
    }

    return { patterns, scoreAdjustment };
  }

  /**
   * Apply zero-day vulnerability detection
   */
  private applyZeroDayDetection(
    url: string,
    result: MaliciousPatternResult
  ): { patterns: DetectedPattern[]; scoreAdjustment: number } {
    const patterns: DetectedPattern[] = [];
    let scoreAdjustment = 0;

    try {
      // Check pattern clusters
      this.zeroKnowledgePatterns.patternClusters.forEach((cluster, index) => {
        const score = this.scoreAgainstCluster(url, cluster);
        if (score > 0.8) {
          patterns.push({
            type: MaliciousPatternType.ZERO_DAY,
            pattern: `pattern_cluster_${index}`,
            location: `zeroday:cluster:${index}`,
            severity: "high",
            confidence: "medium",
            description: `URL matches emerging threat pattern cluster (score: ${score.toFixed(
              2
            )})`,
            matchedValue: url,
          });
          scoreAdjustment += 40;
        }
      });
    } catch (error) {
      AppLogger.error("Error in zero-day detection:", error);
    }

    return { patterns, scoreAdjustment };
  }

  /**
   * Score a URL against a pattern cluster
   */
  private scoreAgainstCluster(url: string, cluster: PatternCluster): number {
    let matches = 0;
    for (const pattern of cluster.patterns) {
      if (pattern.test(url)) {
        matches++;
      }
    }
    const tokens = cluster.tokens || [];
    for (const token of tokens) {
      if (url.includes(token)) {
        matches++;
      }
    }
    const totalPatterns = cluster.patterns.length + tokens.length;
    return totalPatterns > 0 ? matches / totalPatterns : 0;
  }

  /**
   * Extract URL features
   */
  private extractUrlFeatures(url: string): URLFeatures {
    if (ncu.isValidUrl(url, { allowLocalhost: true })) {
      return {
        length: url.length,
        entropy: this.calculateEntropyScore(url),
        specialCharCount: (url.match(/[^a-zA-Z0-9]/g) || []).length,
        digitCount: (url.match(/[0-9]/g) || []).length,
        encodedCharCount: (url.match(/%[0-9A-F]{2}/g) || []).length,
        subdomainLevels: url.split(".").length - 2,
        parameterCount: new URL(url).searchParams.size,
        pathDepth: new URL(url).pathname.split("/").filter(Boolean).length,
        hasUnusualPort:
          !!new URL(url).port &&
          new URL(url).port !== "80" &&
          new URL(url).port !== "443",
        containsIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url),
        hexEncodingRatio:
          (url.match(/%[0-9A-F]{2}/g) || []).length / url.length,
        domainLength: new URL(url).hostname.length,
        tld: new URL(url).hostname.split(".").pop() || "",
        hasBase64: /[A-Za-z0-9+/]{4,}=?$/.test(url),
      };
    }
    const parsedUrl = new URL(url, "http://default");
    return {
      length: url.length,
      entropy: this.calculateEntropyScore(url),
      specialCharCount: (url.match(/[^a-zA-Z0-9]/g) || []).length,
      digitCount: (url.match(/[0-9]/g) || []).length,
      encodedCharCount: (url.match(/%[0-9A-F]{2}/g) || []).length,
      subdomainLevels: parsedUrl.hostname.split(".").length - 2,
      parameterCount: parsedUrl.searchParams.size,
      pathDepth: parsedUrl.pathname.split("/").filter(Boolean).length,
      hasUnusualPort:
        !!parsedUrl.port && parsedUrl.port !== "80" && parsedUrl.port !== "443",
      containsIPAddress: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(
        parsedUrl.hostname
      ),
      hexEncodingRatio: (url.match(/%[0-9A-F]{2}/g) || []).length / url.length,
      domainLength: parsedUrl.hostname.length,
      tld: parsedUrl.hostname.split(".").pop() || "",
      hasBase64: /[A-Za-z0-9+/]{20,}={0,2}/.test(url),
    };
  }

  /**
   * Calculate entropy score
   */
  private calculateEntropyScore(input: string): number {
    const frequencies: Map<string, number> = new Map();
    const length = input.length;
    for (let i = 0; i < length; i++) {
      const char = input[i];
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }
    let entropy = 0;
    for (const [_, count] of frequencies.entries()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  /**
   * Calculate anomaly score
   */
  private calculateAnomalyScore(
    url: string,
    result: MaliciousPatternResult
  ): number {
    let anomalyScore = 0;
    try {
      const parsedUrl = new URL(url);
      const tldMatch = parsedUrl.hostname.match(/\.([a-z]{2,})$/i);
      if (
        tldMatch &&
        ["xyz", "top", "club"].includes(tldMatch[1].toLowerCase())
      ) {
        anomalyScore += 10;
      }
      if (/^[0-9]+\./.test(parsedUrl.hostname)) {
        anomalyScore += 15;
      }
      parsedUrl.searchParams.forEach((value, key) => {
        if (value.length > 100) {
          anomalyScore += 10;
        }
      });
    } catch (error) {
      AppLogger.error("Error calculating anomaly score:", error);
    }
    return Math.min(anomalyScore, 100);
  }

  /**
   * Detect encoding layers
   */
  private detectEncodingLayers(url: string): number {
    let layers = 0;
    let currentUrl = url;
    while (layers < 10) {
      const decodedUrl = decodeURIComponent(currentUrl);
      if (decodedUrl === currentUrl) {
        break;
      }
      layers++;
      currentUrl = decodedUrl;
    }
    return layers;
  }

  /**
   * Determine confidence level
   */
  private determineConfidence(
    result: MaliciousPatternResult
  ): "low" | "medium" | "high" {
    const score = result.score;
    const patternCount = result.detectedPatterns.length;
    const highSeverityCount = result.detectedPatterns.filter(
      (p) => p.severity === "high"
    ).length;

    if (score >= 100 || highSeverityCount >= 3) {
      return "high";
    } else if (score >= 50 || patternCount >= 3) {
      return "medium";
    }
    return "low";
  }

  /**
   * Enhance recommendation
   */
  private enhanceRecommendation(result: MaliciousPatternResult): string {
    const baseRecommendation =
      result.recommendation || "URL analysis complete.";
    const additionalNotes: string[] = [];
    const patternTypes = new Set(result.detectedPatterns.map((p) => p.type));

    if (patternTypes.has(MaliciousPatternType.ZERO_DAY)) {
      additionalNotes.push(
        "URGENT: Potential zero-day vulnerability detected."
      );
    }
    if (patternTypes.has(MaliciousPatternType.RANSOMWARE)) {
      additionalNotes.push(
        "Implement immediate blocking measures for potential ransomware."
      );
    }
    if (result.score >= 100) {
      additionalNotes.push(
        "High threat score detected; consider blocking this URL."
      );
    }

    return additionalNotes.length > 0
      ? `${baseRecommendation} ${additionalNotes.join(" ")}`
      : baseRecommendation;
  }

  /**
   * Add to training data
   */
  private addToTrainingData(url: string, result: MaliciousPatternResult): void {
    try {
      const features = this.extractUrlFeatures(url);
      this.trainingData.push({
        url,
        features,
        isMalicious: result.isMalicious,
        detectedPatternTypes: result.detectedPatterns.map((p) => p.type),
        score: result.score,
        timestamp: Date.now(),
      });
      if (this.trainingData.length > 1000) {
        this.trainingData.shift();
      }
    } catch (error) {
      AppLogger.error("Error adding to training data:", error);
    }
  }

  /**
   * Update performance stats
   */
  private updatePerformanceStats(startTime: number): void {
    const duration = performance.now() - startTime;
    this.performanceStats.totalProcessingTime += duration;
    this.performanceStats.avgProcessingTime =
      this.performanceStats.totalProcessingTime /
      this.performanceStats.totalRequests;
    try {
      this.performanceStats.peakMemoryUsage = Math.max(
        this.performanceStats.peakMemoryUsage,
        process.memoryUsage().heapUsed / 1024 / 1024
      );
    } catch {
      // Ignore if process.memoryUsage is unavailable
    }
  }

  /**
   * Integrate with NSB
   */
  public static integrateWithNSB(): void {
    const naise = NAISE.getInstance();
    const originalAnalyzeUrl = NSB.analyzeUrl;
    NSB.analyzeUrl = async function (
      input: string,
      options: MaliciousPatternOptions = {}
    ): Promise<MaliciousPatternResult> {
      const basicResult = await originalAnalyzeUrl.call(NSB, input, options);
      try {
        const enhancedResult = await naise.enhanceUrlAnalysis(
          input,
          basicResult,
          options
        );
        AppLogger.debug(
          `NAISE integration: Enhanced URL analysis for ${input}. Score: ${enhancedResult.score}, Patterns: ${enhancedResult.detectedPatterns.length}`
        );
        if (enhancedResult.isMalicious) {
          naise.addToDistributedThreatDB(input, enhancedResult, "analysis");
        }
        NSB.provideFeedback(
          input,
          enhancedResult,
          enhancedResult.isMalicious,
          "automated"
        );
        return enhancedResult;
      } catch (error) {
        AppLogger.error("NAISE integration error:", error);
        return basicResult;
      }
    };
    AppLogger.info("NAISE successfully integrated with NSB");
  }

  /**
   * Add to distributed threat database
   */
  private addToDistributedThreatDB(
    url: string,
    result: MaliciousPatternResult,
    source: "analysis" | "external"
  ): void {
    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();
      const entry = this.distributedThreatDB.get(hostname) || {
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        reportCount: 0,
        maliciousCount: 0,
        maliciousScore: 0,
        patterns: new Set<MaliciousPatternType>(),
        severity: "low",
        confidence: "low",
        source,
      };

      entry.lastSeen = Date.now();
      entry.reportCount++;
      if (result.isMalicious) {
        entry.maliciousCount++;
        result.detectedPatterns.forEach((pattern) =>
          entry.patterns.add(pattern.type)
        );
      }
      entry.maliciousScore =
        entry.maliciousCount / Math.max(entry.reportCount, 1);
      entry.severity =
        entry.maliciousScore > 0.7
          ? "high"
          : entry.maliciousScore > 0.3
          ? "medium"
          : "low";
      entry.confidence = entry.maliciousScore > 0.7 ? "high" : "medium";

      this.distributedThreatDB.set(hostname, entry);
    } catch (error) {
      AppLogger.error("Error adding to distributed threat DB:", error);
    }
  }

  /**
   * Enhance URL analysis with AI
   */
  public async enhanceUrlAnalysis(
    url: string,
    basicResult: MaliciousPatternResult,
    options: MaliciousPatternOptions
  ): Promise<MaliciousPatternResult> {
    const startTime = performance.now();
    this.performanceStats.totalRequests++;
    const urlHash = crypto.createHash("sha256").update(url).digest("hex");

    try {
      // Check distributed threat database for cached results
      const cachedResult = this.distributedThreatDB.get(urlHash);
      if (
        cachedResult &&
        cachedResult.lastSeen > Date.now() - 24 * 60 * 60 * 1000
      ) {
        this.performanceStats.requestsWithCache++;
        return {
          ...basicResult,
          detectedPatterns: Array.from(cachedResult.patterns).map((type) => ({
            type,
            pattern: type,
            location: "cache",
            severity: cachedResult.severity,
            confidence: cachedResult.confidence,
            description: "Cached threat entry",
            matchedValue: url,
          })),
          score: cachedResult.maliciousScore * 100,
          isMalicious: cachedResult.maliciousScore > 0.7,
        };
      }

      this.performanceStats.requestsWithoutCache++;
      return this.processUrlInParallel(
        url,
        basicResult,
        options,
        urlHash,
        startTime
      );
    } catch (error) {
      AppLogger.error("Error enhancing URL analysis:", error);
      return basicResult;
    }
  }
}
