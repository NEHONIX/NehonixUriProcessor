import { AppLogger } from "../common/AppLogger";
import { MaliciousComponentType } from "../types/v2.2.0";
import { PARTTERNS } from "../utils/attacks_parttens";
import {
  ContextAnalysisResult,
  DetectedPattern,
  MaliciousPatternOptions,
  MaliciousPatternResult,
  MaliciousPatternType,
  RelatedPatternGroup,
} from "../services/MaliciousPatterns.service";
import NSS from "../services/NehonixSecurity.service";

export class NMPSUtils {
  private static SUSPICIOUS_PARAMETER_NAMES =
    PARTTERNS.SUSPICIOUS_PARAMETER_NAMES;
  static sanitizeInput: typeof NSS.sanitizeInput;
  constructor(sanitizeInput: typeof NSS.sanitizeInput) {
    NMPSUtils.sanitizeInput = sanitizeInput;
  }

  static isSafeHighEntropy(input: string): boolean {
    // JWT pattern
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input)) {
      return true;
    }

    // Data URI for images
    if (/^data:image\/(png|jpeg|gif);base64,[A-Za-z0-9+/=]+$/.test(input)) {
      return true;
    }

    // API key pattern (example: 32+ alphanumeric characters)
    if (/^[A-Za-z0-9]{32,}$/.test(input)) {
      return true;
    }

    return false;
  }

  /**
   * Generates a recommendation specifically for URLs based on detected patterns
   */
  static generateUrlRecommendation(
    detectedPatterns: DetectedPattern[],
    componentResults: Record<MaliciousComponentType, MaliciousPatternResult>
  ): string {
    if (detectedPatterns.length === 0) {
      return "No suspicious patterns detected in the URL.";
    }

    const componentIssues: string[] = [];
    let hasCriticalIssue = false;

    // Check severity of issues by component
    Object.entries(componentResults).forEach(([component, result]) => {
      if (result.detectedPatterns.length > 0) {
        const highSeverity = result.detectedPatterns.some(
          (p) => p.severity === "high"
        );

        if (highSeverity) {
          hasCriticalIssue = true;
          componentIssues.push(
            `Critical issues found in the ${component} component`
          );
        } else {
          componentIssues.push(
            `Suspicious patterns found in the ${component} component`
          );
        }
      }
    });

    // Generate overall recommendation
    if (hasCriticalIssue) {
      return `This URL contains potentially malicious patterns. ${componentIssues.join(
        ". "
      )}. Consider blocking this URL and scanning related systems for compromise.`;
    } else if (componentIssues.length > 1) {
      return `This URL has multiple suspicious components: ${componentIssues.join(
        "; "
      )}. Recommend further review before processing this URL.`;
    } else {
      return `This URL contains suspicious patterns. ${componentIssues[0]}. Proceed with caution and validate the URL source.`;
    }
  }

  /**
   * Finds related patterns across different components that might indicate a sophisticated attack
   */
  static findRelatedPatternGroups(
    patterns: DetectedPattern[]
  ): RelatedPatternGroup[] {
    const groups: RelatedPatternGroup[] = [];

    // Find cross-site scripting patterns across multiple components
    const xssPatterns = patterns.filter(
      (p) => p.type === MaliciousPatternType.XSS
    );
    if (xssPatterns.length > 1) {
      groups.push({
        patterns: [MaliciousPatternType.XSS],
        description:
          "Multiple XSS vectors detected across different URL components",
        riskMultiplier: 1.5,
      });
    }

    // Find SQL injection patterns across multiple components
    const sqlInjectionPatterns = patterns.filter(
      (p) => p.type === MaliciousPatternType.SQL_INJECTION
    );
    if (sqlInjectionPatterns.length > 1) {
      groups.push({
        patterns: [MaliciousPatternType.SQL_INJECTION],
        description:
          "Multiple SQL injection vectors detected across different URL components",
        riskMultiplier: 1.6,
      });
    }

    // Find encoding obfuscation techniques
    const encodingPatterns = patterns.filter(
      (p) =>
        p.type === MaliciousPatternType.ENCODED_PAYLOAD ||
        p.type === MaliciousPatternType.MULTI_ENCODING
    );

    // Check for encoding + injection combination (sophisticated attack)
    if (encodingPatterns.length > 0) {
      const injectionPatterns = patterns.filter(
        (p) =>
          p.type === MaliciousPatternType.SQL_INJECTION ||
          p.type === MaliciousPatternType.XSS ||
          p.type === MaliciousPatternType.COMMAND_INJECTION ||
          p.type === MaliciousPatternType.TEMPLATE_INJECTION ||
          p.type === MaliciousPatternType.NOSQL_INJECTION
      );

      if (injectionPatterns.length > 0) {
        groups.push({
          patterns: [
            MaliciousPatternType.ENCODED_PAYLOAD,
            ...injectionPatterns.map((p) => p.type),
          ],
          description:
            "Encoded payload combined with injection attempt - sophisticated evasion technique",
          riskMultiplier: 2.0,
        });
      }
    }

    // Detect potential combination attacks
    const hasRedirect = patterns.some(
      (p) => p.type === MaliciousPatternType.OPEN_REDIRECT
    );
    const hasXss = patterns.some((p) => p.type === MaliciousPatternType.XSS);

    if (hasRedirect && hasXss) {
      groups.push({
        patterns: [
          MaliciousPatternType.OPEN_REDIRECT,
          MaliciousPatternType.XSS,
        ],
        description: "Combined redirect and XSS attack vector detected",
        riskMultiplier: 1.8,
      });
    }

    // Detect protocol confusion attacks
    const hasProtocolConfusion = patterns.some(
      (p) => p.type === MaliciousPatternType.PROTOCOL_CONFUSION
    );
    const hasSsrf = patterns.some((p) => p.type === MaliciousPatternType.SSRF);

    if (hasProtocolConfusion && hasSsrf) {
      groups.push({
        patterns: [
          MaliciousPatternType.PROTOCOL_CONFUSION,
          MaliciousPatternType.SSRF,
        ],
        description: "Protocol confusion combined with SSRF attempt",
        riskMultiplier: 1.9,
      });
    }

    return groups;
  }

  /**
   * Checks a string against a set of regex patterns for a specific attack type
   */
  static checkPatterns(
    input: string,
    patterns: RegExp[],
    type: MaliciousPatternType,
    description: string,
    severity: "low" | "medium" | "high",
    results: DetectedPattern[],
    options: Required<MaliciousPatternOptions>
  ): void {
    for (const pattern of patterns) {
      const match = pattern.exec(input);
      if (match) {
        const matchedValue = match[0];
        const confidence = this.calculateConfidence(matchedValue, input);
        const contextScore = options.enableContextualAnalysis
          ? this.calculateContextScore(match, input)
          : undefined;

        results.push({
          type,
          pattern: pattern.toString(),
          location: `index: ${match.index}`,
          severity,
          confidence,
          description,
          matchedValue,
          contextScore,
        });

        if (options.debug) {
          AppLogger.debug(
            `NMPS: Detected ${type} pattern: '${matchedValue}' at index ${match.index}`
          );
        }

        // Only report the first match for each pattern to avoid redundancy
        break;
      }
    }
  }

  /**
   * Checks for suspicious parameter names in a URL
   */
  static checkSuspiciousParameters(
    input: string,
    results: DetectedPattern[],
    options: Required<MaliciousPatternOptions>
  ): void {
    try {
      // Try to extract parameter names from URL query string
      let params: string[] = [];

      // Check if input contains URL parameters
      const queryStart = input.indexOf("?");
      if (queryStart !== -1) {
        const queryString = input.substring(queryStart + 1);
        const pairs = queryString.split("&");

        for (const pair of pairs) {
          const eqIndex = pair.indexOf("=");
          if (eqIndex !== -1) {
            const paramName = pair.substring(0, eqIndex).toLowerCase();
            params.push(paramName);
          }
        }
      }

      // Check parameter names against suspicious list
      for (const param of params) {
        if (this.SUSPICIOUS_PARAMETER_NAMES.includes(param)) {
          results.push({
            type: MaliciousPatternType.SUSPICIOUS_PARAMETER,
            pattern: "suspicious_param_name",
            location: `parameter: ${param}`,
            severity: "low",
            confidence: "medium",
            description: `Suspicious parameter name "${param}" detected`,
            matchedValue: param,
          });

          if (options.debug) {
            AppLogger.debug(`NMPS: Detected suspicious parameter: '${param}'`);
          }
        }
      }
    } catch (error) {
      AppLogger.error("Error in checkSuspiciousParameters:", error);
    }
  }

  /**
   * Calculates confidence level for a pattern match based on match characteristics
   */
  // In NehonixSecurity.service.txt
  static calculateConfidence(
    matchedValue: string,
    fullInput: string
  ): "low" | "medium" | "high" {
    const matchRatio = matchedValue.length / fullInput.length;

    // High-confidence patterns
    const highConfidencePatterns = [
      /<script/i,
      /javascript:/i,
      /onload=/i,
      /alert\(/i,
      /select.*from/i,
      /union.*select/i,
      /whoami/i,
      /ping/i,
      /etc\/passwd/i,
      /localhost/i,
    ];

    if (highConfidencePatterns.some((pattern) => pattern.test(matchedValue))) {
      return "high";
    }

    if (matchRatio < 0.1 && matchedValue.length < 5) {
      return "low";
    }

    if (this.isLikelyFalsePositive(matchedValue, fullInput)) {
      return "low";
    }

    if (matchedValue.length >= 10 || matchRatio > 0.5) {
      return "high";
    }

    return "medium";
  }

  /**
   * Checks if a match is likely a false positive based on context
   */
  // In NehonixSecurity.service.txt
  static isLikelyFalsePositive(match: string, fullInput: string): boolean {
    const falsePositiveContexts = [
      /https?:\/\/[^\/]+\/documentation\/examples?\/.*sql/i,
      /https?:\/\/[^\/]+\/blog\/.*security/i,
      /code example/i,
      /security training/i,
      /\/\/\s*Example/i,
      // Ignore common URL parameters
      /\?(sort|filter|category|page|limit|offset)=/i,
    ];

    for (const context of falsePositiveContexts) {
      if (context.test(fullInput)) {
        return true;
      }
    }

    // Ignore matches in legitimate query parameters
    if (/[&?]sort=/.test(fullInput) && match.includes("sort")) {
      return true;
    }
    /**
     * TODO: Add a feed back for false positives
     * */

    return false;
  }
  /**
   * Calculates additional context score for pattern matches
   */
  static calculateContextScore(
    match: RegExpExecArray,
    fullInput: string
  ): number {
    let score = 1.0;

    const start = Math.max(0, match.index - 10);
    const end = Math.min(fullInput.length, match.index + match[0].length + 10);
    const context = fullInput.substring(start, end);

    if (/\\x|\\u|%u|%[0-9a-f]{2}|&#\d+;|&#x[0-9a-f]+;/i.test(context)) {
      score *= 1.5;
    }

    if (/\/\*|\*\/|--|#|\/{2}/i.test(context)) {
      score *= 1.3;
    }

    const criticalPatterns = [
      /etc\/passwd/i,
      /localhost/i,
      /192\.168\.\d{1,3}\.\d{1,3}/i,
      /file=https?:\/\//i,
    ];

    for (const pattern of criticalPatterns) {
      if (pattern.test(context)) {
        score *= 1.5;
        break;
      }
    }

    return score;
  }

  /**
   * Performs contextual analysis on detected patterns to improve detection accuracy
   */
  static performContextualAnalysis(
    patterns: DetectedPattern[],
    fullInput: string,
    options: MaliciousPatternOptions
  ): ContextAnalysisResult {
    // Find relationships between detected patterns
    const relatedGroups: RelatedPatternGroup[] =
      this.findRelatedPatternGroups(patterns);

    // Calculate entropy score
    const entropyScore = this.calculateEntropy(fullInput);

    // Detect potential encoding layers
    const encodingLayers = this.detectEncodingLayers(fullInput);

    // Calculate anomaly score based on character distribution
    const anomalyScore = this.calculateAnomalyScore(fullInput);

    return {
      relatedPatterns: relatedGroups,
      entropyScore,
      anomalyScore,
      encodingLayers,
    };
  }

  /**
   * Calculates Shannon entropy of a string to detect random or encoded content
   * Higher entropy often indicates encryption or encoding
   */
  static calculateEntropy(input: string): number {
    const len = input.length;
    const charCounts: Record<string, number> = {};

    // Count character occurrences
    for (let i = 0; i < len; i++) {
      const char = input[i];
      charCounts[char] = (charCounts[char] || 0) + 1;
    }

    // Calculate entropy
    let entropy = 0;
    for (const char in charCounts) {
      const probability = charCounts[char] / len;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  /**
   * Detects number of potential encoding layers in a string
   */
  static detectEncodingLayers(input: string): number {
    let layers = 0;
    let currentInput = input;

    const maxLayers = 5; // Prevent infinite loops
    let attempts = 0;

    while (attempts < maxLayers) {
      let decoded = currentInput;

      // URL decoding
      if (/%[0-9A-Fa-f]{2}/.test(decoded)) {
        try {
          decoded = decodeURIComponent(decoded);
          if (decoded !== currentInput) {
            layers++;
            currentInput = decoded;
          }
        } catch {}
      }

      // HTML entities
      if (/&[#a-zA-Z0-9]+;/.test(decoded)) {
        const temp = decoded
          .replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">")
          .replace(/&amp;/g, "&")
          .replace(/&quot;/g, '"')
          .replace(/&#x[0-9a-fA-F]+;/g, (match) => {
            try {
              const hex = match.substring(3, match.length - 1);
              return String.fromCodePoint(parseInt(hex, 16));
            } catch {
              return match;
            }
          })
          .replace(/&#\d+;/g, (match) => {
            try {
              const decimal = match.substring(2, match.length - 1);
              return String.fromCodePoint(parseInt(decimal, 10));
            } catch {
              return match;
            }
          });

        if (temp !== decoded) {
          layers++;
          currentInput = temp;
        }
      }

      // Unicode escapes
      if (/\\u[0-9a-fA-F]{4}/.test(decoded)) {
        try {
          const temp = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
            return String.fromCodePoint(parseInt(hex, 16));
          });
          if (temp !== decoded) {
            layers++;
            currentInput = temp;
          }
        } catch {}
      }

      // Base64
      if (/^[A-Za-z0-9+/=]+$/.test(decoded)) {
        try {
          const temp = Buffer.from(decoded, "base64").toString();
          if (temp !== decoded && temp.length > 0) {
            layers++;
            currentInput = temp;
          }
        } catch {}
      }

      // If no further decoding occurred, break
      if (decoded === currentInput) {
        break;
      }
      attempts++;
    }

    return layers;
  }

  /**
   * Calculates statistical anomaly score based on character distribution
   */
  static calculateAnomalyScore(input: string): number {
    const len = input.length;
    if (len === 0) return 0;

    // Character type counts
    let lowerCount = 0;
    let upperCount = 0;
    let digitCount = 0;
    let specialCount = 0;
    let controlCount = 0;
    let nonAsciiCount = 0;

    // Count character types
    for (let i = 0; i < len; i++) {
      const code = input.charCodeAt(i);

      if (code >= 97 && code <= 122) {
        // a-z
        lowerCount++;
      } else if (code >= 65 && code <= 90) {
        // A-Z
        upperCount++;
      } else if (code >= 48 && code <= 57) {
        // 0-9
        digitCount++;
      } else if (code < 32 || code === 127) {
        // Control characters
        controlCount++;
      } else if (code > 127) {
        // Non-ASCII
        nonAsciiCount++;
      } else {
        specialCount++; // Other special characters
      }
    }

    // Calculate percentages
    const lowerPercent = lowerCount / len;
    const upperPercent = upperCount / len;
    const digitPercent = digitCount / len;
    const specialPercent = specialCount / len;
    const controlPercent = controlCount / len;
    const nonAsciiPercent = nonAsciiCount / len;

    // Calculate anomaly score - higher means more unusual distribution
    let anomalyScore = 0;

    // Unusual amount of special characters
    if (specialPercent > 0.3) {
      anomalyScore += specialPercent * 2;
    }

    // Unusual amount of non-ASCII characters
    if (nonAsciiPercent > 0.1) {
      anomalyScore += nonAsciiPercent * 3;
    }

    // Presence of control characters is very suspicious
    if (controlPercent > 0) {
      anomalyScore += controlPercent * 5;
    }

    // Unusual character type distribution
    const alphaPercent = lowerPercent + upperPercent;
    if (alphaPercent < 0.2 && len > 10) {
      anomalyScore += 1;
    }

    // Very high percentage of digits can be suspicious
    if (digitPercent > 0.7 && len > 10) {
      anomalyScore += 0.5;
    }

    return Math.min(anomalyScore, 5); // Cap at 5
  }

  /**
   * Calculates total risk score based on detected patterns
   */
  // In NehonixSecurity.service.txt
  static calculateTotalScore(
    patterns: DetectedPattern[],
    sensitivityMultiplier: number
  ): number {
    if (patterns.length === 0) return 0;

    let score = 0;

    const severityScores = {
      high: 40,
      medium: 20,
      low: 10,
    };

    const criticalPatternMultipliers = {
      [MaliciousPatternType.PATH_TRAVERSAL]: 1.5,
      [MaliciousPatternType.SSRF]: 1.5,
      [MaliciousPatternType.RFI]: 1.5,
    };

    const confidenceMultipliers = {
      high: 1.5,
      medium: 1.0,
      low: 0.5,
    };

    for (const pattern of patterns) {
      let patternScore =
        severityScores[pattern.severity] *
        confidenceMultipliers[pattern.confidence];

      // Apply critical pattern multiplier
      if (
        criticalPatternMultipliers[
          pattern.type as keyof typeof criticalPatternMultipliers
        ]
      ) {
        patternScore *=
          criticalPatternMultipliers[
            pattern.type as keyof typeof criticalPatternMultipliers
          ];
      }

      if (pattern.contextScore) {
        patternScore *= pattern.contextScore;
      }

      score += patternScore;
    }

    score *= sensitivityMultiplier;

    const patternTypeCounts: Record<string, number> = {};
    for (const pattern of patterns) {
      patternTypeCounts[pattern.type] =
        (patternTypeCounts[pattern.type] || 0) + 1;
    }

    for (const type in patternTypeCounts) {
      if (patternTypeCounts[type] > 1) {
        score *= 1 + (patternTypeCounts[type] - 1) * 0.2;
      }
    }

    return Math.min(Math.round(score), 100);
  }
  /**
   * Determines overall confidence level based on score and pattern count
   */
  static determineConfidence(
    score: number,
    patternCount: number
  ): "low" | "medium" | "high" {
    if (score >= 75 || (score >= 50 && patternCount >= 3)) {
      return "high";
    } else if (score >= 40 || (score >= 25 && patternCount >= 2)) {
      return "medium";
    } else {
      return "low";
    }
  }

  /**
   * Generates appropriate recommendation based on detected patterns
   */
  static generateRecommendation(
    patterns: DetectedPattern[],
    score: number
  ): string {
    if (patterns.length === 0) {
      return "No malicious patterns detected. Input appears safe.";
    }

    const patternTypes = new Set(patterns.map((p) => p.type));
    const recommendations: string[] = [];

    // Critical recommendations first
    if (score >= 75) {
      recommendations.push(
        "HIGH RISK: Input contains malicious patterns. Block and investigate immediately."
      );
    } else if (score >= 50) {
      recommendations.push(
        "MEDIUM RISK: Input contains suspicious patterns. Validate before processing."
      );
    } else {
      recommendations.push(
        "LOW RISK: Input contains potentially suspicious patterns. Use caution."
      );
    }

    // Specific recommendations based on pattern types
    if (patternTypes.has(MaliciousPatternType.SQL_INJECTION)) {
      recommendations.push(
        "Implement prepared statements or parameterized queries for database operations."
      );
    }

    if (patternTypes.has(MaliciousPatternType.XSS)) {
      recommendations.push(
        "Implement output encoding and content security policy (CSP) headers."
      );
    }

    if (patternTypes.has(MaliciousPatternType.COMMAND_INJECTION)) {
      recommendations.push(
        "Avoid direct command execution. Use restricted APIs and allowlists."
      );
    }

    if (patternTypes.has(MaliciousPatternType.PATH_TRAVERSAL)) {
      recommendations.push(
        "Validate file paths and use path canonicalization before file operations."
      );
    }

    if (patternTypes.has(MaliciousPatternType.SSRF)) {
      recommendations.push(
        "Implement allowlists for external resource access and validate URLs."
      );
    }

    if (patternTypes.has(MaliciousPatternType.RFI)) {
      recommendations.push(
        "Validate file inclusions against a whitelist of allowed sources and disable remote file access."
      );
    }
    if (
      patternTypes.has(MaliciousPatternType.ENCODED_PAYLOAD) ||
      patternTypes.has(MaliciousPatternType.MULTI_ENCODING)
    ) {
      recommendations.push(
        "Decode and normalize input before validation to prevent evasion techniques."
      );
    }

    return recommendations.join(" ");
  }

  /**
   * Checks if content is likely HTML/JavaScript code fragment
   *
   * @param input - String to check
   * @returns boolean indicating if it looks like code
   */
  static isLikelyCode(input: string): boolean {
    // Check for common code patterns
    const codePatterns = [
      /<\w+>[\s\S]*<\/\w+>/i, // HTML tags
      /<\w+\s+[\w\-]+=(['"]).*?\1(\s+[\w\-]+=(['"]).*?\3)*\s*>/i, // HTML tags with attributes
      /function\s*\([^)]*\)\s*\{/i, // JavaScript function declaration
      /var\s+\w+\s*=|let\s+\w+\s*=|const\s+\w+\s*=/i, // Variable declarations
      /if\s*\([^)]*\)\s*\{/i, // if statement
      /for\s*\([^)]*\)\s*\{/i, // for loop
      /\bclass\s+\w+\s*\{/i, // class declaration
      /import\s+.*\s+from\s+['"].*['"]/i, // ES6 imports
      /export\s+(default\s+)?(function|class|const)/i, // ES6 exports
    ];

    return codePatterns.some((pattern) => pattern.test(input));
  }
  /**
   * Checks if a tag is in the allowed safe tags list
   * @param tag - The tag name to check
   * @returns Whether the tag is considered safe
   */
  static isSafeTag(tag: string): boolean {
    const safeTags = [
      "p",
      "br",
      "b",
      "i",
      "em",
      "strong",
      "small",
      "ul",
      "ol",
      "li",
      "h1",
      "h2",
      "h3",
      "h4",
      "h5",
      "h6",
      "span",
      "div",
      "table",
      "tr",
      "td",
      "th",
      "thead",
      "tbody",
    ];
    return safeTags.includes(tag.toLowerCase());
  }

  /**
   * Creates a placeholder of specified length to preserve original string length
   * @param type - Type of content being replaced
   * @param length - Length of the original content
   * @returns Placeholder string of approximately the same length
   */
  static createPlaceholder(type: string, length: number): string {
    if (length <= 0) return "";
    return `[${type}_${Array(length)
      .fill("x")
      .join("")
      .substring(0, length - type.length - 2)}]`;
  }

  /**
   * Checks if input appears to be a URL
   * @param input - String to check
   * @returns Whether the input looks like a URL
   */
  static isUrlLike(input: string): boolean {
    return (
      /^(https?:\/\/|www\.|\/\/)/i.test(input.trim()) ||
      /\.(com|org|net|io|gov|edu)($|\/|\?)/i.test(input)
    );
  }

  /**
   * Specialized sanitization for URLs
   * @param url - URL to sanitize
   * @param opts - Sanitization options
   * @returns Sanitized URL
   */
  public sanitizeUrl(url: string, opts: any): string {
    // Block potentially dangerous protocols
    const dangerousProtocols = [
      "javascript:",
      "data:",
      "vbscript:",
      "file:",
      "about:",
    ];

    for (const protocol of dangerousProtocols) {
      if (url.toLowerCase().includes(protocol)) {
        return opts.strictMode
          ? ""
          : url.replace(
              new RegExp(protocol, "gi"),
              `${protocol.replace(":", "_blocked:")}`
            );
      }
    }

    // Ensure URL structure is valid
    try {
      // Check if URL needs a protocol to be parsed
      if (!url.match(/^[a-z]+:\/\//i)) {
        // Add protocol for validation purposes only
        url = "https://" + url.replace(/^\/\//, "");
      }

      const parsedUrl = new URL(url);

      // Check for potential open redirects
      if (parsedUrl.searchParams.toString().match(/url=|redirect=|to=/i)) {
        return this.handlePotentialRedirect(url, opts);
      }

      return url;
    } catch (e) {
      // If URL is malformed, return it with a warning flag if not in strict mode
      return opts.strictMode ? "" : `[potential_malformed_url]${url}`;
    }
  }

  /**
   * Handle potential redirect parameters in URLs
   * @param url - URL to check
   * @param opts - Sanitization options
   * @returns Sanitized URL
   */
  public handlePotentialRedirect(
    url: string,

    opts: any
  ): string {
    try {
      const parsedUrl = new URL(url);

      // List of common redirect parameter names
      const redirectParams = [
        "url",
        "redirect",
        "to",
        "target",
        "link",
        "goto",
      ];

      // Check each parameter
      for (const param of redirectParams) {
        if (parsedUrl.searchParams.has(param)) {
          const redirectValue = parsedUrl.searchParams.get(param);

          // If redirect value is present, sanitize it and update the parameter
          if (redirectValue) {
            parsedUrl.searchParams.set(
              param,
              NMPSUtils.sanitizeInput(redirectValue, {
                ...opts,
                strictMode: true, // More strict for embedded URLs
              })
            );
          }
        }
      }

      return parsedUrl.toString();
    } catch (e) {
      // If there's an error processing the URL, return safe version
      return opts.strictMode ? "" : `[redirect_sanitized]${url}`;
    }
  }
}
