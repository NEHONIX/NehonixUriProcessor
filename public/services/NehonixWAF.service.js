import { AppLogger } from "../common/AppLogger";
/**
 * Web Application Firewall (WAF) service for detecting and preventing encoded attack patterns
 * Provides advanced pattern matching and heuristic analysis for security protection
 */
export class NehonixWAFService {
    /**
     * Detects if a string contains encoded attack patterns
     *
     * @param input - The string to analyze
     * @param options - Configuration options for detection
     * @returns Object with detection result and confidence score
     */
    static detectEncodedAttacks(input, options) {
        const confidenceThreshold = (options === null || options === void 0 ? void 0 : options.confidenceThreshold) || this.DEFAULT_CONFIDENCE_THRESHOLD;
        const patternMatchThreshold = (options === null || options === void 0 ? void 0 : options.patternMatchThreshold) || this.DEFAULT_PATTERN_MATCH_THRESHOLD;
        try {
            // Track the number of pattern matches
            let patternMatches = 0;
            let detectedPatterns = [];
            // Check for common attack patterns
            if (this.containsMaliciousPatterns(input, options === null || options === void 0 ? void 0 : options.detectionOptions)) {
                patternMatches++;
                detectedPatterns.push("direct_pattern_match");
            }
            // Check for obfuscation techniques
            if (this.detectsObfuscationTechniques(input)) {
                patternMatches++;
                detectedPatterns.push("obfuscation_detected");
            }
            // Check for encoding anomalies
            if (this.detectsEncodingAnomalies(input)) {
                patternMatches++;
                detectedPatterns.push("encoding_anomalies");
            }
            // Check for evasion techniques
            if (this.detectsEvasionTechniques(input)) {
                patternMatches++;
                detectedPatterns.push("evasion_techniques");
            }
            // Calculate confidence score based on number of matches
            const confidenceScore = Math.min(patternMatches / patternMatchThreshold, 1.0);
            return {
                isAttack: confidenceScore >= confidenceThreshold,
                confidenceScore,
                detectedPatterns,
                patternMatches,
            };
        }
        catch (e) {
            AppLogger.error("Error in WAF attack detection:", e);
            return {
                isAttack: false,
                confidenceScore: 0,
                detectedPatterns: [],
                patternMatches: 0,
                error: e.message,
            };
        }
    }
    /**
     * Checks if a string contains common malicious patterns
     *
     * @param input - The string to check
     * @param options - Optional configuration for pattern detection
     * @returns True if malicious patterns are detected
     */
    static containsMaliciousPatterns(input, options) {
        // Default all detection types to true if not specified
        const opts = {
            detectSqlInjection: (options === null || options === void 0 ? void 0 : options.detectSqlInjection) !== false,
            detectXss: (options === null || options === void 0 ? void 0 : options.detectXss) !== false,
            detectPathTraversal: (options === null || options === void 0 ? void 0 : options.detectPathTraversal) !== false,
            detectCommandInjection: (options === null || options === void 0 ? void 0 : options.detectCommandInjection) !== false,
            customPatterns: (options === null || options === void 0 ? void 0 : options.customPatterns) || [],
        };
        const lowerInput = input.toLowerCase();
        // Check for common XSS patterns
        if (opts.detectXss &&
            /<script|javascript:|on\w+\s*=|alert\s*\(|eval\s*\(|\bdata:\s*text\/html|\bvbscript:|\bbase64|\bxss:|\bimg\s+src|\biframe\s+src|\bdocument\.cookie|\bdocument\.location|\bwindow\.location|\bdocument\.write|\bdocument\.\w+\s*=/.test(lowerInput)) {
            return true;
        }
        // Check for SQL injection patterns
        if (opts.detectSqlInjection &&
            /('|\s)or\s|union\s+select|--\s|;\s*drop|;\s*insert|exec\s*\(|'\s*\+\s*'|\bselect\s+.*?\bfrom\b|\bdelete\s+from\b|\bupdate\s+.*?\bset\b|\bwhere\s+\d+=\d+|\bwaitfor\s+delay\b|\bsleep\s*\(|\bor\s+\d+=\d+|\band\s+\d+=\d+|\bchar\s*\(|\bconcat\s*\(|\bhaving\s+\d+=\d+/.test(lowerInput)) {
            return true;
        }
        // Check for path traversal
        // if (opts.detectPathTraversal && (
        //   /\.\.\/|\.\.\\/|\.\.\.%2f|\.\.\.%5c|\.\.\.%c0%af|\.\.\.%252f|%c0%ae%c0%ae\/|%c0%ae%c0%ae%5c/.test(input)
        // )) {
        //   return true;
        // }
        // Check for command injection
        if (opts.detectCommandInjection &&
            /;\s*\w+|\|\s*\w+|`\s*\w+|\$\(|\&\s*\w+|\|\|\s*\w+|\&\&\s*\w+|\bping\s+-c\b|\bnc\s+|\bnetcat\b|\bnmap\b|\bcurl\s+|\bwget\s+|\btelnet\s+|\bpowershell\b|\bcmd\b|\bbash\b|\bsh\b/.test(lowerInput)) {
            return true;
        }
        // Check custom patterns if provided
        if (opts.customPatterns.length > 0) {
            for (const pattern of opts.customPatterns) {
                if (pattern.test(input)) {
                    return true;
                }
            }
        }
        return false;
    }
    /**
     * Detects common obfuscation techniques in the input
     *
     * @private
     * @param input - The string to analyze
     * @returns True if obfuscation is detected
     */
    static detectsObfuscationTechniques(input) {
        // Check for hex encoding patterns
        if (/\\x[0-9a-f]{2}/i.test(input)) {
            return true;
        }
        // Check for unicode escape sequences
        if (/\\u[0-9a-f]{4}/i.test(input)) {
            return true;
        }
        // Check for excessive URL encoding
        if (/%[0-9a-f]{2}(%[0-9a-f]{2})+/i.test(input)) {
            return true;
        }
        // Check for mixed encoding (different encoding schemes used together)
        const hasPercentEncoding = /%[0-9a-f]{2}/i.test(input);
        const hasHtmlEntities = /&[#a-z0-9]+;/i.test(input);
        const hasUnicodeEscapes = /\\u[0-9a-f]{4}/i.test(input);
        // If multiple encoding types are detected together, it's suspicious
        if ((hasPercentEncoding && hasHtmlEntities) ||
            (hasPercentEncoding && hasUnicodeEscapes) ||
            (hasHtmlEntities && hasUnicodeEscapes)) {
            return true;
        }
        return false;
    }
    /**
     * Detects anomalies in encoding patterns that might indicate attacks
     *
     * @private
     * @param input - The string to analyze
     * @returns True if encoding anomalies are detected
     */
    static detectsEncodingAnomalies(input) {
        // Check for unnecessarily encoded common characters
        if (/%(41|42|43|44|45|46|47|48|49|4a|4b|4c|4d|4e|4f|50|51|52|53|54|55|56|57|58|59|5a)/i.test(input)) {
            return true; // Uppercase letters A-Z are unnecessarily encoded
        }
        // Check for null byte injection attempts
        if (/%00|\\0|\\x00|\\u0000/.test(input)) {
            return true;
        }
        // Check for overlong UTF-8 sequences (often used to bypass filters)
        if (/%c0%ae|%c1%1c|%e0%80%ae|%f0%80%80%ae/.test(input)) {
            return true;
        }
        return false;
    }
    /**
     * Detects common WAF evasion techniques
     *
     * @private
     * @param input - The string to analyze
     * @returns True if evasion techniques are detected
     */
    static detectsEvasionTechniques(input) {
        // Check for comment injection in SQL or HTML contexts
        if (/\/\*.*?\*\/|<!--.*?-->/.test(input)) {
            return true;
        }
        // Check for case switching (e.g., ScRiPt instead of script)
        const lowerInput = input.toLowerCase();
        if (lowerInput !== input &&
            (lowerInput.includes("script") ||
                lowerInput.includes("alert") ||
                lowerInput.includes("select") ||
                lowerInput.includes("union"))) {
            // If the lowercase version contains suspicious keywords but the original has mixed case
            return true;
        }
        // Check for character insertion (e.g., scr'+'ipt)
        if (/[a-z]\s*['"+]\s*['"+]\s*[a-z]/i.test(input)) {
            return true;
        }
        return false;
    }
    /**
     * Generates WAF configuration recommendations based on detected patterns
     *
     * @param detectionResults - Results from detectEncodedAttacks
     * @returns Array of configuration recommendations
     */
    static generateWAFRecommendations(detectionResults) {
        const recommendations = [];
        if (detectionResults.isAttack) {
            recommendations.push("Implement a Web Application Firewall (WAF) that can detect encoded attack patterns.");
            if (detectionResults.detectedPatterns.includes("direct_pattern_match")) {
                recommendations.push("Configure WAF rules to block common attack patterns in all inputs.");
            }
            if (detectionResults.detectedPatterns.includes("obfuscation_detected")) {
                recommendations.push("Enable WAF detection for obfuscation techniques like hex encoding and unicode escapes.");
            }
            if (detectionResults.detectedPatterns.includes("encoding_anomalies")) {
                recommendations.push("Configure WAF to detect and block anomalous encoding patterns, especially overlong UTF-8 sequences.");
            }
            if (detectionResults.detectedPatterns.includes("evasion_techniques")) {
                recommendations.push("Enhance WAF rules to detect evasion techniques like comment injection and case switching.");
            }
            // Add general recommendations
            recommendations.push("Implement input validation on all parameters before processing.");
            recommendations.push("Consider using a commercial WAF solution with regularly updated rule sets.");
        }
        else if (detectionResults.confidenceScore > 0.3) {
            // Some suspicious patterns but not enough to trigger an alert
            recommendations.push("Consider implementing a WAF as a preventive security measure.");
            recommendations.push("Validate all input parameters against a strict schema before processing.");
        }
        else {
            recommendations.push("No specific attack patterns detected. Continue following security best practices.");
        }
        return recommendations;
    }
}
// Default detection thresholds
NehonixWAFService.DEFAULT_CONFIDENCE_THRESHOLD = 0.7;
NehonixWAFService.DEFAULT_PATTERN_MATCH_THRESHOLD = 3;
// Export as NWAF for easier importing
export const NWAF = NehonixWAFService;
//# sourceMappingURL=NehonixWAF.service.js.map