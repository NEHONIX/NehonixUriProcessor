import { NehonixEncService as enc } from "./NehonixEnc.service";
import { NehonixDecService as dec } from "./NehonixDec.service";
import { SecurityRules as sr } from "../rules/security.rules";
import { AppLogger } from "../common/AppLogger";
/**
 * Service class for enhanced security features in v2.2.0
 * Provides methods for comparing URI variants and generating security reports
 */
export class NehonixSecurityService {
    /**
     * Generates and compares encoded variants of a URI to evaluate their safety against common security filters (e.g., WAFs).
     *
     * @param input - The URI string to analyze
     * @returns Array of objects with variant, encoding type, and safety assessment
     */
    static compareUriVariants(input) {
        const variants = [];
        try {
            // Generate basic WAF bypass variants
            const wafVariants = sr.generateWAFBypassVariants(input);
            // Add percent encoding variant
            variants.push({
                variant: wafVariants.percentEncoding,
                encoding: "percent",
                isSafe: !this.containsMaliciousPatterns(wafVariants.percentEncoding),
            });
            // Add double percent encoding variant
            variants.push({
                variant: wafVariants.doublePercentEncoding,
                encoding: "doublepercent",
                isSafe: !this.containsMaliciousPatterns(wafVariants.doublePercentEncoding),
            });
            // Add base64 variant
            const base64Variant = enc.encode(input, "base64");
            variants.push({
                variant: base64Variant,
                encoding: "base64",
                isSafe: true, // Base64 typically bypasses simple pattern matching
            });
            // Add hex variant
            const hexVariant = enc.encode(input, "hex");
            variants.push({
                variant: hexVariant,
                encoding: "hex",
                isSafe: true, // Hex encoding typically bypasses simple pattern matching
            });
            // Add unicode variant
            variants.push({
                variant: wafVariants.unicodeVariant,
                encoding: "unicode",
                isSafe: !this.containsMaliciousPatterns(wafVariants.unicodeVariant),
            });
            // Add HTML entity variant
            variants.push({
                variant: wafVariants.htmlEntityVariant,
                encoding: "htmlEntity",
                isSafe: !this.containsMaliciousPatterns(wafVariants.htmlEntityVariant),
            });
            // Add mixed encoding variant
            variants.push({
                variant: wafVariants.mixedEncoding,
                encoding: "mixed",
                isSafe: !this.containsMaliciousPatterns(wafVariants.mixedEncoding),
            });
            // Add ROT13 variant
            const rot13Variant = enc.encode(input, "rot13");
            variants.push({
                variant: rot13Variant,
                encoding: "rot13",
                isSafe: !this.containsMaliciousPatterns(rot13Variant),
            });
            // Add URL-safe Base64 variant
            const urlSafeBase64Variant = enc.encode(input, "urlSafeBase64");
            variants.push({
                variant: urlSafeBase64Variant,
                encoding: "urlSafeBase64",
                isSafe: true, // URL-safe Base64 typically bypasses simple pattern matching
            });
        }
        catch (e) {
            AppLogger.error("Error generating URI variants:", e);
        }
        return variants;
    }
    /**
     * Generates a detailed security report for a URI, including vulnerability analysis,
     * encoded variants, and actionable recommendations.
     *
     * @param url - The URI to analyze
     * @returns A comprehensive security report object
     */
    static generateSecurityReport(url) {
        try {
            // Analyze the URL for vulnerabilities
            const analysis = sr.analyzeURL(url);
            // Generate and compare encoding variants
            const variants = this.compareUriVariants(url);
            // Generate recommendations based on analysis
            const recommendations = this.generateRecommendations(analysis, variants);
            return {
                analysis,
                variants,
                recommendations,
            };
        }
        catch (e) {
            AppLogger.error("Error generating security report:", e);
            return {
                analysis: {
                    baseURL: url,
                    parameters: {},
                    potentialVulnerabilities: ["Error analyzing URL: " + e.message],
                },
                variants: [],
                recommendations: [
                    "Unable to generate security recommendations due to an error.",
                ],
            };
        }
    }
    /**
     * Asynchronously detects and decodes a URI string to plaintext, with optional Web Worker support.
     *
     * @param input - The URI string to decode
     * @param opt - Optional configuration object
     * @param opt.maxIterations - Maximum decoding iterations (default: 10)
     * @param opt.useWorker - Whether to use a Web Worker for decoding (browser only, default: false)
     * @param opt.timeout - Timeout in milliseconds for the decoding operation (default: 5000)
     * @returns Promise resolving to the decoded string
     */
    static async autoDetectAndDecodeAsync(input, opt) {
        const timeout = (opt === null || opt === void 0 ? void 0 : opt.timeout) || 5000; // Default timeout of 5 seconds
        const maxIterations = (opt === null || opt === void 0 ? void 0 : opt.maxIterations) || 10; // Default max iterations
        AppLogger.log("opt: ", opt);
        // If Web Workers are not supported or not requested, use the synchronous method
        if (!(opt === null || opt === void 0 ? void 0 : opt.useWorker) || typeof Worker === "undefined") {
            return new Promise((resolve, reject) => {
                try {
                    const result = dec.decodeAnyToPlaintext(input, { maxIterations });
                    resolve(result.val());
                }
                catch (e) {
                    AppLogger.error("Error in synchronous decoding:", e);
                    reject(new Error(`Decoding failed: ${e.message}`));
                }
            });
        }
        // Web Worker implementation
        return new Promise((resolve, reject) => {
            try {
                // Create a new Web Worker
                const worker = new Worker("./worker/NehonixDecodeWorker.js");
                console.log("worker: ", worker);
                // Set up timeout
                const timeoutId = setTimeout(() => {
                    worker.terminate();
                    AppLogger.error("Web Worker decoding timed out");
                    reject(new Error("Decoding operation timed out"));
                }, timeout);
                // Handle messages from the Worker
                worker.onmessage = (event) => {
                    clearTimeout(timeoutId);
                    const { type, data, error } = event.data;
                    if (type === "result") {
                        resolve(data);
                    }
                    else if (type === "error") {
                        AppLogger.error("Web Worker error:", error);
                        reject(new Error(`Worker error: ${error}`));
                    }
                    worker.terminate(); // Clean up Worker
                };
                // Handle Worker errors
                worker.onerror = (error) => {
                    clearTimeout(timeoutId);
                    AppLogger.error("Web Worker error:", error.message);
                    worker.terminate();
                    reject(new Error(`Worker error: ${error.message}`));
                };
                // Send decoding task to Worker
                worker.postMessage({
                    type: "decode",
                    data: { input, maxIterations },
                });
            }
            catch (e) {
                AppLogger.error("Error initializing Web Worker:", e);
                // Fallback to synchronous decoding
                try {
                    const result = dec.decodeAnyToPlaintext(input, { maxIterations });
                    resolve(result.val());
                }
                catch (fallbackError) {
                    reject(new Error(`Fallback decoding failed: ${fallbackError.message}`));
                }
            }
        });
    }
    /**
     * Checks if a string contains common malicious patterns.
     *
     * @private
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
     * Generates security recommendations based on URL analysis and variant comparison.
     *
     * @private
     * @param analysis - The URL analysis result
     * @param variants - The URI variant comparison results
     * @returns Array of security recommendations
     */
    static generateRecommendations(analysis, variants) {
        var _a, _b, _c;
        const recommendations = [];
        // Add recommendations based on vulnerabilities
        for (const vulnerability of analysis.potentialVulnerabilities) {
            if (vulnerability.includes("XSS")) {
                const param = (_a = vulnerability.match(/"([^"]+)"/)) === null || _a === void 0 ? void 0 : _a[1];
                recommendations.push(`Escape parameter "${param}" to prevent XSS (e.g., use an HTML sanitizer).`);
            }
            else if (vulnerability.includes("SQLi")) {
                const param = (_b = vulnerability.match(/"([^"]+)"/)) === null || _b === void 0 ? void 0 : _b[1];
                recommendations.push(`Sanitize parameter "${param}" to prevent SQL injection (e.g., use prepared statements).`);
            }
            else if (vulnerability.includes("Path Traversal") ||
                vulnerability.includes("LFI")) {
                const param = (_c = vulnerability.match(/"([^"]+)"/)) === null || _c === void 0 ? void 0 : _c[1];
                recommendations.push(`Validate and sanitize parameter "${param}" to prevent path traversal attacks.`);
            }
        }
        // Add general recommendations
        if (variants.some((v) => !v.isSafe)) {
            recommendations.push("Implement a Web Application Firewall (WAF) that can detect encoded attack patterns.");
        }
        if (Object.keys(analysis.parameters).length > 0) {
            recommendations.push("Validate all input parameters against a strict schema before processing.");
        }
        // If no specific recommendations, add a general one
        if (recommendations.length === 0) {
            recommendations.push("No specific vulnerabilities detected. Continue following security best practices.");
        }
        return recommendations;
    }
}
// Export as NSS for easier importing
export const NSS = NehonixSecurityService;
//# sourceMappingURL=NehonixSecurity.service.js.map