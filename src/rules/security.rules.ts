import { AppLogger } from "../common/AppLogger";
import {
  DetectedPattern,
  MaliciousPatternOptions,
} from "../services/MaliciousPatterns.service";
import { NehonixEncService } from "../services/NehonixEnc.service";
import NSS from "../services/NehonixSecurity.service";
import { URLAnalysisResult, WAFBypassVariants } from "../types";
import { MaliciousComponentType as malicious_component_type } from "../types/v2.2.0";

export class SecurityRules {
  private static get enc() {
    return NehonixEncService;
  }

  // =============== SECURITY UTILITIES ===============

  static analyzeMaliciousPatterns(
    url: string,
    options?: MaliciousPatternOptions
  ) {
    const maliciousResult = NSS.analyzeUrl(url, options);
    return maliciousResult;
  }

  static analyzeURL(
    ...p: Parameters<typeof SecurityRules.analyzeMaliciousPatterns>
  ): URLAnalysisResult {
    const [url, options] = p;
    const vulnerabilities: string[] = [];
    const vulnerabilitieDetails: DetectedPattern[] = [];

    try {
      const urlObj = new URL(url);
      const params = new URLSearchParams(urlObj.search);
      const paramMap: { [key: string]: string } = {};

      // Extract parameters
      params.forEach((value, key) => {
        paramMap[key] = value;
        SecurityRules.analyzeMaliciousPatterns(value, options).then((c) => {
          if (c.isMalicious) {
            c.detectedPatterns.forEach((pattern) => {
              vulnerabilities.push(pattern.description);
            });
            vulnerabilitieDetails.push(...c.detectedPatterns);
          }
        });
      });

      return {
        baseURL: `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`,
        parameters: paramMap,
        potentialVulnerabilities: vulnerabilities,
        vulnerabilitieDetails: vulnerabilitieDetails,
      };
    } catch (e: any) {
      AppLogger.error("Error while analyzing URL:", e);
      return {
        baseURL: url,
        parameters: {},
        potentialVulnerabilities: ["Invalid or malformed URL"],
        vulnerabilitieDetails,
      };
    }
  }

  /**
   * Generates encoding variants of a string for WAF bypass testing
   * @param input The string to encode
   * @returns An object containing different encoding variants
   */
  static generateWAFBypassVariants(input: string): WAFBypassVariants {
    return {
      percentEncoding: SecurityRules.enc.encodePercentEncoding(input),
      doublePercentEncoding:
        SecurityRules.enc.encodeDoublePercentEncoding(input),
      mixedEncoding: SecurityRules.generateMixedEncoding(input),
      alternatingCase: SecurityRules.generateAlternatingCase(input),
      fullHexEncoding: SecurityRules.enc.encodeAllChars(input),
      unicodeVariant: SecurityRules.enc.encodeUnicode(input),
      htmlEntityVariant: SecurityRules.enc.encodeHTMLEntities(input),
    };
  }

  /**
   * Generates mixed encoding (different types of encoding combined)
   */
  private static generateMixedEncoding(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      // Apply different encodings based on position
      switch (i % 3) {
        case 0:
          result += encodeURIComponent(char);
          break;
        case 1:
          const hex = char.charCodeAt(0).toString(16).padStart(2, "0");
          result += `\\x${hex}`;
          break;
        case 2:
          result += char;
          break;
      }
    }
    return result;
  }

  /**
   * Generates a string with alternating upper and lower case
   * Useful for bypassing certain filters
   */
  private static generateAlternatingCase(input: string): string {
    let result = "";
    for (let i = 0; i < input.length; i++) {
      const char = input[i];
      result += i % 2 === 0 ? char.toLowerCase() : char.toUpperCase();
    }
    return result;
  }
}

export { SecurityRules as sr };
