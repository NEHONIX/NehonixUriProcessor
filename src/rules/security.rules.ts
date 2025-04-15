import { NehonixEncService } from "../services/NehonixEnc.service";
import { URLAnalysisResult, WAFBypassVariants } from "../types";

export class SecurityRules {
  private static enc: typeof NehonixEncService = NehonixEncService;
  // =============== SECURITY UTILITIES ===============

  static analyzeURL(url: string): URLAnalysisResult {
    const vulnerabilities: string[] = [];

    try {
      const urlObj = new URL(url);
      const params = new URLSearchParams(urlObj.search);
      const paramMap: { [key: string]: string } = {};

      // Extract parameters
      params.forEach((value, key) => {
        paramMap[key] = value;

        // Detect potential vulnerabilities
        if (value.includes("<") || value.includes(">")) {
          vulnerabilities.push(`Possible XSS in parameter "${key}"`);
        }
        if (value.includes("'") || value.includes('"')) {
          vulnerabilities.push(`Possible SQLi in parameter "${key}"`);
        }
        if (
          value.toLowerCase().includes("union") &&
          value.toLowerCase().includes("select")
        ) {
          vulnerabilities.push(
            `Suspicion of SQLi (UNION) in parameter "${key}"`
          );
        }
        if (value.includes("../") || value.includes("..\\")) {
          vulnerabilities.push(
            `Possible LFI/Path Traversal in parameter "${key}"`
          );
        }
      });

      return {
        baseURL: `${urlObj.protocol}//${urlObj.host}${urlObj.pathname}`,
        parameters: paramMap,
        potentialVulnerabilities: vulnerabilities,
      };
    } catch (e: any) {
      console.error("Error while analyzing URL:", e);
      return {
        baseURL: url,
        parameters: {},
        potentialVulnerabilities: ["Invalid or malformed URL"],
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
