import NDS from "../services/NehonixDec.service";
import { AppLogger } from "./AppLogger";

/**
 * Shared utility methods for encoding detection and basic decoding operations
 */
class NehonixCommonUtils {
  // static static decodeB64 = this.dec.decodeBase64;
  // static static drwp = this.dec.decodeRawHexWithoutPrefix;

  // =============== ENCODING DETECTION METHODS ===============

  /**
   * Checks if the string contains hexadecimal encoding
   */
  static hasHexEncoding(input: string): boolean {
    // Look for hexadecimal sequences like \x20, 0x20, etc.
    return /\\x[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2}/.test(input);
  }

  /**
   * Checks if the string contains Unicode encoding
   */
  static hasUnicodeEncoding(input: string): boolean {
    // Look for Unicode sequences like \u00A9, \u{1F600}, etc.
    return /\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]+\}/.test(input);
  }

  /**
   * Checks if the string contains HTML entities
   */
  static hasHTMLEntityEncoding(input: string): boolean {
    // Look for HTML entities like &lt;, &#60;, &#x3C;, etc.
    return /&[a-zA-Z]+;|&#\d+;|&#x[0-9A-Fa-f]+;/.test(input);
  }

  /**
   * Checks if the string contains punycode
   */
  static hasPunycode(input: string): boolean {
    // Look for punycode prefixes
    return /xn--/.test(input);
  }

  /**
   * Checks if the string contains percent encoding (%)
   */
  static hasPercentEncoding(input: string): boolean {
    // Look for sequences like %20, %3F, etc.
    return /%[0-9A-Fa-f]{2}/.test(input);
  }

  /**
   * Checks if the string contains double percent encoding (%%XX)
   */
  static hasDoublePercentEncoding(input: string): boolean {
    // Look for sequences like %2520 (which is encoded %20)
    return /%25[0-9A-Fa-f]{2}/.test(input);
  }

  // First implementation removed to fix duplicate error

  // =============== BASIC DECODING METHODS ===============

  /**
   * Decodes raw hexadecimal string (without prefixes)
   */
  static drwp(hexString: string): string {
    // Verify the input is a valid string (even length only)
    if (!/^[0-9A-Fa-f]+$/.test(hexString) || hexString.length % 2 !== 0) {
      throw new Error(
        "Invalid hex string: length must be even or contains non-hex characters"
      );
    }

    let result = "";

    // Process the string in character pairs
    for (let i = 0; i < hexString.length; i += 2) {
      const hexPair = hexString.substring(i, i + 2);

      // Convert hexadecimal pair to character
      const charCode = parseInt(hexPair, 16);
      result += String.fromCharCode(charCode);
    }

    return result;
  }
  /**
   * Basic Base64 decoding
   */

  /**
   * Decodes base64 encoding
   */
  static decodeB64(input: string): string {
    try {
      // Convert URL-safe Base64 to standard Base64
      let base64String = input.replace(/-/g, "+").replace(/_/g, "/");

      // Add padding if needed
      while (base64String.length % 4 !== 0) {
        base64String += "=";
      }

      // Try decoding with proper error handling
      try {
        // Node.js
        if (typeof Buffer !== "undefined") {
          return Buffer.from(base64String, "base64").toString("utf-8");
        }
        // Browser
        else {
          return atob(base64String);
        }
      } catch (e) {
        AppLogger.warn("Base64 decoding failed, returning original input");
        return input;
      }
    } catch (e: any) {
      AppLogger.error(`Base64 decoding failed: ${e.message}`);
      return input; // Return original input on error instead of throwing
    }
  }

  //new with is[name] methods
  /**
   * Enhanced encoding detection methods to accurately detect various encoding types
   */

  /**
   * Checks if a string is likely to be plain text
   * @param s The string to check
   */
  static isPlainText(s: string): boolean {
    if (!s || s.length < 3) return true;

    // Check for readable text characteristics
    const words = s.split(/\s+/).filter((w) => w.length > 0);
    const alphaRatio =
      (s.match(/[a-zA-Z\s\d.,!?'"-]/g) || []).length / s.length;
    const punctuationRatio =
      (s.match(/[.,!?;:'"()-]/g) || []).length / s.length;
    const spaceRatio = (s.match(/\s/g) || []).length / s.length;

    // Readable text typically has spaces between words
    const hasNormalSpacing = spaceRatio > 0.05 && spaceRatio < 0.3;

    // Normal text has a high ratio of alphanumeric and punctuation characters
    const hasNormalCharset = alphaRatio > 0.8;

    // Normal text has some punctuation but not too much
    const hasNormalPunctuation = punctuationRatio < 0.15;

    return (
      words.length > 1 &&
      hasNormalSpacing &&
      hasNormalCharset &&
      hasNormalPunctuation
    );
  }

  /**
   * Enhanced ROT13 detection that avoids false positives
   * @param s The string to check
   */
  static isRot13(s: string): boolean {
    if (!s || s.length < 5) return false;

    // Skip if it appears to be plain English
    if (/(the|and|for|that|with|this|from|have|will)\s/i.test(s)) return false;

    // Check for common ROT13 patterns
    const hasCommonRot13Patterns =
      /(gur|naq|sbe|gung|jvgu|guvf|sebz|unir|jvyy)\s/i.test(s);

    // Check for alphabetic content and normal spacing
    const alphaRatio = (s.match(/[a-zA-Z]/g) || []).length / s.length;
    const spaceRatio = (s.match(/\s/g) || []).length / s.length;
    const hasAlphaAndSpaces =
      alphaRatio > 0.6 && spaceRatio > 0.05 && spaceRatio < 0.3;

    // Check for ROT13 characteristics - letters are shifted
    const letterFrequency = { e: 0, t: 0, a: 0, o: 0, i: 0, n: 0, r: 0, s: 0 };
    const rot13Frequency = { r: 0, g: 0, n: 0, b: 0, v: 0, a: 0, e: 0, f: 0 };

    const lowerS = s.toLowerCase();

    for (const char of lowerS) {
      if (letterFrequency[char as keyof typeof letterFrequency] !== undefined) {
        letterFrequency[char as keyof typeof letterFrequency]++;
      }
      if (rot13Frequency[char as keyof typeof rot13Frequency] !== undefined) {
        rot13Frequency[char as keyof typeof rot13Frequency]++;
      }
    }

    // Calculate frequency sums for each set
    const commonLetterSum = Object.values(letterFrequency).reduce(
      (a, b) => a + b,
      0
    );
    const rot13LetterSum = Object.values(rot13Frequency).reduce(
      (a, b) => a + b,
      0
    );
    const decoded = NDS.decodeRot13(s);
    const decoded_test = /^[a-zA-Z0-9:/?=&.]+$/.test(decoded) && decoded !== s;
    // If ROT13 pattern letters appear more frequently, it's likely ROT13
    return (
      hasCommonRot13Patterns &&
      hasAlphaAndSpaces &&
      rot13LetterSum > commonLetterSum * 1.2 &&
      decoded_test
    );
  }

  /**
   * Improved Base64 detection
   * @param s The string to check
   */
  static isBase64(input: string): boolean {
    // Base64 can be padded with = at the end
    const base64Regex = /^[A-Za-z0-9+/=_-]*$/;

    // Check basic pattern
    if (!base64Regex.test(input)) return false;

    // Check length - must be divisible by 4 or could be made so with padding
    const paddedLength = input.endsWith("=")
      ? input.length
      : input.length + ((4 - (input.length % 4)) % 4);
    if (paddedLength % 4 !== 0) return false;

    // Try to decode it to verify
    try {
      const decoded = Buffer.from(
        input.replace(/-/g, "+").replace(/_/g, "/"),
        "base64"
      ).toString();
      // Check if the decoded result makes sense
      const printableChars = decoded.replace(/[^\x20-\x7E\t\r\n]/g, "").length;
      return printableChars / decoded.length > 0.7;
    } catch {
      return false;
    }
  }

  static decodeBase64(input: string): string {
    // Fix padding and URL-safe chars
    let normalizedInput = input;

    // Replace URL-safe chars
    normalizedInput = normalizedInput.replace(/-/g, "+").replace(/_/g, "/");

    // Add padding if needed
    while (normalizedInput.length % 4 !== 0) {
      normalizedInput += "=";
    }

    try {
      // Use Buffer for more robust Base64 decoding
      return Buffer.from(normalizedInput, "base64").toString();
    } catch (e: any) {
      throw new Error(`Base64 decode error: ${e.message}`);
    }
  }
  /**
   * Base32 detection
   * @param s The string to check
   */
  static isBase32(s: string): boolean {
    // Base32 must have valid length and character set
    if (!s || s.length < 8) return false;

    // Base32 uses A-Z and 2-7, with = as padding
    const base32Pattern = /^[A-Z2-7]*={0,6}$/;

    // Check if pattern matches
    if (!base32Pattern.test(s)) return false;

    // Base32 padding rules - if padded, it must have proper padding
    if (s.includes("=")) {
      // Base32 padding should align to 8-character blocks
      const paddingLength = s.split("=").length - 1;
      const dataLength = s.length - paddingLength;

      // Valid Base32 padding results in data length that's a multiple of 8
      // or specific remainder patterns
      if (dataLength % 8 !== 0 && ![2, 4, 5, 7].includes(dataLength % 8)) {
        return false;
      }
    }

    // Check for entropy like regular Base64
    const charCount: Record<string, number> = {};
    for (const char of s.replace(/=/g, "")) {
      charCount[char] = (charCount[char] || 0) + 1;
    }

    const normalizedEntropy =
      Object.values(charCount).reduce((entropy: number, count) => {
        const prob = (count as number) / s.length;
        return entropy - prob * Math.log2(prob);
      }, 0) / Math.log2(Math.min(s.length, 32));

    // Base32 encoded data typically has high entropy
    return normalizedEntropy > 0.7;
  }

  /**
   * Improved URL-safe Base64 detection
   * @param s The string to check
   */
  static isUrlSafeBase64(s: string): boolean {
    if (!s || s.length < 8) return false;

    // URL-safe Base64 uses - and _ instead of + and /
    const urlSafePattern = /^[A-Za-z0-9\-_]*={0,2}$/;
    if (!urlSafePattern.test(s)) return false;

    // Check for specific URL-safe chars
    const hasUrlSafeChars = s.includes("-") || s.includes("_");

    // Check entropy like regular Base64
    const charCount: Record<string, number> = {};
    for (const char of s) {
      charCount[char] = (charCount[char] || 0) + 1;
    }

    const normalizedEntropy =
      Object.values(charCount).reduce((entropy: number, count) => {
        const prob = (count as number) / s.length;
        return entropy - prob * Math.log2(prob);
      }, 0) / Math.log2(Math.min(s.length, 64));

    return (
      normalizedEntropy > 0.75 &&
      (hasUrlSafeChars ||
        this.isBase64(s.replace(/-/g, "+").replace(/_/g, "/")))
    );
  }

  /**
   * Improved percent encoding detection
   * @param s The string to check
   */
  static isPercentEncoding(s: string): boolean {
    if (!s || s.length < 3) return false;

    // Basic pattern check - must contain at least one %XX sequence
    const percentPattern = /%[0-9A-Fa-f]{2}/;
    if (!percentPattern.test(s)) return false;

    // Count percent-encoded sequences
    const percentSequences = s.match(/%[0-9A-Fa-f]{2}/g) || [];
    const percentRatio = percentSequences.length / (s.length / 3); // Each %XX is 3 chars

    // Ensure it's not just one random % character
    if (percentSequences.length === 1 && s.length > 10) return false;

    // Check for typical percent-encoded sequences
    const commonEncodings = /%20|%2F|%3F|%3D|%26|%25|%2B|%40/i;
    const hasCommonEncodings = commonEncodings.test(s);

    // For URL path/query components, check structure
    if (s.includes("=") || s.includes("?") || s.includes("&")) {
      // Check URL components with percent encoding
      const urlPatterns = /[?&=].*?(%[0-9A-Fa-f]{2})/;
      if (urlPatterns.test(s)) return true;
    }

    return percentRatio > 0.1 || hasCommonEncodings;
  }

  /**
   * Improved double percent encoding detection
   * @param s The string to check
   */
  static isDoublePercent(s: string): boolean {
    if (!s || s.length < 6) return false;

    // Pattern for double percent encoding: %25XX where XX are hex digits
    const doublePercentPattern = /%25[0-9A-Fa-f]{2}/;

    // Must have at least one instance of %25XX
    return doublePercentPattern.test(s);
  }

  /**
   * Improved hexadecimal encoding detection
   * @param s The string to check
   */
  static isHex(s: string): boolean {
    if (!s || s.length < 4) return false;

    // Check for common hex formatting patterns
    const hexPatterns = [
      /\\x[0-9A-Fa-f]{2}/, // \xNN format
      /0x[0-9A-Fa-f]{2}/, // 0xNN format
      /%[0-9A-Fa-f]{2}/, // %NN format
    ];

    for (const pattern of hexPatterns) {
      if (pattern.test(s)) {
        // Count matches to ensure it's not just a single occurrence
        const matches = s.match(new RegExp(pattern, "g")) || [];
        if (matches.length > 1) return true;
      }
    }

    return false;
  }

  /**
   * Improved raw hexadecimal string detection
   * @param s The string to check
   */

  /**
   * Improved raw hexadecimal string detection
   * @param s The string to check
   */
  static hasRawHexString(s: string): boolean {
    if (!s || s.length < 6) return false;

    // Must be all hex digits and even length
    if (!/^[0-9A-Fa-f]+$/.test(s)) return false;
    if (s.length % 2 !== 0) return false;

    // Check for URL parameter or path context
    const inUrlContext = s.includes("=") || s.includes("?") || s.includes("/");

    if (inUrlContext) {
      // For URLs with parameters, check if parameter value is hex
      if (s.includes("=")) {
        const parts = s.split("=");
        const value = parts[parts.length - 1];
        return (value &&
          value.length >= 6 &&
          /^[0-9A-Fa-f]+$/.test(value) &&
          value.length % 2 === 0) as boolean;
      }

      // For path segments
      if (s.includes("/")) {
        const segments = s.split("/");
        for (const segment of segments) {
          if (
            segment.length >= 6 &&
            /^[0-9A-Fa-f]+$/.test(segment) &&
            segment.length % 2 === 0
          ) {
            return true;
          }
        }
      }

      return false;
    }

    // For raw hex strings, check for entropy
    const charCount: Record<string, number> = {};
    for (const char of s) {
      charCount[char] = (charCount[char] || 0) + 1;
    }

    // Hexadecimal representation typically has more diverse character usage
    const uniqueCharsRatio = Object.keys(charCount).length / 16; // 16 possible hex chars

    // Real hex data usually uses most hex digits
    return uniqueCharsRatio > 0.5 && s.length >= 8;
  }

  /**
   * Improved ASCII Hex detection
   * @param s The string to check
   */
  static isAsciiHex(s: string): boolean {
    if (!s || s.length < 2) return false;

    // ASCII Hex encoding uses hex digits in specific patterns
    const asciiHexPattern = /^(\s*[0-9A-Fa-f]{2}\s*)+$/;

    // For spaced hex digits like "48 65 6C 6C 6F"
    if (s.includes(" ")) {
      const parts = s.trim().split(/\s+/);
      const allHexPairs = parts.every((part) => /^[0-9A-Fa-f]{2}$/.test(part));
      return allHexPairs && parts.length > 2;
    }

    // For unspaced but separated by other delimiters
    const commonDelimiters = ["-", ":", ",", ";"];
    for (const delimiter of commonDelimiters) {
      if (s.includes(delimiter)) {
        const parts = s.split(delimiter);
        const allHexPairs = parts.every((part) =>
          /^[0-9A-Fa-f]{2}$/.test(part)
        );
        return allHexPairs && parts.length > 2;
      }
    }

    return false;
  }

  /**
   * Improved ASCII Octal detection
   * @param s The string to check
   */
  static isAsciiOct(s: string): boolean {
    if (!s || s.length < 6) return false;

    // ASCII Octal typically uses 3-digit sequences
    const octPattern = /\\([0-3][0-7]{2})/g;
    const matches = s.match(octPattern);

    if (!matches || matches.length < 2) return false;

    // Check if a substantial portion of the string is octal encodings
    const encodedPortion = matches.length * 4; // Each \NNN is 4 chars
    return encodedPortion / s.length > 0.3;
  }

  /**
   * Improved Unicode escape detection
   * @param s The string to check
   */
  static isUnicode(s: string): boolean {
    if (!s || s.length < 6) return false;

    // Unicode escape patterns
    const unicodePatterns = [
      /\\u[0-9A-Fa-f]{4}/, // \uXXXX format
      /\\u\{[0-9A-Fa-f]{1,6}\}/, // \u{XXXX} format
      /&#x[0-9A-Fa-f]{2,6};/, // &#xXXXX; format (HTML hexadecimal)
    ];

    for (const pattern of unicodePatterns) {
      const matches = s.match(new RegExp(pattern, "g"));
      if (matches && matches.length > 0) {
        // For short strings, one match might be enough
        if (s.length < 20 && matches.length >= 1) return true;

        // For longer strings, require multiple matches or significant portion
        const encodedPortion = matches.join("").length;
        if (matches.length > 1 || encodedPortion / s.length > 0.3) return true;
      }
    }

    return false;
  }

  /**
   * Improved HTML entity detection
   * @param s The string to check
   */
  static isHtmlEntity(s: string): boolean {
    if (!s || s.length < 4) return false;

    // HTML entity patterns
    const entityPatterns = [
      /&[a-zA-Z]+;/, // Named entities like &lt;
      /&#\d+;/, // Decimal entities like &#60;
      /&#x[0-9A-Fa-f]+;/, // Hex entities like &#x3C;
    ];

    for (const pattern of entityPatterns) {
      const matches = s.match(new RegExp(pattern, "g"));
      if (matches && matches.length > 0) {
        // Check common entities
        const commonEntities = /&(lt|gt|amp|quot|apos|nbsp);/;
        const hasCommonEntities = commonEntities.test(s);

        // For short strings, one match might be enough if it's a common entity
        if (s.length < 20 && hasCommonEntities) return true;

        // For longer strings, require multiple matches or significant portion
        const encodedPortion = matches.join("").length;
        if (matches.length > 1 || encodedPortion / s.length > 0.3) return true;
      }
    }

    return false;
  }

  /**
   * Improved decimal HTML entity detection
   * @param s The string to check
   */
  static isDecimalHtmlEntity(s: string): boolean {
    if (!s || s.length < 4) return false;

    // Decimal HTML entity pattern (&#NN;)
    const decimalPattern = /&#\d+;/g;
    const matches = s.match(decimalPattern);

    if (!matches || matches.length < 1) return false;

    // Check if entities could represent printable ASCII
    const validEntities = matches.filter((match) => {
      const codepoint = parseInt(match.slice(2, -1), 10);
      return codepoint >= 32 && codepoint <= 126; // Printable ASCII range
    });

    // Check ratio of valid entities to all matched entities
    return validEntities.length / matches.length > 0.7;
  }

  /**
   * Improved quoted-printable detection
   * @param s The string to check
   */
  static isQuotedPrintable(s: string): boolean {
    if (!s || s.length < 6) return false;

    // Quoted-printable uses =XX format for non-ASCII chars
    const qpPattern = /=[0-9A-F]{2}/g;
    const matches = s.match(qpPattern);

    if (!matches || matches.length < 2) return false;

    // Check for soft line breaks (=\r\n)
    const hasSoftBreaks = /=(\r\n|\n|\r)/.test(s);

    // Check for typical QP characteristics
    const hasEqualsSign = s.includes("=");
    const hasMultipleEncodedChars = matches.length >= 2;

    // Calculate ratio of encoded characters
    const encodedPortion = matches.length * 3; // Each =XX is 3 chars
    const encodedRatio = encodedPortion / s.length;

    // Typical QP encoding has a mix of plain text and encoded chars
    const hasMixOfPlainAndEncoded = encodedRatio > 0.1 && encodedRatio < 0.9;

    return (
      hasEqualsSign &&
      hasMultipleEncodedChars &&
      (hasSoftBreaks || hasMixOfPlainAndEncoded)
    );
  }

  /**
   * Improved Punycode detection
   * @param s The string to check
   */
  static isPunycode(s: string): boolean {
    if (!s || s.length < 5) return false;

    // Punycode domains start with 'xn--'
    const punycodePattern = /xn--[a-z0-9-]+/i;

    // Check for entire domain match
    if (/^xn--[a-z0-9-]+$/i.test(s)) return true;

    // Check for domain within URL/hostname
    if (s.includes(".")) {
      const parts = s.split(".");
      for (const part of parts) {
        if (punycodePattern.test(part)) return true;
      }
    }

    return false;
  }

  /**
   * Improved JWT format detection
   * @param s The string to check
   */
  static hasJWTFormat(s: string): boolean {
    if (!s || s.length < 20) return false;

    // JWT has exactly two dots separating three base64url-encoded segments
    const parts = s.split(".");
    if (parts.length !== 3) return false;

    // Check that each part is non-empty and base64url-encoded
    const base64urlPattern = /^[A-Za-z0-9_-]+$/;
    const allPartsValid = parts.every(
      (part) => part.length > 0 && base64urlPattern.test(part)
    );

    if (!allPartsValid) return false;

    // Further validation - try to decode the header
    try {
      // This is a simplified check - in real code you would use a proper base64url decoder
      const header = JSON.parse(
        atob(parts[0].replace(/-/g, "+").replace(/_/g, "/"))
      );
      // Check for typical JWT header fields
      return header && (header.alg || header.typ);
    } catch (e) {
      return false;
    }
  }

  /**
   * Improved UTF-7 detection
   * @param s The string to check
   */
  static isUtf7(s: string): boolean {
    if (!s || s.length < 6) return false;

    // UTF-7 uses +/- encoding for non-ASCII
    const utf7Pattern = /\+[A-Za-z0-9+/]+-/g;
    const matches = s.match(utf7Pattern);

    if (!matches || matches.length < 1) return false;

    // Check that the + is followed by valid Base64 chars
    for (const match of matches) {
      const base64Part = match.slice(1, -1); // Remove + and -
      if (!/^[A-Za-z0-9+/]+$/.test(base64Part)) return false;
    }

    return true;
  }

  /**
   * Improved JavaScript escape sequence detection
   * @param s The string to check
   */
  static isJsEscape(s: string): boolean {
    if (!s || s.length < 4) return false;

    // JS escape sequences
    const jsEscapePatterns = [
      /\\x[0-9A-Fa-f]{2}/, // \xNN - hex escape
      /\\u[0-9A-Fa-f]{4}/, // \uNNNN - unicode escape
      /\\[0-7]{1,3}/, // \NNN - octal escape
      /\\[bfnrtv'"\\]/, // \b, \f, \n etc. - control chars
    ];

    let matchCount = 0;
    for (const pattern of jsEscapePatterns) {
      const matches = s.match(new RegExp(pattern, "g")) || [];
      matchCount += matches.length;
    }

    // Need multiple matches or significant portion for longer strings
    if (matchCount === 0) return false;

    // For short strings with quote markers, a single escape might be enough
    if (
      s.length < 20 &&
      (s.startsWith('"') || s.startsWith("'")) &&
      (s.endsWith('"') || s.endsWith("'"))
    ) {
      return matchCount >= 1;
    }

    return matchCount > 1;
  }

  /**
   * Improved CSS escape sequence detection
   * @param s The string to check
   */
  static isCssEscape(s: string): boolean {
    if (!s || s.length < 3) return false;

    // CSS escape patterns
    const cssEscapePatterns = [
      /\\[0-9A-Fa-f]{1,6}\s?/, // Unicode escapes like \20AC or \20AC
      /\\[^0-9A-Fa-f\s]/, // Single character escapes like \' or \"
    ];

    let matchCount = 0;
    for (const pattern of cssEscapePatterns) {
      const matches = s.match(new RegExp(pattern, "g")) || [];
      matchCount += matches.length;
    }

    // CSS context indicators
    const hasCssContext =
      s.includes(":") || s.includes(";") || s.includes("{") || s.includes("}");

    return matchCount > 0 && (matchCount > 1 || hasCssContext);
  }
}
export { NehonixCommonUtils as NehonixSharedUtils };
export default NehonixCommonUtils;
