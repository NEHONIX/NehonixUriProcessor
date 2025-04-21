# NehonixURIProcessor v2.1.2

A comprehensive TypeScript library for detecting, decoding, and encoding various URI encoding schemes. Designed for security testing, web application penetration testing, and analyzing potential attacks, `NehonixURIProcessor` offers powerful auto-detection, decoding, and validation capabilities.

**Version**: 2.1.2  
**License**: MIT

## Overview

The `NehonixURIProcessor` class provides methods to:

- Validate URIs with configurable rules, including custom properties (`checkUrl`).
- Automatically detect and decode encoded URIs to plaintext (`autoDetectAndDecode`).
- Analyze URLs for potential security vulnerabilities (`analyzeURL`).
- Encode and decode strings using a wide range of encoding schemes.
- Generate encoding variations for Web Application Firewall (WAF) bypass testing.
- Create `URL` objects from URI strings.

Version 2.1.2 includes performance improvements, enhanced encoding detection algorithms, and better error handling for complex nested encodings.

## Installation

```bash
npm i nehonix-uri-processor
```

Install the `punycode` dependency:

```bash
npm install punycode
```

## Key Features in v2.1.2

### Enhanced Encoding Detection

The library now provides more accurate detection of complex and nested encodings, with improved confidence scoring and better handling of edge cases.

### Improved Error Handling

Better error handling in decoding functions ensures more reliable results even with malformed or unusual input strings.

### Comprehensive Documentation

Detailed JSDoc comments and examples make it easier to understand and use the library's features effectively.

## Core Methods

### autoDetectAndDecode

**Signature**:

```typescript
static autoDetectAndDecode(input: string, maxIterations?: number): DecodeResult
```

**Description**:  
Automatically detects and decodes a URI string to plaintext, handling complex and nested encodings (e.g., Base64, percent-encoding, hexadecimal). This method uses advanced detection to identify encoding types and iteratively decodes until plaintext is reached or the maximum iteration limit is met. Ideal for security testing and decoding obfuscated URIs.

**Parameters**:

- `input` (`string`): The URI string to decode (e.g., `https://example.com?test=dHJ1ZQ==`).
- `maxIterations` (`number`, optional, default: `10`): Maximum decoding iterations to prevent infinite loops.

**Example**:

```typescript
const decoded = NehonixURIProcessor.autoDetectAndDecode(
  "https://example.com?param=dHJ1ZQ=="
);
console.log(decoded.val()); // https://example.com?param=true
```

### checkUrl

**Signature**:

```typescript
static checkUrl(url: string, options?: UrlValidationOptions): UrlCheckResult
```

**Description**:  
Performs comprehensive validation of a URL string against configurable rules, returning detailed results for each validation step. This method is ideal for security testing, debugging, and detailed URL analysis.

**Parameters**:

- `url` (`string`): The URL string to validate.
- `options` (`UrlValidationOptions`, optional): Configuration for validation rules.

**Example**:

```typescript
const result = NehonixURIProcessor.checkUrl("https://example.com?test=value", {
  httpsOnly: true,
  strictParamEncoding: true,
});

console.log(result.isValid); // true or false
console.log(result.validationDetails); // Detailed validation results
```

## Recommendations

- Use `autoDetectAndDecode` as the primary method for decoding URIs (instead of the deprecated `detectAndDecode`)
- For security testing, use the comprehensive `checkUrl` method for detailed validation results
- Refer to the [changelog](./changelog.md) for details on all changes in this version

## Supported Encoding Types

The library supports a wide range of encoding types, including:

- Percent encoding (`%XX`)
- Double percent encoding (`%25XX`)
- Base64 and URL-safe Base64
- Hexadecimal (`\xXX` or `0xXX`)
- Unicode (`\uXXXX` or `\u{XXXXX}`)
- HTML entities (`&lt;`, `&#60;`, `&#x3C;`)
- Punycode (`xn--`)
- ASCII octal (`\XXX`)
- ROT13
- Base32
- JavaScript and CSS escape sequences
- UTF-7
- Quoted-Printable
- Raw hexadecimal
- JWT

See the [main documentation](../readme.md) for a complete list of supported encoding types and methods.
