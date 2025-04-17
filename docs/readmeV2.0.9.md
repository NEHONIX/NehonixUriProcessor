# NehonixURIProcessor

A comprehensive TypeScript library for detecting, decoding, and encoding various URI encoding schemes. Designed for security testing, web application penetration testing, and analyzing potential attacks, `NehonixURIProcessor` offers powerful auto-detection, decoding, and validation capabilities.

**Version**: 2.0.9  
**License**: MIT

## Overview

The `NehonixURIProcessor` class provides methods to:

- Validate URIs with configurable rules, including custom properties (`checkUrl`).
- Automatically detect and decode encoded URIs to plaintext (`autoDetectAndDecode`).
- Analyze URLs for potential security vulnerabilities (`analyzeURL`).
- Encode and decode strings using a wide range of encoding schemes.
- Generate encoding variations for Web Application Firewall (WAF) bypass testing.
- Create `URL` objects from URI strings.

This README focuses on the `autoDetectAndDecode`, `analyzeURL`, and `checkUrl` methods, highlighting their capabilities for URI decoding, vulnerability analysis, and custom validation.

## Installation

```bash
npm i nehonix-uri-processor
```

Install the `punycode` dependency:

```bash
npm install punycode
```

## Core Methods

### autoDetectAndDecode

**Signature**:

```typescript
static autoDetectAndDecode(input: string, maxIterations?: number): string
```

**Description**:  
Automatically detects and decodes a URI string to plaintext, handling complex and nested encodings (e.g., Base64, percent-encoding, hexadecimal). This method uses advanced detection to identify encoding types and iteratively decodes until plaintext is reached or the maximum iteration limit is met. Ideal for security testing and decoding obfuscated URIs.

**Parameters**:

- `input` (`string`): The URI string to decode (e.g., `https://example.com?test=dHJ1ZQ==`).
- `maxIterations` (`number`, optional, default: `10`): Maximum decoding iterations to prevent infinite loops.

**Returns**:  
`string` - The decoded URI in plaintext (e.g., `https://example.com?test=true`).

**Example**:

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

// Decode a Base64-encoded query parameter
const decoded = NehonixURIProcessor.autoDetectAndDecode(
  "https://example.com?test=dHJ1ZQ=="
);
console.log(decoded); // https://example.com?test=true

// Decode a nested encoding
const nested = NehonixURIProcessor.autoDetectAndDecode(
  "aHR0cHM6Ly9leGFtcGxlLmNvbQ=="
);
console.log(nested); // https://example.com
```

**Notes**:

- Supports encoding types like `percentEncoding`, `base64`, `hex`, `unicode`, and more (see [Supported Encoding Types](#supported-encoding-types)).
- Use `maxIterations` to control decoding depth for deeply nested encodings.
- For detailed encoding detection, use `detectEncoding`.

### analyzeURL

**Signature**:

```typescript
static analyzeURL(url: string): { url: string; params: Record<string, { value: string; risks: string[] }> }
```

**Description**:  
Analyzes a URL to identify potentially vulnerable query parameters. It parses the URL, extracts query parameters, and evaluates them for common security risks (e.g., SQL injection, XSS, path traversal). Useful for penetration testing and vulnerability assessment.

**Parameters**:

- `url` (`string`): The URL to analyze (e.g., `https://example.com?user=admin`).

**Returns**:  
An object containing:

- `url` (`string`): The base URL.
- `params` (`Record<string, { value: string; risks: string[] }>`): Query parameters with their values and associated risks (e.g., `["sql_injection", "xss"]`).

**Example**:

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

const analysis = NehonixURIProcessor.analyzeURL(
  "https://example.com?user=admin&pass=123"
);
console.log(analysis);
// Output:
// {
//   url: "https://example.com",
//   params: {
//     user: { value: "admin", risks: ["sql_injection", "xss"] },
//     pass: { value: "123", risks: ["sql_injection"] }
//   }
// }
```

**Notes**:

- Risks are based on parameter names and values, using predefined patterns for common attack vectors.
- Combine with `checkUrl` for comprehensive URI validation and analysis.

### checkUrl

**Signature**:

```typescript
static checkUrl(url: string, options?: UrlValidationOptions): UrlCheckResult
```

**Description**:  
Validates a URI string against configurable rules, returning detailed results for each validation step. Supports validation of standard URL components (e.g., `hostname`, `pathname`), literal values, and custom properties via `fullCustomValidation` (aliased as `fcv`). Ideal for security testing, debugging, and detailed URI analysis.

**Parameters**:

- `url` (`string`): The URI string to validate (e.g., `https://example.com?test=true`).
- `options` (`UrlValidationOptions`, optional): Configuration for validation rules. Key options include:
  - `strictMode` (`boolean`, default: `false`): Requires a leading slash before query parameters.
  - `httpsOnly` (`boolean`, default: `false`): Restricts to `https://` URLs.
  - `maxUrlLength` (`number`, default: `2048`): Maximum URL length.
  - `customValidations` (`ComparisonRule[]`): Rules for validating URL components or custom properties.
  - `literalValue` (`string`): Value for `literal` comparison rules.
  - `fullCustomValidation` (`Record<string, string | number>`): Custom properties for validation.
  - `debug` (`boolean`, default: `false`): Enables debug logging.
  - See [checkUrl_method.md](#see-also) for full options.

**Returns**:  
`UrlCheckResult` - An object with:

- `isValid` (`boolean`): Overall validity.
- `validationDetails` (`object`): Results for each validation check (e.g., `protocol`, `customValidations`).
- `cause` (`string`): Reason for failure (empty if valid).

**Custom Validation with `fullCustomValidation`**:  
The `fullCustomValidation` option (aliased as `fcv`) allows users to define custom properties and validate them in `customValidations` rules. Use `fullCustomValidation.<property>` or `fcv.<property>` syntax to reference properties.

**Example**:

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

// Validate URL with custom properties
const result = NehonixURIProcessor.checkUrl("https://google.com/api", {
  literalValue: "7",
  debug: true,
  fullCustomValidation: {
    domain: "test_domain",
    testKey: "test",
  },
  customValidations: [
    ["hostname", "===", "google.com"],
    ["pathname", "===", "/api"],
    ["fullCustomValidation.domain", "===", "test_domain"],
    ["fullCustomValidation.testKey", "===", "test"],
  ],
});

console.log(result);
// Output:
// {
//   isValid: true,
//   validationDetails: {
//     customValidations: {
//       isValid: true,
//       message: "Validation passed: hostname === google.com; ...",
//       results: [
//         { isValid: true, message: "Validation passed: hostname === google.com", rule: ["hostname", "===", "google.com"] },
//         { isValid: true, message: "Validation passed: pathname === /api", rule: ["pathname", "===", "/api"] },
//         { isValid: true, message: "Validation passed: fullCustomValidation.domain === test_domain", rule: ["fullCustomValidation.domain", "===", "test_domain"] },
//         { isValid: true, message: "Validation passed: fullCustomValidation.testKey === test", rule: ["fullCustomValidation.testKey", "===", "test"] }
//       ]
//     },
//     // ...other validation details
//   },
//   cause: ""
// }
```

**Example with `fcv` Alias**:

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

const result = NehonixURIProcessor.checkUrl("https://google.com/api", {
  literalValue: "7",
  debug: true,
  fullCustomValidation: {
    ta: 2,
  },
  customValidations: [
    ["hostname", "===", "google.com"],
    ["pathname", "===", "/api"],
    ["fcv.ta", ">=", 2],
  ],
});

console.log(result);
// Output:
// {
//   isValid: true,
//   validationDetails: {
//     customValidations: {
//       isValid: true,
//       message: "Validation passed: hostname === google.com; ...",
//       results: [
//         { isValid: true, message: "Validation passed: hostname === google.com", rule: ["hostname", "===", "google.com"] },
//         { isValid: true, message: "Validation passed: pathname === /api", rule: ["pathname", "===", "/api"] },
//         { isValid: true, message: "Validation passed: fcv.ta >= 2", rule: ["fcv.ta", ">=", 2] }
//       ]
//     },
//     // ...other validation details
//   },
//   cause: ""
// }
```

**Notes**:

- Use `debug: true` to log validation details (e.g., `[DEBUG] Left Value: test_domain`).
- `literalValue` must be a `string`; use `fullCustomValidation` for `string | number` values.
- See [checkUrlMethod.md](#see-also) for detailed `UrlValidationOptions` and `UrlCheckResult` structures.

## Usage Example

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

// Decode and validate a URL
const encodedUrl = "https://example.com?data=dHJ1ZQ==";
const decoded = NehonixURIProcessor.autoDetectAndDecode(encodedUrl);
console.log(decoded); // https://example.com?data=true

// Validate with custom properties
const validation = NehonixURIProcessor.checkUrl(decoded, {
  httpsOnly: true,
  fullCustomValidation: { sessionId: "abc123" },
  customValidations: [["fcv.sessionId", "===", "abc123"]],
});
console.log(validation.isValid); // true

// Analyze for vulnerabilities
const analysis = NehonixURIProcessor.analyzeURL(decoded);
console.log(analysis.params);
// Output: { data: { value: "true", risks: ["xss"] } }
```

## Supported Encoding Types

The library supports the following encoding types for `autoDetectAndDecode`, `encode`, and `decode`:

- `percentEncoding` / `percent` / `url`
- `doublepercent` / `doublePercentEncoding`
- `base64`
- `hex` / `hexadecimal`
- `unicode`
- `htmlEntity` / `html`
- `punycode`
- `asciihex`
- `asciioct`
- `rot13`
- `base32`
- `urlSafeBase64`
- `jsEscape`
- `cssEscape`
- `utf7`
- `quotedPrintable`
- `decimalHtmlEntity`
- `rawHexadecimal`
- `jwt`

## Security Testing Features

- **URI Validation**: Use `checkUrl` to enforce strict rules and validate custom metadata.
- **Vulnerability Analysis**: `analyzeURL` identifies risky query parameters.
- **Encoding Detection**: `autoDetectAndDecode` decodes obfuscated URIs for analysis.
- **WAF Bypass**: Generate variants with `generateWAFBypassVariants` (see [Other Methods](#other-methods)).

## Other Methods

- `isValidUri(url: string, options?: UrlValidationOptions): boolean` - Checks if a URI is valid (returns `boolean`).
- `createUrl(uri: string): URL` - Creates a `URL` object from a URI.
- `encode(input: string, encodingType: string): string` - Encodes a string.
- `decode(input: string, encodingType: string, maxRecursionDepth?: number): string` - Decodes a string.
- `detectEncoding(input: string, depth?: number): { mostLikely: string; confidence: number; nestedTypes: string[] }` - Detects encoding types.
- `generateWAFBypassVariants(input: string): Record<string, string>` - Generates WAF bypass variants.

## See Also

- [checkUrlMethod.md](./checkUrlMethod.md) - Detailed `checkUrl` reference.
- NehonixURIProcessor documentation for other methods.

## License

MIT License. See LICENSE for details.
