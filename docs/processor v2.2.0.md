# NehonixURIProcessor

A comprehensive TypeScript library for detecting, decoding, and encoding various URI encoding schemes. This utility is designed for security testing, web application penetration testing, and analyzing potential attacks, with powerful auto-detection and decoding capabilities.

**Version**: 2.2.0  
**License**: MIT  
**Documentation**: [lab.nehonix.space](https://lab.nehonix.space/nehonix_viewer/_doc/NehonixUriProcessor/readme)

## Table of Contents

- [Introduction](#introduction)
- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
  - [Core Methods](#core-methods)
    - [`checkUrl(url: string, options?: object)`](#checkurlurl-string-options-object)
    - [`asyncCheckUrl(url: string, options?: object)`](#asynccheckurlurl-string-options-object)
    - [`isValidUri(url: string, options?: object)`](#isvaliduriurl-string-options-object)
    - [`asyncIsUrlValid(url: string, options?: object)`](#asyncisurlvalidurl-string-options-object)
    - [`createUrl(uri: string)`](#createurluri-string)
    - [`detectEncoding(input: string, depth?: number)`](#detectencodinginput-string-depth-number)
    - [`autoDetectAndDecode(input: string, maxIterations?: number)`](#autodetectanddecodeinput-string-maxiterations-number)
    - [`asyncAutoDetectAndDecode(input: string, maxIterations?: number, useWorker?: boolean)`](#asyncautodetectanddecodeinput-string-maxiterations-number-useworker-boolean)
    - [`scanUrl(url: string)`](#scanurlurl-string)
    - [`sanitizeInput(input: string, options?: object)`](#sanitizeinputinput-string-options-object)
    - [`needsDeepScan(input: string)`](#needsdeepscaninput-string)
    - [`detectMaliciousPatterns(input: string, options?: MaliciousPatternOptions)`](#detectmaliciouspatternsinput-string-options-maliciouspatternoptions)
  - [Framework Integrations](#framework-integrations)
    - [Express Middleware](#express-middleware)
    - [React Hook](#react-hook)
- [Supported Encoding Types](#supported-encoding-types)
- [Detection Capabilities](#detection-capabilities)
- [Security Testing Features](#security-testing-features)
- [More Information](#more-information)
- [License](#license)

## Introduction

`NehonixURIProcessor` is a powerful TypeScript library for developers and security professionals. It provides advanced tools for URI validation, encoding/decoding, and security analysis. For convenience, you can import it as `__processor__` to shorten the name (both are the same):

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";
` OR`;
import { __processor__ } from "nehonix-uri-processor";
```

## Overview

The `NehonixURIProcessor` class offers:

- **URI Validation**: Validate URIs with customizable rules and malicious pattern detection.
- **Auto-Detection and Decoding**: Decode complex URI encodings using `autoDetectAndDecode` or `asyncAutoDetectAndDecode`.
- **Encoding/Decoding**: Support for multiple encoding schemes (e.g., Base64, percent encoding, JWT).
- **Security Analysis**: Analyze URLs for vulnerabilities and generate WAF bypass variants.
- **Framework Integration**: Seamless integration with Express and React.
- **Internationalized URIs**: Handle non-ASCII characters with punycode support.

## Installation

Install the library and its dependency:

```bash
npm install nehonix-uri-processor punycode
```

## Usage

Below are examples showcasing key features:

```typescript
import {
  NehonixURIProcessor as __processor__,
  MaliciousPatternType,
} from "nehonix-uri-processor";

async function main() {
  // Validate a URI with malicious pattern detection
  const result = await __processor__.asyncCheckUrl(
    "https://example.com?user=admin' OR '1'='1",
    {
      detectMaliciousPatterns: true,
      customMaliciousPatterns: [MaliciousPatternType.ANOMALY],
      maliciousPatternSensitivity: 1.0,
      maliciousPatternMinScore: 50,
    }
  );
  console.log(result.isValid); // false (detects SQL injection attempt)

  // Decode a complex URI
  const decoded = await __processor__.asyncAutoDetectAndDecode(
    "https://example.com?data=SGVsbG8gV29ybGQ="
  );
  console.log(decoded); // https://example.com?data=Hello World

  // Check if deep scanning is needed
  const needsScan = __processor__.needsDeepScan(
    "https://example.com?user=<script>"
  );
  console.log(needsScan); // booelan
}
main();
```

## API Reference

### Core Methods

### checkUrl

```typescript
static checkUrl(url: string, options?: UrlValidationOptions): UrlCheckResult
```

### asyncCheckUrl

```typescript
static asyncCheckUrl(url: string, options?: AsyncUrlValidationOptions): Promise<AsyncUrlCheckResult>
```

### Parameters

- `url` (`string`): The URI string to validate (e.g., `https://example.com?test=true`).

- `options` (`UrlValidationOptions` or `AsyncUrlValidationOptions`, optional): Configuration object to customize validation rules. Defaults to:

  ```typescript
  {
    strictMode: false,
    allowUnicodeEscapes: true,
    rejectDuplicateParams: true,
    httpsOnly: false,
    maxUrlLength: 2048,
    allowedTLDs: [],
    allowedProtocols: ["http", "https"],
    requireProtocol: false,
    requirePathOrQuery: false,
    strictParamEncoding: false,
    rejectDuplicatedValues: false,
    debug: false,
    allowInternationalChars: false,
    // AsyncUrlValidationOptions only (for asyncCheckUrl)
    detectMaliciousPatterns: false,
    customMaliciousPatterns: [],
    maliciousPatternSensitivity: 1.0,
    maliciousPatternMinScore: 50
  }
  ```

#### UrlValidationOptions

| Option                    | Type                   | Default             | Description                                                                  |
| ------------------------- | ---------------------- | ------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `strictMode`              | `boolean`              | `false`             | Requires a leading slash before query parameters (e.g., `/path` vs. `path`). |
| `allowUnicodeEscapes`     | `boolean`              | `true`              | Allows Unicode escape sequences (e.g., `\uXXXX`) in query parameters.        |
| `rejectDuplicateParams`   | `boolean`              | `true`              | Rejects URIs with duplicate query parameter keys (e.g., `?test=1&test=2`).   |
| `rejectDuplicatedValues`  | `boolean`              | `false`             | Rejects URIs with duplicate query parameter values.                          |
| `httpsOnly`               | `boolean`              | `false`             | Restricts URIs to `https://` protocol only.                                  |
| `maxUrlLength`            | `number`               | `2048`              | Maximum URL length in characters (0 to disable).                             |
| `allowedTLDs`             | `string[]`             | `[]`                | Allowed top-level domains (empty for all).                                   |
| `allowedProtocols`        | `string[]`             | `["http", "https"]` | Allowed protocols (e.g., `http`, `https`).                                   |
| `requireProtocol`         | `boolean`              | `false`             | Requires an explicit protocol (e.g., `http://` or `https://`).               |
| `requirePathOrQuery`      | `boolean`              | `false`             | Requires a path or query string (e.g., `/path` or `?query=test`).            |
| `strictParamEncoding`     | `boolean`              | `false`             | Enforces strict URI encoding for query parameters.                           |
| `debug`                   | `boolean`              | `false`             | Enables debug logging for custom validations, printing actual values.        |
| `allowInternationalChars` | `boolean`              | `false`             | Allows non-ASCII characters in URIs (normalized with punycode).              |
| `customValidations`       | `ComparisonRule[]`     | `undefined`         | Array of custom validation rules for URL components or custom properties.    |
| `literalValue`            | `"@this"               | string              | number`                                                                      | `"@this"`                                                                     | Value for `literal` rules in `customValidations`. Defaults to input `url`. |
| `fullCustomValidation`    | `Record<string, string | number>`            | `undefined`                                                                  | Defines custom properties for validation (e.g., `{ domain: "test_domain" }`). |

#### AsyncUrlValidationOptions (extends UrlValidationOptions)

| Option                        | Type                     | Default | Description                                                         |
| ----------------------------- | ------------------------ | ------- | ------------------------------------------------------------------- |
| `detectMaliciousPatterns`     | `boolean`                | `false` | Enables detection of malicious patterns (e.g., SQL injection, XSS). |
| `customMaliciousPatterns`     | `MaliciousPatternType[]` | `[]`    | Specifies custom malicious patterns to detect.                      |
| `maliciousPatternSensitivity` | `number`                 | `1.0`   | Sensitivity for malicious pattern detection (0.0 to 1.0).           |
| `maliciousPatternMinScore`    | `number`                 | `50`    | Minimum score for malicious pattern detection.                      |

#### ComparisonRule

A `ComparisonRule` defines a validation rule for a URL component or custom property:

```typescript
type ComparisonRule = [
  ValidUrlComponents | custumValidUriComponent,
  comparisonOperator,
  string | number
];
```

- `ValidUrlComponents`:

  ```typescript
  type ValidUrlComponents =
    | "href"
    | "origin"
    | "protocol"
    | "username"
    | "password"
    | "host"
    | "hostname"
    | "port"
    | "pathname"
    | "search"
    | "hash";
  ```

- `custumValidUriComponent`:

  ```typescript
  type custumValidUriComponent = "fullCustomValidation" | "literal";
  ```

- `comparisonOperator`:
  ```typescript
  type comparisonOperator =
    | "==="
    | "=="
    | "<="
    | ">="
    | "!="
    | "!=="
    | "<"
    | ">";
  ```

Rules can reference:

- Standard URL components (e.g., `["hostname", "===", "example.com"]`).
- Literal values (e.g., `["literal", "===", "nehonix.space"]` with `literalValue` set).
- Custom properties (e.g., `["fullCustomValidation.domain", "===", "test_domain"]` or `["fcv.domain", "===", "test_domain"]`).

### Return Value

#### checkUrl

Returns a `UrlCheckResult` object:

```typescript
export interface UrlCheckResult {
  /**
   * Indicates whether the URL is valid based on all validation checks.
   * `true` if all checks pass, `false` if any check fails.
   */
  isValid: boolean;

  /**
   * Return the reason of failing
   */
  cause?: string;

  /**
   * Contains detailed results for each validation check performed on the URL.
   * Each property corresponds to a specific validation aspect and is optional,
   * as not all validations may be relevant depending on the provided options.
   */
  validationDetails: {
    customValidations?: {
      isValid: boolean;
      message: string;
      results: {
        isValid: boolean;
        message: string;
        rule: ComparisonRule;
      }[];
    };
    length?: {
      isValid: boolean;
      message?: string;
      actualLength?: number;
      maxLength?: number | "NO_LIMIT";
    };
    emptyCheck?: {
      isValid: boolean;
      message?: string;
    };
    protocol?: {
      isValid: boolean;
      message?: string;
      detectedProtocol?: string;
      allowedProtocols?: string[];
    };
    httpsOnly?: {
      isValid: boolean;
      message?: string;
    };
    domain?: {
      isValid: boolean;
      message?: string;
      hostname?: string;
      error?: string;
      type?: "INV_DOMAIN_ERR" | "INV_STRUCTURE" | "ERR_UNKNOWN";
    };
    tld?: {
      isValid: boolean;
      message?: string;
      detectedTld?: string;
      allowedTlds?: string[];
    };
    pathOrQuery?: {
      isValid: boolean;
      message?: string;
    };
    strictMode?: {
      isValid: boolean;
      message?: string;
    };
    querySpaces?: {
      isValid: boolean;
      message?: string;
    };
    paramEncoding?: {
      isValid: boolean;
      message?: string;
      invalidParams?: string[];
    };
    duplicateParams?: {
      isValid: boolean;
      message?: string;
      duplicatedKeys?: string[];
    };
    duplicateValues?: {
      isValid: boolean;
      message?: string;
      duplicatedValues?: string[];
    };
    unicodeEscapes?: {
      isValid: boolean;
      message?: string;
    };
    parsing?: {
      isValid: boolean;
      message?: string;
    };
    internationalChars?: {
      isValid: boolean;
      message: string;
      containsNonAscii?: boolean;
      containsPunycode?: boolean;
    };
  };
}
```

#### asyncCheckUrl

Returns a `Promise<AsyncUrlCheckResult>`, which extends `UrlCheckResult` with `maliciousPatterns` in `validationDetails`:

```typescript
interface DetectedPattern {
  type: string; // e.g., "XSS", "SQL_INJECTION"
  value: string; // The detected malicious content
  score: number; // Severity score (0-100)
}

export type AsyncUrlCheckResult = Omit<UrlCheckResult, "validationDetails"> & {
  validationDetails: UrlCheckResult["validationDetails"] & {
    maliciousPatterns?: {
      isValid?: boolean;
      message?: string;
      error?: string;
      detectedPatterns?: DetectedPattern[];
      score?: number;
      confidence?: string;
      recommendation?: string;
    };
  };
};
```

- `isValid`: `true` if the URI passes all validation rules, `false` otherwise.
- `validationDetails`: Detailed results for each validation check.
- `cause`: Reason for failure (empty if `isValid` is `true`).
- `maliciousPatterns` (asyncCheckUrl only): Included in `validationDetails`, containing results of malicious pattern detection (e.g., XSS, SQL injection).

## Custom Validation with `fullCustomValidation`

The `fullCustomValidation` option (aliased as `fcv`) allows defining custom properties for validation alongside standard URL components:

- **Define Custom Properties**: Provide a `fullCustomValidation` object (e.g., `{ domain: "test_domain", version: 1.2 }`).
- **Reference in Rules**: Use `fullCustomValidation.<property>` or `fcv.<property>` in `customValidations` (e.g., `["fcv.domain", "===", "test_domain"]`).
- **Validate**: Compares the property’s value against the rule’s value using the specified operator.

## literalValue Usage

The `literalValue` option specifies the value for `literal` rules in `customValidations`. It defaults to `"@this"`, which uses the input `url`. For specific comparisons (e.g., `["literal", "===", "nehonix.space"]`), set `literalValue` explicitly.

## Question: Synchronous (checkUrl) vs. Asynchronous (asyncCheckUrl) - Which is Best and When?

### Question

When should you use `checkUrl` versus `asyncCheckUrl`? How do their performance characteristics and use cases differ, especially regarding execution time and resource usage?

### Answer

Both `checkUrl` and `asyncCheckUrl` validate URIs, but their execution models and capabilities differ, impacting their suitability for various scenarios:

- **checkUrl (Synchronous)**:

  - **Pros**:
    - Faster for simple validations, completing in microseconds, as it avoids Promise overhead.
    - Ideal for lightweight, single-threaded applications or quick checks in non-async contexts (e.g., CLI tools, synchronous middleware).
    - Lower memory overhead due to synchronous execution.
  - **Cons**:
    - Lacks malicious pattern detection, limiting its use in security-critical applications.
    - Can block the main thread, causing delays in event-driven environments (e.g., Node.js servers) for complex or long URLs.
  - **Best Use Cases**:
    - Quick validations in synchronous codebases.
    - Non-security-critical scenarios.
    - Example: Validating static URLs in a build script.
  - **Performance**: Microseconds for simple URLs, but may scale poorly with complex rules.

- **asyncCheckUrl (Asynchronous)**:

  - **Pros**:
    - Includes malicious pattern detection, critical for security-focused applications (e.g., detecting XSS, SQL injection).
    - Non-blocking, ideal for event-driven environments like web servers or React apps.
    - Scales better for complex validations or long URLs by leveraging async processing.
  - **Cons**:
    - Slower due to Promise overhead, typically milliseconds.
    - Higher memory usage due to async context and pattern analysis.
  - **Best Use Cases**:
    - Security testing requiring malicious pattern detection.
    - Async workflows in Node.js or front-end apps.
    - Example: Validating user-submitted URLs in an Express API.
  - **Performance**: Milliseconds, but non-blocking, suitable for high-concurrency scenarios.

- **When to Choose**:

  - Use `checkUrl` for fast, non-security-critical validations in synchronous environments.
  - Use `asyncCheckUrl` for security-critical applications or async environments where non-blocking is essential.
  - **Precious Time to Use**:
    - `checkUrl` saves microseconds in low-latency, synchronous scenarios.
    - `asyncCheckUrl` is worth the millisecond overhead for security and non-blocking behavior.

- **Recommendation**:
  - In modern web applications, prefer `asyncCheckUrl` for its security features and non-blocking nature. Use `checkUrl` only in specific synchronous, non-security-critical cases.

## Example Usage

### Validating with checkUrl

````typescript
import { __processor__ } from "nehonix-uri-processor";

const result = __processor__.checkUrl("https://google.com/api", {
  literalValue: "nehonix.space",
  debug: true,
  fullCustomValidation: { domain: "test_domain", version: 1.2 },
  customValidations: [
    ["hostname", "===", "google.com"],
    ["pathname", "===", "/api"],
    ["literal", "===", "nehonix.space"],
    ["fcv.domain", "===", "test_domain"],
    ["fcv.version", ">=", 1.0],
  ],
});


#### `isValidUri(url: string, options?: object)`

Checks if a string is a valid URI with configurable rules and malicious pattern detection.

- **Parameters**:

  - `url` (`string`): The URI to validate.
  - `options` (optional): Includes `detectMaliciousPatterns`, `allowInternationalChars`, etc.

- **Returns**: `boolean`.

- **Example**:

```typescript
const isValid = __processor__.isValidUri(
  "https://xn--n3h.com?greeting=こんにちは",
  {
    allowInternationalChars: true,
  }
);
console.log(isValid); // true
````

#### `asyncIsUrlValid(url: string, options?: object)`

Asynchronously validates a URI string, similar to `isValidUri` but designed for async workflows.

- **Parameters**:

  - `url` (`string`): The URI to validate.
  - `options` (optional): Same as `isValidUri`.

- **Returns**: `Promise<boolean>`.

- **Example**:

```typescript
const isValid = await __processor__.asyncIsUrlValid("https://example.com", {
  httpsOnly: true,
});
console.log(isValid); // true
```

#### `createUrl(uri: string)`

Creates a native `URL` object from a URI string.

- **Returns**: `URL`.

- **Example**:

```typescript
const url = __processor__.createUrl("https://example.com/path");
console.log(url.pathname); // /path
```

#### `detectEncoding(input: string, depth?: number)`

Detects encoding types in a URI string, with optional recursion for nested encodings.

- **Returns**: `{ mostLikely: string, confidence: number, nestedTypes: string[] }`.

- **Example**:

```typescript
const detection = __processor__.detectEncoding("hello%20world");
console.log(detection.mostLikely); // percentEncoding
```

#### `autoDetectAndDecode(input: string, maxIterations?: number)`

**Recommended**: Automatically detects and decodes a URI to plaintext.

- **Parameters**:

  - `input` (`string`): The URI to decode.
  - `maxIterations` (`number`, default: `10`): Limits decoding iterations.

- **Returns**: `string` (decoded plaintext).

- **Example**:

```typescript
const decoded = __processor__.autoDetectAndDecode(
  "https://example.com?test=dHJ1ZQ=="
);
console.log(decoded); // https://example.com?test=true
```

#### `asyncAutoDetectAndDecode(input: string, maxIterations?: number, useWorker?: boolean)`

Asynchronously decodes a URI to plaintext, suitable for complex URIs.

- **Returns**: `Promise<string>`.

- **Example**:

```typescript
const decoded = await __processor__.asyncAutoDetectAndDecode(
  "https://example.com?data=SGVsbG8gV29ybGQ="
);
console.log(decoded); // https://example.com?data=Hello World
```

#### `scanUrl(url: string)`

Generates a security report for a URI, including vulnerability analysis and recommendations.

- **Returns**: `{ analysis, variants, recommendations }`.

- **Example**:

```typescript
const report = __processor__.scanUrl(
  "https://example.com?user=admin' OR '1'='1"
);
console.log(report.recommendations); // ["Sanitize parameter \"user\" to prevent SQL injection..."]
```

#### `sanitizeInput(input: string, options?: object)`

Sanitizes input by removing potentially malicious patterns. **Note**: This method is not stable and should be used cautiously.

- **Parameters**:

  - `input` (`string`): The string to sanitize.
  - `options` (optional): Additional sanitization options.

- **Returns**: `string` (sanitized string).

- **Example**:

```typescript
const sanitized = __processor__.sanitizeInput("<script>alert('xss')</script>");
console.log(sanitized); // Sanitized string with malicious content removed
```

#### `needsDeepScan(input: string)`

Lightweight check to determine if a string requires deep scanning. Use as a pre-filter before full pattern detection.

- **Parameters**:

  - `input` (`string`): The string to check.

- **Returns**: `boolean` (whether deep scanning is needed).

- **Example**:

```typescript
const needsScan = __processor__.needsDeepScan(
  "https://example.com?user=<script>"
);
console.log(needsScan); // true
```

#### `detectMaliciousPatterns(input: string, options?: MaliciousPatternOptions)`

Analyzes input for malicious patterns and returns detailed detection results.

- **Parameters**:

  - `input` (`string`): The string to analyze.
  - `options` (`MaliciousPatternOptions`, optional): Configuration for detection (e.g., sensitivity, patterns).

- **Returns**: Detailed analysis result (type depends on `NSS.detectMaliciousPatterns`).

- **Example**:

```typescript
const result = __processor__.detectMaliciousPatterns(
  "https://example.com?user=admin' OR '1'='1",
  { sensitivity: 1.0 }
);
console.log(result); // Detailed malicious pattern analysis
```

### Framework Integrations

#### Express Middleware

Validate and decode URIs in Express applications.

- **Setup**:

```typescript
import express from "express";
import { nehonixShieldMiddleware } from "nehonix-uri-processor";

const app = express();
app.use(nehonixShieldMiddleware({ blockOnMalicious: true }));
app.get("/", (req, res) => res.send("Hello world"));
app.listen(3000, () => console.log("Server running on port 3000"));
```

#### React Hook

Validate and decode URIs in React applications.

- **Usage**:

```typescript
import { NehonixShieldProvider, useNehonixShield } from "nehonix-uri-processor";

const App = () => (
  <NehonixShieldProvider>
    <SecurityDemo />
  </NehonixShieldProvider>
);

const SecurityDemo = () => {
  const { scanUrl } = useNehonixShield();
  const handleAnalyze = async () => {
    const result = await scanUrl("https://example.com?category=books");
    console.log(result);
  };
  return <button onClick={handleAnalyze}>Analyze URL</button>;
};
```

## Supported Encoding Types

- `percentEncoding` / `url`
- `doublepercent`
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

## Detection Capabilities

The library detects all supported encoding types, including nested encodings, with high accuracy.

## Security Testing Features

- **Parameter Analysis**: Detects SQL injection, XSS, and path traversal patterns.
- **WAF Bypass**: Generates encoded variants for testing.
- **Malicious Pattern Detection**: Configurable sensitivity for detecting attacks.
- **Sanitization**: Sanitizes harmful inputs (use `sanitizeInput` cautiously due to instability).

## More Information

- Detailed `checkUrl` and `asyncCheckUrl` documentation: [checkUrlMethod.md](./docs/checkUrlMethod.md)
- Full documentation: [lab.nehonix.space](https://lab.nehonix.space)
- Changelog: [changelog.md](./docs/changelog.md)
- Previous versions:
  - [v2.1.2](./docs/readme-v2.1.2.md)
  - [v2.0.9](./docs/readmeV2.0.9.md)

## License

MIT
