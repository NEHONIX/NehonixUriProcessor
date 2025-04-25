# NehonixURIProcessor: checkUrl and asyncCheckUrl Methods

## Overview

The `checkUrl` and `asyncCheckUrl` methods in the `NehonixURIProcessor` library validate URI strings against configurable rules, making them ideal for security testing, web application penetration testing, and URI analysis. Both methods support validation of standard URL components (e.g., `hostname`, `pathname`), literal values, and custom properties via the `fullCustomValidation` option. The key difference is that `checkUrl` operates synchronously, while `asyncCheckUrl` is asynchronous and includes malicious pattern detection, with results accessible via `validationDetails.maliciousPatterns`.

**Version**: 2.2.0  
**License**: MIT

## Method Signatures

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

```typescript
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

console.log(result);
/* Output:
{
  isValid: false,
  validationDetails: {
    emptyCheck: { isValid: true, message: "URL contains valid content" },
    parsing: { isValid: true, message: "URL parsed successfully" },
    customValidations: {
      isValid: false,
      message: "Validation passed: hostname === google.com; Validation passed: pathname === /api; Validation failed: literal === nehonix.space; Validation passed: fcv.domain === test_domain; Validation passed: fcv.version >= 1.0",
      results: [
        { isValid: true, message: "Validation passed: hostname === google.com", rule: ["hostname", "===", "google.com"] },
        { isValid: true, message: "Validation passed: pathname === /api", rule: ["pathname", "===", "/api"] },
        { isValid: false, message: "Validation failed: literal === nehonix.space", rule: ["literal", "===", "nehonix.space"] },
        { isValid: true, message: "Validation passed: fcv.domain === test_domain", rule: ["fcv.domain", "===", "test_domain"] },
        { isValid: true, message: "Validation passed: fcv.version >= 1.0", rule: ["fcv.version", ">=", 1.0] }
      ]
    },
    // ...other validation details
  },
  cause: "Validation failed: literal === nehonix.space"
}
*/
```

### Validating with asyncCheckUrl

```typescript
import { __processor__ } from "nehonix-uri-processor";

const result = await __processor__.asyncCheckUrl(
  "https://example.com?user=<script>",
  {
    detectMaliciousPatterns: true,
    customValidations: [
      ["pathname", "===", "/"],
      ["literal", "===", "@this"],
    ],
  }
);

console.log(result);
/* Output:
{
  isValid: false,
  validationDetails: {
    emptyCheck: { isValid: true, message: "URL contains valid content" },
    parsing: { isValid: true, message: "URL parsed successfully" },
    customValidations: {
      isValid: false,
      message: "Validation failed: pathname === /; Validation passed: literal === @this",
      results: [
        { isValid: false, message: "Validation failed: pathname === /", rule: ["pathname", "===", "/"] },
        { isValid: true, message: "Validation passed: literal === @this", rule: ["literal", "===", "@this"] }
      ]
    },
    maliciousPatterns: {
      isValid: false,
      message: "Malicious pattern detected",
      detectedPatterns: [{ type: "XSS", value: "<script>", score: 90 }],
      score: 90,
      confidence: "High",
      recommendation: "Sanitize parameter 'user' to prevent XSS"
    },
    // ...other validation details
  },
  cause: "Validation failed: pathname === /"
}
*/
```

## Notes

- **Debug Logging**: Set `debug: true` to log detailed validation information (e.g., `[DEBUG] Left Value: test_domain`).
- **Type Safety**: `literalValue` accepts `"@this"`, `string`, or `number`. Use `fullCustomValidation` for custom property validations.
- **FCV Alias**: Both `fullCustomValidation.<property>` and `fcv.<property>` are supported in `customValidations`.
- **Error Messages**: Failures provide detailed `cause` and `validationDetails` for debugging.
- **International Characters**: Enable `allowInternationalChars` for non-ASCII URIs (uses punycode).
- **Malicious Patterns**: Only `asyncCheckUrl` populates `validationDetails.maliciousPatterns` when `detectMaliciousPatterns` is enabled.

## Security Considerations

Both methods are designed for security testing and URI validation:

- Use `customValidations` to enforce constraints on URL components or metadata.
- Leverage `asyncCheckUrl` for malicious pattern detection (e.g., SQL injection, XSS).
- Combine with `scanUrl` or `detectMaliciousPatterns` to identify vulnerable parameters.
- Use `fullCustomValidation` to validate application-specific metadata (e.g., session IDs, versions).
- Enable `strictMode`, `httpsOnly`, or `strictParamEncoding` for high-security contexts.

## Example Integration with Security Testing

```typescript
import { __processor__ } from "nehonix-uri-processor";

async function validateLoginUrl(url: string) {
  const result = await __processor__.asyncCheckUrl(url, {
    httpsOnly: true,
    strictParamEncoding: true,
    detectMaliciousPatterns: true,
    fullCustomValidation: { sessionId: "abc123", version: 1.2 },
    customValidations: [
      ["pathname", "===", "/login"],
      ["fcv.sessionId", "===", "abc123"],
      ["fcv.version", ">=", 1.0],
    ],
  });

  if (!result.isValid) {
    console.error(`Validation failed: ${result.cause}`);
    console.log(result.validationDetails.maliciousPatterns); // Check for malicious patterns
  } else {
    console.log("URL and metadata are valid");
  }
}

validateLoginUrl("https://example.com/login?user=admin");
```

## See Also

- NehonixURIProcessor README
- `autoDetectAndDecode`
- `scanUrl`
- `detectMaliciousPatterns`

## License

MIT License. See LICENSE for details.
