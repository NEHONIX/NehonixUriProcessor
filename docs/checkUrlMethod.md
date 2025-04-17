# NehonixURIProcessor: checkUrl Method

## Overview

The `checkUrl` method in the `NehonixURIProcessor` library validates a URI string against a set of configurable rules, making it ideal for security testing, web application penetration testing, and URI analysis. It supports validation of standard URL components (e.g., `hostname`, `pathname`), literal values, and custom properties defined via the `fullCustomValidation` option. This method provides detailed validation results, including reasons for failure, to aid in debugging and analysis.

**Version**: 2.0.9\
**License**: MIT

## Method Signature

```typescript
static checkUrl(url: string, options?: UrlValidationOptions): UrlCheckResult
```

### Parameters

- `url` (`string`): The URI string to validate (e.g., `https://example.com?test=true`).

- `options` (`UrlValidationOptions`, optional): Configuration object to customize validation rules. Defaults to:

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
    debug: false
  }
  ```

#### UrlValidationOptions

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `strictMode` | `boolean` | `false` | Requires a leading slash before query parameters (e.g., `/path` vs. `path`). |
| `allowUnicodeEscapes` | `boolean` | `true` | Allows Unicode escape sequences (e.g., `\uXXXX`) in query parameters. |
| `rejectDuplicateParams` | `boolean` | `true` | Rejects URIs with duplicate query parameter keys (e.g., `?test=1&test=2`). |
| `rejectDuplicatedValues` | `boolean` | `false` | Rejects URIs with duplicate query parameter values. |
| `httpsOnly` | `boolean` | `false` | Restricts URIs to `https://` protocol only. |
| `maxUrlLength` | `number` | `2048` | Maximum URL length in characters (0 to disable). |
| `allowedTLDs` | `string[]` | `[]` | Allowed top-level domains (empty for all). |
| `allowedProtocols` | `string[]` | `["http", "https"]` | Allowed protocols (e.g., `http`, `https`). |
| `requireProtocol` | `boolean` | `false` | Requires an explicit protocol (e.g., `http://` or `https://`). |
| `requirePathOrQuery` | `boolean` | `false` | Requires a path or query string (e.g., `/path` or `?query=test`). |
| `strictParamEncoding` | `boolean` | `false` | Enforces strict URI encoding for query parameters. |
| `debug` | `boolean` | `false` | Enables debug logging for custom validations, printing actual values. |
| `customValidations` | `ComparisonRule[]` | `undefined` | Array of custom validation rules for URL components or custom properties. |
| `literalValue` | `string` | `undefined` | Value to compare against `literal` rules in `customValidations`. |
| `fullCustomValidation` | \`Record&lt;string, string | number&gt;\` | `undefined` |

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
  type comparisonOperator = "===" | "==" | "<=" | ">=" | "!=" | "!==" | "<" | ">";
  ```

Rules can reference:

- Standard URL components (e.g., `["hostname", "===", "example.com"]`).
- Literal values (e.g., `["literal", "==", "value"]` with `literalValue: "value"`).
- Custom properties (e.g., `["fullCustomValidation.domain", "==", "test_domain"]` or `["fcv.domain", "==", "test_domain"]`).

### Return Value

The method returns a `UrlCheckResult` object:

```typescript
interface UrlCheckResult {
  isValid: boolean;
  validationDetails: {
    emptyCheck?: { isValid: boolean; message: string };
    length?: { isValid: boolean; message: string; actualLength: number; maxLength: number };
    protocol?: { isValid: boolean; message: string; detectedProtocol?: string; allowedProtocols?: string[] };
    httpsOnly?: { isValid: boolean; message: string };
    domain?: { isValid: boolean; type: string; message: string; hostname: string };
    tld?: { isValid: boolean; message: string; detectedTld?: string; allowedTlds?: string[] };
    pathOrQuery?: { isValid: boolean; message: string };
    strictMode?: { isValid: boolean; message: string };
    querySpaces?: { isValid: boolean; message: string };
    paramEncoding?: { isValid: boolean; message: string; invalidParams?: string[] };
    duplicateParams?: { isValid: boolean; message: string; duplicatedKeys: string[] };
    duplicateValues?: { isValid: boolean; message: string; duplicatedValues: string[] };
    unicodeEscapes?: { isValid: boolean; message: string };
    parsing?: { isValid: boolean; message: string };
    customValidations?: {
      isValid: boolean;
      message: string;
      results: {
        isValid: boolean;
        message: string;
        rule: ComparisonRule;
      }[];
    };
  };
  cause: string;
}
```

- `isValid`: `true` if the URI passes all validation rules, `false` otherwise.
- `validationDetails`: Object containing detailed results for each validation check.
- `cause`: A string describing the reason for failure (empty if `isValid` is `true`).

## Custom Validation with `fullCustomValidation`

The `fullCustomValidation` option (aliased as `fcv`) allows users to define custom properties and validate them alongside standard URL components. Users can:

- **Define Custom Properties**: Provide a `fullCustomValidation` object with key-value pairs (e.g., `{ domain: "test_domain", testKey: "test" }`).
- **Reference in Rules**: Use `fullCustomValidation.<property>` or `fcv.<property>` in `customValidations` rules (e.g., `["fullCustomValidation.domain", "===", "test_domain"]` or `["fcv.domain", "===", "test_domain"]`).
- **Validate**: The method compares the property’s value against the rule’s value using the specified operator.

### Example Usage

#### Validating URL Components and Custom Properties

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

const uriAnalysed = NehonixURIProcessor.checkUrl("https://google.com/api", {
  literalValue: "7",
  debug: true,
  fullCustomValidation: {
    domain: "test_domain",
    testKey: "test"
  },
  customValidations: [
    ["hostname", "===", "google.com"],
    ["pathname", "===", "/api"],
    ["fullCustomValidation.domain", "===", "test_domain"],
    ["fullCustomValidation.testKey", "===", "test"]
  ]
});

console.log(uriAnalysed);
/* Output:
{
  isValid: true,
  validationDetails: {
    emptyCheck: { isValid: true, message: "URL contains valid content" },
    parsing: { isValid: true, message: "URL parsed successfully" },
    customValidations: {
      isValid: true,
      message: "Validation passed: hostname === google.com; Validation passed: pathname === /api; Validation passed: fullCustomValidation.domain === test_domain; Validation passed: fullCustomValidation.testKey === test",
      results: [
        { isValid: true, message: "Validation passed: hostname === google.com", rule: ["hostname", "===", "google.com"] },
        { isValid: true, message: "Validation passed: pathname === /api", rule: ["pathname", "===", "/api"] },
        { isValid: true, message: "Validation passed: fullCustomValidation.domain === test_domain", rule: ["fullCustomValidation.domain", "===", "test_domain"] },
        { isValid: true, message: "Validation passed: fullCustomValidation.testKey === test", rule: ["fullCustomValidation.testKey", "===", "test"] }
      ]
    },
    // ...other validation details
  },
  cause: ""
}
*/
```

#### Using the `fcv` Alias with Numeric Comparison

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

const uriAnalysed = NehonixURIProcessor.checkUrl("https://google.com/api", {
  literalValue: "7",
  debug: true,
  fullCustomValidation: {
    ta: 2
  },
  customValidations: [
    ["hostname", "===", "google.com"],
    ["pathname", "===", "/api"],
    ["fcv.ta", ">=", 2]
  ]
});

console.log(uriAnalysed);
/* Output:
{
  isValid: true,
  validationDetails: {
    emptyCheck: { isValid: true, message: "URL contains valid content" },
    parsing: { isValid: true, message: "URL parsed successfully" },
    customValidations: {
      isValid: true,
      message: "Validation passed: hostname === google.com; Validation passed: pathname === /api; Validation passed: fcv.ta >= 2",
      results: [
        { isValid: true, message: "Validation passed: hostname === google.com", rule: ["hostname", "===", "google.com"] },
        { isValid: true, message: "Validation passed: pathname === /api", rule: ["pathname", "===", "/api"] },
        { isValid: true, message: "Validation passed: fcv.ta >= 2", rule: ["fcv.ta", ">=", 2] }
      ]
    },
    // ...other validation details
  },
  cause: ""
}
*/
```

#### Handling Validation Failures

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

const uriAnalysed = NehonixURIProcessor.checkUrl("https://google.com/api", {
  customValidations: [
    ["fullCustomValidation.domain", "===", "test_domain"]
  ]
});

console.log(uriAnalysed);
/* Output:
{
  isValid: false,
  validationDetails: {
    emptyCheck: { isValid: true, message: "URL contains valid content" },
    parsing: { isValid: true, message: "URL parsed successfully" },
    customValidations: {
      isValid: false,
      message: "Full custom validation failed: The fullCustomValidation option is required",
      results: [
        {
          isValid: false,
          message: "Full custom validation failed: The fullCustomValidation option is required",
          rule: ["fullCustomValidation.domain", "===", "test_domain"]
        }
      ]
    },
    // ...other validation details
  },
  cause: "The fullCustomValidation option is required for 'fullCustomValidation' comparison rules"
}
*/
```

## Notes

- **Debug Logging**: Enable `debug: true` to log detailed validation information, including actual values for `customValidations` rules (e.g., `[DEBUG] Left Value: test_domain`).
- **Type Safety**: The `literalValue` option must be a `string`. Use `fullCustomValidation` for `string` or `number` values in custom properties.
- **FCV Alias**: Both `fullCustomValidation.<property>` and `fcv.<property>` are supported in `customValidations` rules, providing flexibility.
- **Error Messages**: Validation failures provide detailed `cause` and `validationDetails` to aid debugging, especially for `fullCustomValidation` rules.

## Security Considerations

The `checkUrl` method is designed for security testing and URI validation:

- Use `customValidations` to enforce specific constraints on URL components or custom metadata.
- Combine with `analyzeURL` to identify vulnerable parameters.
- Leverage `fullCustomValidation` to validate application-specific metadata (e.g., session IDs, version numbers) alongside URIs.
- Enable `strictMode`, `httpsOnly`, or `strictParamEncoding` for stricter validation in high-security contexts.

## Example Integration with Security Testing

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

// Validate a URL with custom metadata for security testing
const result = NehonixURIProcessor.checkUrl("https://example.com/login", {
  httpsOnly: true,
  strictParamEncoding: true,
  fullCustomValidation: {
    sessionId: "abc123",
    version: 1.2
  },
  customValidations: [
    ["pathname", "===", "/login"],
    ["fcv.sessionId", "===", "abc123"],
    ["fcv.version", ">=", 1.0]
  ]
});

if (!result.isValid) {
  console.error(`Validation failed: ${result.cause}`);
  console.log(result.validationDetails);
} else {
  console.log("URL and custom metadata are valid");
}
```

## See Also

- NehonixURIProcessor README
- autoDetectAndDecode
- analyzeURL

## License

MIT License. See LICENSE for details.