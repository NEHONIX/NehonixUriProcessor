# NehonixURIProcessor

A comprehensive TypeScript library for detecting, decoding, and encoding various URI encoding schemes. This utility is designed for security testing, web application penetration testing, and analyzing potential attacks, with powerful auto-detection and decoding capabilities.

## Overview

The `NehonixURIProcessor` class provides methods to:

- Validate URIs with configurable rules
- Automatically detect and decode encoding types in URIs with the recommended `autoDetectAndDecode` method
- Encode and decode strings using a wide range of encoding schemes
- Analyze URLs for potential security vulnerabilities
- Generate encoding variations for Web Application Firewall (WAF) bypass testing
- Create `URL` objects from URI strings

## Installation

```bash
npm i nehonix-uri-processor
```

Make sure to also install the `punycode` dependency:

```bash
npm install punycode
```

## Usage

```typescript
import { NehonixURIProcessor } from "nehonix-uri-processor";

// Validate a URI
const isValid = NehonixURIProcessor.isValidUri("https://example.com?test=true");
console.log(isValid); // true

// Recommended: Automatically detect and decode with autoDetectAndDecode
const encodedURL = "https://example.com/page?param=dHJ1ZQ==";
const decoded = NehonixURIProcessor.autoDetectAndDecode(encodedURL);
console.log(decoded); // https://example.com/page?param=true

// Encode a string using a specific encoding type
const encoded = NehonixURIProcessor.encode("hello world", "rot13");
console.log(encoded); // uryyb jbeyq

// Generate WAF bypass variants
const variants = NehonixURIProcessor.generateWAFBypassVariants("<script>");
console.log(variants); // { percent: "%3Cscript%3E", base64: "PHNjcmlwdD4=", ... }

// Create a URL object
const urlObj = NehonixURIProcessor.createUrl("https://example.com");
console.log(urlObj.href); // https://example.com/
```

## API Reference

### Core Methods

#### `isValidUri(url: string, options?: object)`

Checks whether a string is a valid URI with configurable validation rules.

- **Parameters**:

  - `url` - The string to validate (e.g., `https://example.com?test=true`)
  - `options` (optional):
    - `strictMode` (boolean, default: `false`) - Requires a leading slash before query parameters
    - `allowUnicodeEscapes` (boolean, default: `true`) - Allows Unicode escape sequences in query parameters
    - `rejectDuplicateParams` (boolean, default: `true`) - Rejects URIs with duplicate query parameter keys
    - `rejectDuplicatedValues` (boolean, default: `false`) - Rejects URIs with duplicate query parameter values
    - `httpsOnly` (boolean, default: `false`) - Only allows `https://` URLs
    - `maxUrlLength` (number, default: `2048`) - Maximum URL length (0 to disable)
    - `allowedTLDs` (string[], default: `[]`) - Allowed top-level domains (empty for all)
    - `allowedProtocols` (string[], default: `['http', 'https']`) - Allowed protocols
    - `requireProtocol` (boolean, default: `false`) - Requires an explicit protocol
    - `requirePathOrQuery` (boolean, default: `false`) - Requires a path or query string
    - `strictParamEncoding` (boolean, default: `false`) - Validates proper URI encoding

- **Returns**: `boolean` - `true` if the URI is valid, `false` otherwise

- **Example**:

  ```typescript
  const isValid = NehonixURIProcessor.isValidUri(
    "https://example.com?test=thank%20you",
    { httpsOnly: true }
  );
  console.log(isValid); // true

  const isInvalid = NehonixURIProcessor.isValidUri(
    "https://example.com?test=thank you"
  );
  console.log(isInvalid); // false (unencoded space)
  ```

#### `createUrl(uri: string)`

Creates a `URL` object from a URI string.

- **Parameters**: `uri` - The URI string (e.g., `https://example.com`)

- **Returns**: `URL` - A native `URL` object

- **Example**:
  ```typescript
  const url = NehonixURIProcessor.createUrl(
    "https://example.com/path?query=test"
  );
  console.log(url.pathname); // /path
  console.log(url.search); // ?query=test
  ```

#### `detectEncoding(input: string, depth?: number)`

Detects the encoding type(s) of a URI string, with optional recursion for nested encodings.

- **Parameters**:

  - `input` - The URI string to analyze
  - `depth` (optional) - Recursion depth for nested encodings

- **Returns**: An object containing:

  - `mostLikely`: The most probable encoding type
  - `confidence`: Confidence score (0-1)
  - `nestedTypes`: Array of detected nested encoding types

- **Example**:
  ```typescript
  const detection = NehonixURIProcessor.detectEncoding("hello%20world");
  console.log(detection); // { mostLikely: "percentEncoding", confidence: 0.95, nestedTypes: [] }
  ```

#### `autoDetectAndDecode(input: string, maxIterations = 10)`

**Recommended**: Automatically detects and decodes a URI string to plaintext with advanced intelligence and performance. This method is smarter and more powerful than the deprecated `detectAndDecode`, handling complex and nested encodings efficiently.

- **Parameters**:

  - `input` - The URI string to decode
  - `maxIterations` (optional, default: `10`) - Maximum decoding iterations to prevent infinite loops

- **Returns**: The decoded string in plaintext

- **Example**:
  ```typescript
  const decoded = NehonixURIProcessor.autoDetectAndDecode(
    "https://example.com?test=dHJ1ZQ=="
  );
  console.log(decoded); // https://example.com?test=true
  ```

#### `detectAndDecode(input: string)`

**Deprecated**: Used in previous versions. Use `autoDetectAndDecode` for improved precision and performance.

Automatically detects and decodes a URI string.

- **Parameters**: `input` - The URI string to decode

- **Returns**: An object containing:

  - `val`: The decoded string
  - `encodingType`: The detected encoding type
  - `confidence`: Confidence score (0-1)

- **Example**:
  ```typescript
  const result = NehonixURIProcessor.detectAndDecode("dHJ1ZQ==");
  console.log(result); // { val: "true", encodingType: "base64", confidence: 0.9 }
  ```

#### `encode(input: string, encodingType: string)`

Encodes a string using a specific encoding type.

- **Parameters**:

  - `input` - The string to encode
  - `encodingType` - The encoding type (e.g., `percentEncoding`, `base64`, `rot13`)

- **Returns**: The encoded string

- **Example**:
  ```typescript
  const encoded = NehonixURIProcessor.encode("hello world", "rot13");
  console.log(encoded); // uryyb jbeyq
  ```

#### `decode(input: string, encodingType: string, maxRecursionDepth?: number)`

Decodes a string using a specific encoding type, with optional recursion for nested encodings.

- **Parameters**:

  - `input` - The string to decode
  - `encodingType` - The encoding type (e.g., `percentEncoding`, `base64`, `jwt`)
  - `maxRecursionDepth` (optional) - Maximum recursion depth for nested decoding

- **Returns**: The decoded string

- **Example**:
  ```typescript
  const decoded = NehonixURIProcessor.decode("uryyb%20jbeyq", "rot13");
  console.log(decoded); // hello%20world
  ```

#### `analyzeURL(url: string)`

Analyzes a URL and identifies potentially vulnerable parameters.

- **Parameters**: `url` - The URL to analyze

- **Returns**: An object containing:

  - `url`: The base URL
  - `params`: Object with query parameters and their risk assessments

- **Example**:
  ```typescript
  const analysis = NehonixURIProcessor.analyzeURL(
    "https://example.com?user=admin"
  );
  console.log(analysis); // { url: "https://example.com", params: { user: { value: "admin", risks: ["sql_injection", "xss"] } }, ... }
  ```

#### `generateWAFBypassVariants(input: string)`

Generates various encoded versions of a string for WAF bypass testing.

- **Parameters**: `input` - The string to encode in various ways

- **Returns**: Object containing different encoded variants

- **Example**:
  ```typescript
  const variants = NehonixURIProcessor.generateWAFBypassVariants("<script>");
  console.log(variants); // { percent: "%3Cscript%3E", base64: "PHNjcmlwdD4=", rot13: "<fpevcg>", ... }
  ```

### Encoding and Decoding Methods

The library supports the following encoding/decoding methods, accessible via `encode` and `decode`:

- `percentEncoding` / `percent` / `url`: Standard URL percent encoding (e.g., space → `%20`)
- `doublepercent` / `doublePercentEncoding`: Double percent encoding (e.g., space → `%2520`)
- `base64`: Base64 encoding (e.g., `true` → `dHJ1ZQ==`)
- `hex` / `hexadecimal`: Hexadecimal encoding (e.g., `A` → `\x41`)
- `unicode`: Unicode encoding (e.g., `A` → `\u0041`)
- `htmlEntity` / `html`: HTML entity encoding (e.g., `&` → `&amp;`)
- `punycode`: Punycode encoding for internationalized domain names (e.g., `☺` → `xn--n3h`)
- `asciihex`: ASCII characters as hexadecimal values (e.g., `A` → `\x41`)
- `asciioct`: ASCII characters as octal values (e.g., `A` → `\101`)
- `rot13`: ROT13 cipher (e.g., `hello` → `uryyb`)
- `base32`: Base32 encoding (alphanumeric with padding)
- `urlSafeBase64`: URL-safe Base64 encoding (uses `-` and `_` instead of `+` and `/`)
- `jsEscape`: JavaScript escape sequences for string contexts (e.g., `"` → `\"`)
- `cssEscape`: CSS escape sequences for selectors and values (e.g., `#` → `\23`)
- `utf7`: UTF-7 encoding for legacy systems
- `quotedPrintable`: Quoted-Printable encoding for email systems (e.g., `=` → `=3D`)
- `decimalHtmlEntity`: Decimal HTML entity encoding (e.g., `<` → `&#60;`)
- `rawHexadecimal`: Raw hexadecimal encoding without prefixes
- `jwt`: JSON Web Token encoding

### Security Testing Features

The library includes features specifically designed for security testing:

- Parameter analysis for common injection patterns (SQL injection, XSS, path traversal)
- WAF bypass techniques with mixed encoding strategies (including new types like `rot13` and `jwt`)
- Support for alternating case generation
- Detailed URI validation with customizable rules

## Supported Encoding Types

The library supports the following encoding types for encoding, decoding, and auto-detection:

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

## Detection Capabilities

The library can automatically detect the following encoding types:

- Percent encoding (`%XX`)
- Double percent encoding (`%25XX`)
- Base64
- Hexadecimal (`\xXX` or `0xXX`)
- Unicode (`\uXXXX` or `\u{XXXXX}`)
- HTML entities (`&lt;`, `&#60;`, `&#x3C;`)
- Punycode (`xn--`)
- ASCII octal (`\XXX`)
- ROT13
- Base32
- URL-safe Base64
- JavaScript escape sequences
- CSS escape sequences
- UTF-7
- Quoted-Printable
- Decimal HTML entities (`&#XX;`)
- Raw hexadecimal
- JWT

## Version

2.0.0

## License

MIT
