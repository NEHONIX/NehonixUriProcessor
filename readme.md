# NehonixURIProcessor

A comprehensive TypeScript library for detecting, decoding, and encoding different types of URI encoding schemes. This utility is particularly useful for security testing, web application penetration testing, and analyzing potential attacks.

## Overview

The `NehonixURIProcessor` class provides methods to:

- Automatically detect encoding types in URIs
- Encode and decode strings using various encoding schemes
- Analyze URLs for potential security vulnerabilities
- Generate encoding variations for Web Application Firewall (WAF) bypass testing

## Installation

```bash
npm install "@nehonix/uri-processor"
```

Make sure to also install the `punycode` dependency:

```bash
npm install punycode
```

## Usage

```typescript
import { NehonixURIProcessor } from "@nehonix/uri-processor";

// Automatically detect and decode
const encodedURL = "https://example.com/page?param=select%20*%20from%20users";
const result = NehonixURIProcessor.detectAndDecode(encodedURL);
console.log(`Detected type: ${result.encodingType}`);
console.log(`Confidence: ${result.confidence}`);
console.log(`Decoded value: ${result.decodedValue}`);

// Encode a string using a specific encoding type
const encoded = NehonixURIProcessor.encode("test<script>", "htmlEntity");
console.log(encoded); // test&lt;script&gt;
```

## API Reference

### Core Methods

#### `detectEncoding(input: string)`

Automatically detects the encoding type of a URI string.

- **Parameters**: `input` - The URI string to analyze
- **Returns**: An object containing:
  - `types`: Array of detected encoding types
  - `mostLikely`: The most probable encoding type
  - `confidence`: Confidence score (0-1) of the detection

#### `detectAndDecode(input: string)`

Automatically detects and decodes a URI string.

- **Parameters**: `input` - The URI string to decode
- **Returns**: An object containing:
  - `decodedValue`: The decoded string
  - `encodingType`: The detected encoding type used
  - `confidence`: Confidence score of the detection

#### `decode(input: string, encodingType: string)`

Decodes a string using a specific encoding type.

- **Parameters**:
  - `input` - The string to decode
  - `encodingType` - The encoding type to use (e.g., "percent", "base64")
- **Returns**: The decoded string

#### `encode(input: string, encodingType: string)`

Encodes a string using a specific encoding type.

- **Parameters**:
  - `input` - The string to encode
  - `encodingType` - The encoding type to use
- **Returns**: The encoded string

### Decoding Methods

#### `decodePercentEncoding(input: string)`

Decodes URL percent encoding (e.g., `%20` → space).

#### `decodeDoublePercentEncoding(input: string)`

Decodes double percent encoding (e.g., `%2520` → `%20` → space).

#### `decodeBase64(input: string)`

Decodes Base64 encoded strings.

#### `decodeHex(input: string)`

Decodes hexadecimal encoded strings (e.g., `\x20` or `0x20` → space).

#### `decodeUnicode(input: string)`

Decodes Unicode encoded strings (e.g., `\u0020` → space).

#### `decodeHTMLEntities(input: string)`

Decodes HTML entities (e.g., `&lt;` → `<`).

#### `decodePunycode(input: string)`

Decodes Punycode domains (e.g., `xn--n3h` → `☺`).

### Encoding Methods

#### `encodePercentEncoding(input: string, encodeSpaces = false)`

Encodes a string using URL percent encoding.

#### `encodeDoublePercentEncoding(input: string)`

Applies double percent encoding.

#### `encodeBase64(input: string)`

Encodes a string to Base64.

#### `encodeHex(input: string)`

Encodes a string using hexadecimal encoding with `\x` prefix.

#### `encodeUnicode(input: string)`

Encodes a string using Unicode escape sequences.

#### `encodeHTMLEntities(input: string)`

Encodes a string with HTML entities.

#### `encodePunycode(input: string)`

Encodes a string using Punycode (for internationalized domain names).

#### `encodeASCIIWithHex(input: string)`

Encodes all characters as hexadecimal with `\x` prefix.

#### `encodeASCIIWithOct(input: string)`

Encodes all characters as octal.

#### `encodeAllChars(input: string)`

Encodes all characters using percent encoding (for WAF bypass).

### Security Utilities

#### `analyzeURL(url: string)`

Analyzes a URL and identifies potentially vulnerable parameters.

- **Parameters**: `url` - The URL to analyze
- **Returns**: An object containing:
  - `baseURL`: The base URL (protocol, host, path)
  - `parameters`: Object containing all query parameters
  - `potentialVulnerabilities`: Array of detected potential vulnerabilities

#### `generateWAFBypassVariants(input: string)`

Generates various encoded versions of a string for WAF bypass testing.

- **Parameters**: `input` - The string to encode in various ways
- **Returns**: Object containing different encoded variants

## Supported Encoding Types

- `percent` / `percentencoding` / `url`: URL percent encoding
- `doublepercent` / `doublepercentencoding`: Double percent encoding
- `base64`: Base64 encoding
- `hex` / `hexadecimal`: Hexadecimal encoding
- `unicode`: Unicode escape sequences
- `htmlentity` / `html`: HTML entity encoding
- `punycode`: Punycode encoding
- `asciihex`: ASCII to hexadecimal conversion
- `asciioct`: ASCII to octal conversion

## Detection Capabilities

The library can automatically detect these encoding types:

- Percent encoding (`%XX`)
- Double percent encoding (`%25XX`)
- Base64
- Hexadecimal (`\xXX` or `0xXX`)
- Unicode (`\uXXXX` or `\u{XXXXX}`)
- HTML entities (`&lt;`, `&#60;`, `&#x3C;`)
- Punycode (`xn--`)

## Security Testing Features

The library includes features specifically designed for security testing:

- Parameter analysis for common injection patterns
- Detection of XSS, SQL injection, and path traversal attempts
- WAF bypass techniques with mixed encoding strategies
- Support for alternating case generation

## License

MIT
