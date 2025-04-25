# NehonixURIProcessor v2.2.0

## Overview

The `NehonixURIProcessor` class provides methods to:

- Validate URIs with configurable rules and advanced malicious pattern detection
- Automatically detect and decode encoding types in URIs with the recommended `autoDetectAndDecode` or the new asynchronous `asyncAutoDetectAndDecode` method
- Encode and decode strings using a wide range of encoding schemes
- Analyze URLs for potential security vulnerabilities with detailed reporting
- Generate encoding variations for Web Application Firewall (WAF) bypass testing and compare their effectiveness
- Create `URL` objects from URI strings
- Support internationalized URIs with proper character handling
- Integrate seamlessly with frameworks like Express and React

Version 2.2.0 introduces several new features focused on security, performance, and framework integration:

## New Features in v2.2.0

### Enhanced Security

- **Malicious Pattern Detection**: New methods to detect SQL injection, XSS, and other attack patterns
  - `detectMaliciousPatterns()`: Analyzes input for malicious patterns
  - `scanUrl()`: Provides detailed security analysis of URLs
  - `needsDeepScan()`: Lightweight pre-filter for efficient processing
  - `sanitizeInput()`: Removes potentially malicious patterns

- **Security Options in Validation**: Added `detectMaliciousPatterns` option to `isValidUri()` for automatic threat detection

### Performance Improvements

- **Asynchronous Processing**: New asynchronous methods for handling complex URIs without blocking
  - `asyncAutoDetectAndDecode()`: Non-blocking version of the popular auto-detection method
  - `asyncCheckUrl()`: Asynchronous URL validation for complex checks

### Framework Integrations

- **Express Middleware**: Ready-to-use middleware for securing Express applications
  - `nehonixShieldMiddleware`: Protects routes from malicious URIs
  - `scanRequest`: Analyzes Express request objects

- **React Integration**: React hooks for client-side URI validation
  - `NehonixShieldProvider`: Context provider for configuration
  - `useNehonixShield`: Hook for URI validation and analysis

### Internationalization Support

- Added support for international characters in URIs
- Improved punycode handling for internationalized domain names

## API Changes

### New Methods

- `asyncAutoDetectAndDecode(input, maxIterations?, useWorker?)`: Asynchronous version of autoDetectAndDecode
- `detectMaliciousPatterns(input, options?)`: Analyzes input for security threats
- `scanUrl(url, options?)`: Comprehensive security analysis of URLs
- `needsDeepScan(input)`: Quick check if input needs deeper security scanning
- `sanitizeInput(input, options?)`: Removes potentially malicious patterns
- `asyncCheckUrl(url, options?)`: Asynchronous version of checkUrl

### Enhanced Methods

- `isValidUri()`: Added options for malicious pattern detection and international character support
- `checkUrl()`: Improved validation with security-focused checks

## Usage Examples

### Malicious Pattern Detection

```typescript
const input = "<script>alert('XSS')</script>";
const result = NehonixURIProcessor.detectMaliciousPatterns(input);
console.log(result.isMalicious); // true
console.log(result.patternType); // "XSS"
```

### Asynchronous Decoding

```typescript
const complexUri = "https://example.com?data=SGVsbG8gV29ybGQ=";
const decoded = await NehonixURIProcessor.asyncAutoDetectAndDecode(complexUri);
console.log(decoded); // https://example.com?data=Hello World
```

### Express Middleware Integration

```typescript
import express from "express";
import { nehonixShieldMiddleware } from "nehonix-uri-processor";

const app = express();
app.use(nehonixShieldMiddleware({
  blockOnMalicious: true,
  logDetails: true,
  minScore: 50
}));
```

### React Hook Usage

```typescript
import { useNehonixShield } from "nehonix-uri-processor";

const MyComponent = () => {
  const { analyzeUrl } = useNehonixShield();
  
  const handleSubmit = async (url) => {
    const analysis = await analyzeUrl(url);
    if (analysis.isSafe) {
      // Process safe URL
    } else {
      // Handle potentially malicious URL
    }
  };
  
  return <form onSubmit={handleSubmit}>...</form>;
};
```

## Compatibility

This version maintains backward compatibility with v2.1.x while adding new capabilities. All existing code using NehonixURIProcessor should continue to work without modifications.

## Performance Considerations

- Use `needsDeepScan()` as a pre-filter before full security analysis for better performance
- For processing large or complex URIs, prefer the asynchronous methods to avoid blocking the main thread
- The React integration is optimized for client-side performance with minimal re-renders

## Security Best Practices

- Always validate user input with `isValidUri()` and enable the `detectMaliciousPatterns` option
- Use `sanitizeInput()` when you need to clean potentially malicious input rather than reject it
- For high-security applications, combine `scanUrl()` with custom validation logic

For more detailed information on specific methods, see the main documentation and API reference.