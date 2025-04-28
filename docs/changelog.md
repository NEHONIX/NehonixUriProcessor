# NehonixURIProcessor Changelog
## [2.3.1] - 2025-04-28

### New Features

- **DOM Analysis**: Added comprehensive DOM scanning to detect malicious content
  - Support for analyzing HTML content, attributes, scripts, and links
  - Optional iframe scanning capability (same-origin only)
  - Visual blocking overlay for malicious content protection
  - Mutation observer for real-time DOM monitoring

- **Request Monitoring**: Added network request analysis capabilities
  - Real-time monitoring using Performance Observer API
  - Configurable filters for XHR, fetch, images, and script requests
  - Notification system for detected threats

- **React Integration**:
  - New `useNehonixShield` hook for functional components
  - Higher-order component `withDomAnalysis` for easy component wrapping
  - Protection components:
    - `NehonixDomProtector`: DOM-specific protection with optional interval scanning
    - `RequestProtector`: Request-specific monitoring
    - `NehonixProtector`: Combined DOM and request protection

- **Developer Controls**:
  - Runtime toggling of blocking behavior
  - Access to analysis results and scanning status
  - Performance metrics for security operations

### Improvements

- Extended context provider with additional security methods
- Enhanced feedback mechanism for security analysis results
- Improved TypeScript type definitions for better IDE support
- Optimized analysis performance for larger DOM trees

### Bug Fixes

- Fixed memory leak in request monitoring when components unmount
- Corrected attribute handling in DOM analysis to prevent false positives
- Resolved race condition in concurrent security analysis operations
- Fixed issue with error handling in feedback reporting

### Documentation

- Added comprehensive README with usage examples
- Updated API documentation with new methods and components
- Added reference diagrams for security architecture
- Included best practices for production deployment

### Changes

- Modified `ShieldContextType` to support extended security features
- Updated default sensitivity levels for more accurate detection
- Adjusted blocking behavior to provide more user feedback
- Changed error reporting format for better integration with monitoring tools

### Dependencies

- Updated internal NSB service to v1.8.2
- Added dependency on Performance Observer polyfill for legacy browser support
- Upgraded React peer dependency to v18.0.0+

### Notes

- DOM analysis requires DOM access and may have limitations in some environments
- Request monitoring is only effective for requests that occur after component mounting
- Same-origin policy restrictions apply to iframe scanning

## [2.2.0] - 2025-04-25

### Added

- **New Methods**:
  - `asyncIsUrlValid`: Asynchronous version of `isValidUri`, validating URIs with configurable rules in async workflows.
  - `sanitizeInput`: Sanitizes input strings by removing potentially malicious patterns (unstable, use with caution).
  - `needsDeepScan`: Lightweight check to determine if a string requires deep scanning, useful as a pre-filter for malicious pattern detection.
  - `detectMaliciousPatterns`: Analyzes input for malicious patterns (e.g., XSS, SQL injection) with detailed detection results and configurable options.
- **Import Alias**: Added support for importing `NehonixURIProcessor` as `__processor__` for shorter, more convenient usage.
- **Type Definitions**:
  - Introduced `DetectedPattern` interface for structuring malicious pattern detection results.
  - Added `AsyncUrlCheckResult` type, extending `UrlCheckResult` with `maliciousPatterns` in `validationDetails`.
  - FrameWork integration

### Changed

- **Type Structure**:
  - Updated `asyncCheckUrl` to include `maliciousPatterns` within `validationDetails` (`result.validationDetails.maliciousPatterns`) instead of at the top level, improving consistency and type safety.
  - Preserved `UrlCheckResult` unchanged to maintain compatibility with `checkUrl`.
- **Documentation**:
  - Updated `checkUrlMethod.md` to reflect new `AsyncUrlCheckResult` type structure and clarify `maliciousPatterns` access for `asyncCheckUrl`.
  - Enhanced `readme.md` with details for new methods (`asyncIsUrlValid`, `sanitizeInput`, `needsDeepScan`, `detectMaliciousPatterns`) and `__processor__` alias.
  - Improved `checkUrl` and `asyncCheckUrl` documentation with clearer `literalValue` explanations and links to `checkUrlMethod.md`.
- **Examples**:
  - Updated code examples in `readme.md` and `checkUrlMethod.md` to use `__processor__` alias and demonstrate new methods.
  - Refined example outputs for `asyncCheckUrl` to show `validationDetails.maliciousPatterns`.

### Fixed

- Corrected `analyzeUrl` to `scanUrl` in `readme.md` React Hook example, aligning with actual API.
- Improved type safety for `literalValue` in `checkUrl` and `asyncCheckUrl`, ensuring proper handling of `"@this"`, `string`, or `number`.

### Removed

- None.

## Version 2.1.2

**Release Date**: 2025-21-04

### Changes

- **Dependencies**: Added `tslib` dependency (v2.8.1) for improved TypeScript support
- **Performance**: Enhanced encoding detection algorithms for better accuracy
- **Documentation**: Updated JSDoc comments for better clarity and examples
- **Bug Fixes**: Improved error handling in decoding functions
- **Stability**: Fixed edge cases in nested encoding detection

### Recommendations

- Continue using `autoDetectAndDecode` as the recommended method for decoding URIs (instead of the deprecated `detectAndDecode`)
- For security testing, use the comprehensive `checkUrl` method for detailed validation results
  See the [v2.1.2 documentation](./nehonix%20uri%20processor%202.1.2.md) for more details.

## Version 2.0.9

### Changes

- Added detailed URL validation with the `checkUrl` method
- Enhanced documentation with specific method guides
- Improved encoding detection for complex nested encodings
- Added support for more encoding types

See the [v2.0.9 documentation](./readmeV2.0.9.md) for more details.

## Version 2.0.0

### Changes

- Initial public release with core functionality
- Support for multiple encoding/decoding methods
- Basic URL validation and analysis
- WAF bypass variant generation

---

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).