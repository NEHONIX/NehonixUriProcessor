# NehonixURIProcessor Changelog

All notable changes to the `NehonixURIProcessor` library are documented in this file.

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
