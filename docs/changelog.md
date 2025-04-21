# NehonixURIProcessor Changelog

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
