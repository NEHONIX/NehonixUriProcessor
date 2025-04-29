# Security Policy

## Supported Versions

The following versions of NehonixURIProcessor are currently being supported with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 2.2.x   | :white_check_mark: |
| 2.1.x   | :white_check_mark: |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

We take the security of NehonixURIProcessor seriously. This library is designed for security testing and protection against URI-based attacks, so maintaining its integrity is our highest priority.

### How to Report

If you discover a security vulnerability within NehonixURIProcessor, please follow these steps:

1. **Do not disclose the vulnerability publicly** until it has been addressed by our team
2. Email your findings to security@nehonix.space
3. Include detailed information about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Verification**: Our team will verify the issue and determine its impact
- **Resolution Timeline**: We aim to release a patch within 7-14 days, depending on severity
- **Credit**: With your permission, we will credit you in the release notes when the issue is fixed

## Security Best Practices

When implementing NehonixURIProcessor in your applications, we recommend the following security practices:

1. **Always use the latest version** to benefit from security patches and improvements
2. **Implement proper input validation** in addition to using this library
3. **Configure WAF features** appropriately for your specific use case
4. **Monitor logs** for potential attack patterns detected by the library
5. **Regularly update** your security rules and patterns

## Security Features

NehonixURIProcessor includes several security-focused features:

- Parameter analysis for common injection patterns (SQL injection, XSS, path traversal)
- WAF bypass detection with mixed encoding strategies
- Support for detecting various encoding techniques used in attacks
- Detailed URI validation with customizable rules

## Responsible Disclosure

We follow responsible disclosure principles and expect the same from security researchers. We will not take legal action against researchers who follow responsible disclosure practices.

---

Thank you for helping keep NehonixURIProcessor secure!