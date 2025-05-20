# CSP Rule to allow trusted CDN
type: csp
priority: 100
condition:
  type: match_path
  value: /.*
action:
  type: modify
  value:
    directive: script-src
    sources: ['https://cdn.trusted-source.com']
---
# Skip CSRF for public API
type: csrf
priority: 90
condition:
  type: match_path
  value: /api/public/.*
action:
  type: allow
---
# Block suspicious IPs
type: ip
priority: 100
condition:
  type: match_ip
  value: 192.168.1.100
action:
  type: deny
  
---
# Add security headers for admin routes
type: header
priority: 80
condition:
  type: match_path
  value: /admin/.*
action:
  type: add_header
  value:
    name: X-Admin-Security
    value: strict
---
# ML-based malicious URL detection
type: ml
priority: 100
condition:
  type: match_path
  value: /.*
action:
  type: deny
  value:
    threshold: 0.85
    model_version: v1.0
    threat_types: ["sql_injection", "xss", "path_traversal"]
---