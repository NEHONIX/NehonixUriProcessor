import json
from microservices.nehonix_shield_model import predict

if __name__ == "__main__":
    # Test URLs
    test_urls = [
        # Benign URLs
        "https://www.amazon.com/s?k=laptop",
        "https://stackoverflow.com/questions/12345",
        "https://www.bbc.com/news",
        "https://example.com/login",
        "https://google.com/search?q=hello+world",
        "https://example.com/profile?user=john.doe&lang=en",

        # SQL Injection
        "http://fake-login.com/auth?user=admin' OR '1'='1",
        "http://example.com/login?id=%27%20UNION%20SELECT%201,2,3--",

        # XSS
        "https://malicious-site.net/secure?payload=<script>alert(document.cookie)</script>",
        "http://example.com/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E",

        # SSRF
        "http://evil.com/fetch?url=http://localhost/admin",
        "http://example.com/proxy?uri=http://169.254.169.254/metadata",

        # Path Traversal
        "http://bad-site.xyz/download.php?file=../../etc/passwd",
        "http://example.com/get?path=/etc/shadow",

        # Command Injection
        "http://example.com/run?cmd=whoami%3Bcat%20/etc/passwd",
        "http://example.com/exec?command=ping%20-c%204%20127.0.0.1",

        # File Upload
        "http://example.com/upload?file=malicious.php%3Bfilename%3Dshell.php",
        "http://example.com/attach?data=multipart/form-data&file=shell.exe",

        # JWT Manipulation
        "http://banking-online-secure.com/token?to%6b%65n=eyJhbGciOiJIUzI1NiIkpXVCJ9.eyJzdWIiOiIxMjM0NTA3OdkwIiwibmFtZSI6IkpvbiAgRG9lIiwiaWF0Ij6aojxNTE2MjM5MDIy0fQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQs3w5c",

        # NoSQL Injection
        "http://example.com/api?query={'$ne':null}&user=admin",
        "http://example.com/find?filter[$where]=this.password=='123'",

        # XXE
        "http://example.com/api?xml=%3C!DOCTYPE%20foo%20[%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E]",

        # Deserialization
        "http://example.com/process?data=rO0ABXVyABNbTGphdmEubGFuZy5TdHJpbmc7RDeyeXBlAHhwdXIAE1tMamF2YS5sYW5nLk9iamVjdDt9ZHNkY2QBdXIAEFtMamF2YS5sYW5nLlN0cmluZzsH7KMt6vMGYQN4cHQAFW15U3RyaW5nMTtzb21lQ29udGVudDEAdAAUbXlTdHJpbmcxO3NvbWV",

        # Edge Cases
        "http://xn--80ak6aa92e.com/login",  # Punycode domain (benign)
        "http://example.com/😀?param=😀",  # Unicode characters
        "http://example.com/" + "a" * 2000,  # Very long URL
        "http://example.com/path?param=",  # Empty query parameter
        "http://[::1]/admin",  # IPv6 loopback (potential SSRF)
        "http://example.com/path?param=%%20",  # Malformed URL-encoded characters
    ]
    
    # Make predictions
    result = predict(test_urls)
    print(json.dumps(result, indent=2))


