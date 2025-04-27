import json
from microservices.nehonix_shield_model import predict

if __name__ == "__main__":
    # Test URLs
    test_urls = [
    "https://www.amazon.com/s?k=laptop",  # Benign
        "https://stackoverflow.com/questions/12345",  # Benign
        "https://www.bbc.com/news",  # Benign
        "https://example.com/login",  # Benign with suspicious keyword
        "http://fake-login.com/auth?user=admin' OR '1'='1",  # SQL Injection
        "https://malicious-site.net/secure?payload=<script>alert(document.cookie)</script>",  # XSS
        "http://evil.com/fetch?url=http://localhost/admin",  # SSRF
        "http://bad-site.xyz/download.php?file=../../etc/passwd"  # Path Traversal
]
    
    # Make predictions
    result = predict(test_urls)
    print(json.dumps(result, indent=2))