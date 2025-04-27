ATTACK_PATTERNS = {
    "sql_injection": [
        # Removed variable-width lookbehinds; added comment exclusion via separate pattern
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)(?:OR|AND)\s+(?:['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*['\"]|[\d]+\s*=\s*[\d]+)(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)",  # OR/AND tautologies
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)UNION\s+(?:ALL\s+)?SELECT\s+(?:[\w*]+,)*\s*(?:password|pass|pwd|credential|hash|secret|token)\b",  # UNION SELECT
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)SELECT\s+(?:[\w*]+,)*\s*(?:FROM|WHERE)\s+(?:INFORMATION_SCHEMA|pg_catalog)\.",  # Metadata tables
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)WAITFOR\s+DELAY\s+['\"][0-9:.]+['\"]",  # Time-based injection
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)EXEC\s+(?:SP_|XP_)\w+\b",  # Stored procedures
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)DROP\s+TABLE\s+\w+\s*(?:;|\b)",  # Table drop
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)INSERT\s+INTO\s+\w+\s*\(.+?\)\s*VALUES\s*\(.+?\)",  # Malicious INSERT
        r"(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)['\"]\s*;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\b",  # Statement chaining
        r"(?:%27|%22|%3b|%2d%2d|%23)\s*(?:OR|AND|SELECT|UNION|INSERT|DROP|DELETE|UPDATE|EXEC)\b",  # URL-encoded keywords
        # Handle comments separately
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)ORDER\s+BY\s+[0-9]+(?:\b|\s|%20|%09|%0a|%0d|\+|\/\*.*?\*\/|--|\#)",  # ORDER BY
    ],

    "path_traversal": [
        # Unchanged; no lookbehind issues
        (r"(?:\.\.|%2e%2e|%252e%252e|%c0%ae|%e0%80%ae)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:etc/passwd|shadow|group|hosts|motd|mtab|fstab|issue)\b", 7.0),
        (r"(?:\.\.|%2e%2e|%252e%252e|%c0%ae|%e0%80%ae)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:wp-config\.php|config\.php|settings\.json|web\.xml|\.htaccess)\b", 6.0),
        (r"(?:\?|&)(?:file|path|dir|resource|uri|url)=[^&]*(?:\.\.|%2e%2e|%252e%252e|%c0%ae|%e0%80%ae)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}", 5.0),
        (r"file:(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){2,10}(?:etc|windows|proc|sys|dev|tmp|var)\b", 6.0),
        r"(?<!\.(?:css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|ico))\b(?:\.\.|%2e%2e|%252e%252e|%c0%ae|%e0%80%ae)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}\b",  # General traversal
    ],

    "command_injection": [
        # Replaced lookbehinds with comment exclusion patterns
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:;|\||&&|\|\||%0a|%0d|`)\s*(?:cat|ls|dir|id|whoami|pwd|uname|curl|wget|nc|netcat|nmap|ping|telnet|bash|sh|python|perl|ruby)\s+(?:-[a-zA-Z0-9]+)*\b",  # Common commands
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:;|\||&&|\|\||%0a|%0d|`)\s*(?:\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/|\/sbin\/)(?:cat|ls|dir|id|whoami|pwd|uname|curl|wget|nc|netcat|nmap|ping|telnet|bash|sh|python|perl|ruby)\b",  # Absolute paths
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:;|\||&&|\|\||%0a|%0d|`)\s*(?:curl|wget)\s+(?:http|https|ftp):\/\/[^\s]+",  # Network commands
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:%26|%7C|%3B|%60|%24%28|%24%7B)\s*(?:cat|ls|dir|id|whoami|pwd|uname|curl|wget|nc|netcat|nmap|ping|telnet|bash|sh|python|perl|ruby)\b",  # URL-encoded operators
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\$\((?:cat|ls|dir|id|whoami|pwd|uname|curl|wget|nc|netcat|nmap|ping|telnet|bash|sh|python|perl|ruby)[^\)]*\)",  # Command substitution
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:;|\||&&|\|\||%0a|%0d|`)\s*(?:chmod|chown|rm|mv|cp|touch|mkdir)\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",  # File system commands
    ],

    "ssrf": [
        # Unchanged; no lookbehind issues
        (r"(?:http|https|ftp|file|ldap|gopher|dict)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|\[::1\])(?:/|$)", 7.0),
        (r"(?:http|https|ftp)://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)(?:\d+\.){2}\d+(?:/|$)", 6.0),
        (r"(?:\?|&)(?:url|uri|target|endpoint|dest|redirect|link)=[^&]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|\[::1\]|metadata\.google\.internal)", 5.0),
        (r"(?:http|https|ftp)://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/|$)", 5.0),
        r"(?:http|https|ftp)://(?![a-zA-Z0-9\-]+\.(?:com|org|net|edu|gov|io|co|ai|app|dev|cloud|online|site|tech|store|biz|info|me|us|uk|ca|de|fr|jp|cn|ru|br|au))[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/|$)",  # Suspicious domains
    ],

    "nosql_injection": [
        # Replaced lookbehinds with comment exclusion
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\{\s*\$where\s*:\s*(?:['\"]`)\s*(?:this\.[a-zA-Z0-9_]+|function\s*\(.*?\)\s*\{.*?\})\s*(?:['\"]`)\s*\}",  # $where with JS
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\{\s*\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|not|nor|exists|type|mod|regex)\s*:\s*(?:\{.*?\}|\[.*?\]|[0-9]+|true|false|null|['\"].*?['\"])\s*\}",  # MongoDB operators
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\{\s*\$expr\s*:\s*\{\s*\$eq\s*:\s*\[\s*['\"]\$?\w+['\"]\s*,\s*['\"]\$?\w+['\"]\s*\]\s*\}\s*\}",  # $expr tautologies
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\[\s*\$match\s*,\s*\{\s*\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or)\s*:\s*.*?\}\s*\]",  # Aggregation pipeline
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)(?:%24|%2524|%5c%24)(?:where|regex|expr|function|code|script)",  # URL-encoded operators
        r"(?!\/\/.*$|\/\*.*?\*\/|\#.*$)\{\s*['\"]?_id['\"]?\s*:\s*\{\s*\$oid\s*:\s*['\"][0-9a-fA-F]{24}['\"]\s*\}\s*\}",  # Valid _id
    ],

    "file_upload": [
        # Unchanged; no lookbehind issues
        r"<\s*input\s+[^>]*?type\s*=\s*['\"]?file['\"]?[^>]*?>\s*(?![^>]*?accept\s*=\s*['\"](?:image|audio|video|text)/)",  # File input without safe accept
        r"<\s*form\s+[^>]*?enctype\s*=\s*['\"]?multipart/form-data['\"]?[^>]*?>\s*(?![^<]*?<\s*input\s+[^>]*?name\s*=\s*['\"]?_csrf|_token|csrf_token|X-CSRF-TOKEN)",  # Form without CSRF
        r"(?:move_uploaded_file|copy|rename|file_put_contents|fwrite)\s*\(\s*['\"][^'\"]+?\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh|exe|dll|bat|cmd|ps1|vbs|js)['\"]\s*\)",  # Dangerous extensions
        r"(?:Content-Type|content-type)\s*:\s*(?:application/x-php|application/x-msdownload|text/x-shellscript)",  # Dangerous MIME types
        r"(?<!\/\/|\/\*|\#)<\s*input\s+[^>]*?type\s*=\s*['\"]?file['\"]?[^>]*?accept\s*=\s*['\"](?:image|audio|video|text|application/pdf)[^'\"]*?['\"][^>]*?>",  # Safe file inputs
    ],

    "ssrf_dns_rebinding": [
        # Unchanged; no lookbehind issues
        (r"(?:http|https|ftp)://(?:[a-zA-Z0-9\-]+\.)*[0-9]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/|$)", 6.0),
        (r"(?:http|https|ftp)://[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}", 6.0),
        (r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.(?:nip\.io|xip\.io|sslip\.io)(?:/|$)", 7.0),
        (r"(?:\?|&)(?:url|uri|target|endpoint|dest|redirect|link)=[^&]*(?:[a-zA-Z0-9\-]+\.)*(?:nip\.io|xip\.io|sslip\.io|localhost|127\.0\.0\.1)", 5.0),
        r"(?:http|https|ftp)://(?![a-zA-Z0-9\-]+\.(?:nip\.io|xip\.io|sslip\.io))[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/|$)",  # Safe domains
    ]
}