ATTACK_PATTERNS = {
 "sql_injection": [
            # Basic SQL injection patterns - enhanced - v2
            r"'(\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(OR|AND|SELECT|UNION|INSERT|DROP|DELETE|UPDATE|ALTER|CREATE|EXEC|EXECUTE|DECLARE)(\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?",
            r"(\s|\+|\/\*.*?\*\/)*?(OR|AND)(\s|\+|\/\*.*?\*\/)*?[0-9]",
            r"(\s|\+|\/\*.*?\*\/)*?(OR|AND)(\s|\+|\/\*.*?\*\/)*?[0-9](\s|\+|\/\*.*?\*\/)*?=(\s|\+|\/\*.*?\*\/)*?[0-9]",
            r"SELECT(\s|\+|\/\*.*?\*\/)*?FROM",
            r"UNION(\s|\+|\/\*.*?\*\/)*?(ALL)?(\s|\+|\/\*.*?\*\/)*?SELECT",
            r"INSERT(\s|\+|\/\*.*?\*\/)*?INTO",
            r"DROP(\s|\+|\/\*.*?\*\/)*?TABLE",
            r"DELETE(\s|\+|\/\*.*?\*\/)*?FROM",
            r"UPDATE(\s|\+|\/\*.*?\*\/)*?SET",
            r"EXEC(\s|\+|\/\*.*?\*\/)*?(SP_|XP_)",
            r"DECLARE(\s|\+|\/\*.*?\*\/)*?[@#]",
            r"EXECUTE(\s|\+|\/\*.*?\*\/)*?(IMMEDIATE|SP_|XP_)",
            r"SELECT(\s|\+|\/\*.*?\*\/)*?(password|pass|pwd|passwd|credential|hash|secret|token)",
            r"SELECT(\s|\+|\/\*.*?\*\/)*?\*",
            r"admin['\"]\s*--",
            r"['\"].*?['\"](\s|\+|\/\*.*?\*\/)*?--",
            r"1['\"]\s*;(\s|\+|\/\*.*?\*\/)*?DROP(\s|\+|\/\*.*?\*\/)*?TABLE(\s|\+|\/\*.*?\*\/)*?users(\s|\+|\/\*.*?\*\/)*?;(\s|\+|\/\*.*?\*\/)*?--",
            r"(\s|\+|\/\*.*?\*\/)*?OR(\s|\+|\/\*.*?\*\/)*?[0-9]=[0-9]",
            r"(\s|\+|\/\*.*?\*\/)*?OR(\s|\+|\/\*.*?\*\/)*?['\"](1|true|yes|y|on)['\"]=(['\"](1|true|yes|y|on)['\"]|\d)",
            r"(\s|\+|\/\*.*?\*\/)*?OR(\s|\+|\/\*.*?\*\/)*?['\"](a|x|string)['\"]=(['\"](a|x|string)['\"])",
            r"['\"]\s*OR(\s|\+|\/\*.*?\*\/)*?username(\s|\+|\/\*.*?\*\/)*?(LIKE|=)(\s|\+|\/\*.*?\*\/)*?['\"]%?(admin|root|user|superuser|manager|supervisor)%?['\"]",
            r"['\"]\s*WAITFOR(\s|\+|\/\*.*?\*\/)*?DELAY(\s|\+|\/\*.*?\*\/)*?['\"][0-9:.]+['\"]--",
            r"(\s|\+|\/\*.*?\*\/)*?ORDER(\s|\+|\/\*.*?\*\/)*?BY(\s|\+|\/\*.*?\*\/)*?[0-9]+",
            r"(\s|\+|\/\*.*?\*\/)*?GROUP(\s|\+|\/\*.*?\*\/)*?BY(\s|\+|\/\*.*?\*\/)*?[0-9]+",
            r"['\"]\s*;(\s|\+|\/\*.*?\*\/)*?EXEC(\s|\+|\/\*.*?\*\/)*?(SP_|XP_)CMDSHELL",
            r"LOAD_FILE\s*\((\s|\+|\/\*.*?\*\/)*?['\"][^'\"]*?['\"]\)",
            r"INTO(\s|\+|\/\*.*?\*\/)*?(OUT|DUMP)FILE",
            r"(SLEEP|PG_SLEEP|WAITFOR\s+DELAY|BENCHMARK|GENERATE_SERIES|MAKE_SET|REGEXP_LIKE|LIKE|RLIKE|PREPARE|HANDLER|EXTRACT|EXTRACTVALUE|UPDATEXML)\s*\((\s|\+|\/\*.*?\*\/)*?[0-9]+(\s|\+|\/\*.*?\*\/)*?\)",
            r"(\%27|\%22|\%5c|\%bf|\%5b|\%5d|\%7b|\%7d|\%60|\%3b|\%3d|\%3c|\%3e|\%26|\%24|\%7c|\%21|\%40|\%23|\%25|\%5e|\%2a|\%28|\%29|\%2b|\%7e|\%0a|\%0d|\%2f|\%25|,)",
            r"CONCAT\s*\([^\)]*?['\"][^'\"]*?['\"]\)",
            r"CONVERT\s*\([^\)]*?USING[^\)]*?\)",
            r"CAST\s*\([^\)]*?AS[^\)]*?\)",
            r"SUBSTRING\s*\([^\)]*?\)",
            r"UNICODE\s*\([^\)]*?\)",
            r"CHAR\s*\([^\)]*?\)",
            r"COLLATE\s*[^\s]+",
            r"ALTER\s+TABLE",
            r"CREATE\s+TABLE",
            r"INFORMATION_SCHEMA\.(TABLES|COLUMNS|SCHEMATA)",
            r"TABLE_NAME\s*=",
            r"COLUMN_NAME\s*=",
            r"IS_SRVROLEMEMBER\s*\(",
            r"HAS_DBACCESS\s*\(",
            r"fn_sqlvarbasetostr",
            r"fn_varbintohexstr",
            r"UTL_HTTP\.",
            r"UTL_INADDR\.",
            r"UTL_SMTP\.",
            r"UTL_FILE\.",
            r"DBMS_LDAP\.",
            r"DBMS_PIPE\.",
            r"DBMS_LOCK\.",
            r"SYS\.DATABASE_MIRRORING",
            r"BEGIN\s+DECLARE",
            r"BULK\s+INSERT",
            r"OPENROWSET\s*\(",
            r"(CHR|CHAR|ASCII)\s*\(\s*\d+\s*\)",
            r"(0x[0-9a-fA-F]{2,}){4,}",  # Hex-encoded strings
            r"UNHEX\s*\(",
            r"FROM_BASE64\s*\(",
    ],
   "xss": [
            # Enhanced XSS patterns covering more evasion techniques
            r"<\s*script[\s\S]*?>[\s\S]*?<\s*/\s*script\s*>",
            r"<\s*script[\s\S]*?src\s*=",
            r"<\s*script[\s\S]*?[\s\S]*?>",
            r"<\s*/?[a-z]+[\s\S]*?\bon\w+\s*=",
            r"<[\s\S]*?javascript:[\s\S]*?>",
            r"<[\s\S]*?vbscript:[\s\S]*?>",
            r"<[\s\S]*?data:[\s\S]*?>",
            r"<[\s\S]*?livescript:[\s\S]*?>",
            r"<[\s\S]*?mocha:[\s\S]*?>",
            r"<[\s\S]*?url\s*\(\s*['\"]\s*data:[\s\S]*?['\"]\s*\)",
            r"<[\s\S]*?expression\s*\([\s\S]*?\)",
            r"on\w+\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})",
            r"<[\s\S]*?ev[\s\S]*?al\s*\([\s\S]*?\)",
            r"<[\s\S]*?se[\s\S]*?t[\s\S]*?Time[\s\S]*?out\s*\([\s\S]*?\)",
            r"<[\s\S]*?set[\s\S]*?Int[\s\S]*?erval\s*\([\s\S]*?\)",
            r"<[\s\S]*?Fun[\s\S]*?ction\s*\([\s\S]*?\)",
            r"document\s*\.\s*cookie",
            r"document\s*\.\s*write",
            r"document\s*\.\s*location",
            r"document\s*\.\s*URL",
            r"document\s*\.\s*documentURI",
            r"document\s*\.\s*domain",
            r"document\s*\.\s*referrer",
            r"window\s*\.\s*location",
            r"(?:document|window)\s*?\.\s*?(?:open|navigate|print|replace|assign|location|href|host|hostname|pathname|search|protocol|hash|port)",
            r"(?:this|top|parent|window|document|frames|self|content)\s*\.\s*(?:window|document|frames|self|content)\s*\.\s*(?:window|document|frames|self|content)",
            r"<[\s\S]*?img[^>]*?\s+s[\s\S]*?rc\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*x\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})[^>]*?\s+on[\s\S]*?error\s*=",
            r"<[\s\S]*?svg[^>]*?\s+on[\s\S]*?load\s*=",
            r"<[\s\S]*?body[^>]*?\s+on[\s\S]*?load\s*=",
            r"<[\s\S]*?iframe[^>]*?\s+s[\s\S]*?rc\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*javascript:",
            r"[\"']\s*>\s*<\s*script\s*>",
            r"<[\s\S]*?div[^>]*?\s+style\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*background-image:\s*url\s*\(\s*javascript:",
            r"<[\s\S]*?link[^>]*?\s+href\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*javascript:",
            r"<[\s\S]*?meta[^>]*?\s+http-equiv\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*refresh\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})[^>]*?\s+url\s*=",
            r"<[\s\S]*?object[^>]*?\s+data\s*=",
            r"<[\s\S]*?embed[^>]*?\s+src\s*=",
            r"<[\s\S]*?form[^>]*?\s+action\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*javascript:",
            r"<[\s\S]*?base[^>]*?\s+href\s*=",
            r"<[\s\S]*?input[^>]*?\s+type\s*=\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})\s*image\s*(['\"]|\&\#[xX]?[0-9a-fA-F]+;?|\\[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})[^>]*?\s+src\s*=",
            r"<[\s\S]*?isindex[^>]*?\s+action\s*=",
            r"al[\s\S]*?ert\s*\(",
            r"pro[\s\S]*?mpt\s*\(",
            r"con[\s\S]*?firm\s*\(",
            r"(?:(?:do|if|else|switch|case|default|for|while|loop|return|yield|function|typeof|instanceof|var|let|const)\s*\([^)]*\)\s*\{[^}]*\}|=>)",
            r"(?:fromCharCode|escape|unescape|btoa|atob|decodeURI|decodeURIComponent|encodeURI|encodeURIComponent)",
            r"\\u[0-9a-fA-F]{4}",
            r"\\x[0-9a-fA-F]{2}",
            r"&#x[0-9a-fA-F]+;",
            r"&#[0-9]+;",
            r"\\\d+",
            r"(?:\/[\w\s\\\/]+){3,}",  # Possible JS obfuscation
            r"(?:fetch|XMLHttpRequest|navigator.sendBeacon|WebSocket|EventSource|Worker)",
            r"(?:innerHTML|outerHTML|innerText|outerText|textContent|createElement|createTextNode|createDocumentFragment|append|appendChild|prepend|insertBefore|insertAfter|replaceWith|replaceChild)",
            r"(?:Storage|localStorage|sessionStorage)\.(?:setItem|getItem|removeItem|clear)",
            r"(?:location\.href|location\.replace|location\.assign|location\.search|location\.hash)",
            r"(?:eval|Function|new Function|setTimeout|setInterval|setImmediate|requestAnimationFrame)\s*\([\s\S]*?\)",
            r"(j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:|d\s*a\s*t\s*a\s*:)",  # Obfuscated protocol handlers
            r"[\"'][\s\S]*?[\"']\s*\+\s*[\"'][\s\S]*?[\"']",  # String concatenation
            r"\\(?:0{0,4}(?:1?[0-7]{0,3}|[0-3][0-7]{0,2}|[4-7][0-7]?|222|x[0-9a-f]{0,2}|u[0-9a-f]{0,4}|c.|.))|\^",  # Various escapes
            r"(?:top|parent|self|window|document)\s*(?:\[[^\]]+\]|\.[^\s\(\)]+)\s*(?:\[\s*[^\]]+\s*\]|\.\s*[^\s\(\)]+\s*)+\s*(?:\(.*?\))?",  # DOM traversal
            r"(?:-[a-z]-[a-z]-[\s\S]*?expr[\s\S]*?ession[\s\S]*?\([\s\S]*?\))",  # CSS expression
    ],
"path_traversal": [
    (r"\.\.(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}", 5.0),
    (r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}\.\.(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:credentials|secret|token|apikey|password|passwd|admin|key|cert|private|dump|backup)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f|$)(?!(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f)*(?:login|profile|user|questions|search|news|api|auth|secure|fetch|download)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f|$))", 5.0),
    (r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:etc|bin|home|root|boot|proc|sys|dev|lib|tmp|var|mnt|media|opt|usr)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f)", 5.0),
    (r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:etc/passwd|shadow|group|hosts|motd|mtab|fstab|issue|bash_history|bash_logout|bash_profile|profile)", 5.0),
    (r"(?:\?|&)(?:file|path|dir|resource|uri|url|data|content)=[^&]*(?:etc/passwd|etc/shadow|windows/win\.ini|system32|WEB-INF/web\.xml|\.htaccess|id_rsa|authorized_keys|config\.php|wp-config\.php|settings\.json)", 5.0),
        r"\.\.(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}",
        r"(?:%2e|%252e|%c0%ae|%c0%2e|%e0%80%ae|%e0%40%ae|%25c0%25ae|%ef%bc%8e|%ef%bc%ae){2,}(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}",
        r"(?:%252e|%25c0%25ae|%25e0%2580%25ae){2,}(?:%252f|%255c)",
        r"file:(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){2,10}",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:etc|bin|home|root|boot|proc|sys|dev|lib|tmp|var|mnt|media|opt|usr)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:etc/passwd|shadow|group|hosts|motd|mtab|fstab|issue|bash_history|bash_logout|bash_profile|profile)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:windows/win.ini|system32/drivers/etc/hosts|boot.ini|autoexec.bat|config.sys)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:system.ini|win.ini|desktop.ini|boot.ini|ntuser.dat|sam|security|software|system|config.sys)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:WEB-INF/web.xml|META-INF/MANIFEST.MF|weblogic.xml|server.xml|context.xml)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:config|conf|settings|inc|include|includes|admin|administrator|phpinfo|php.ini|.htaccess)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:backup|bak|old|orig|temp|tmp|swp|copy|1|2|~)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:config\.php|configuration\.php|settings\.php|functions\.php|db\.php|database\.php|connection\.php|config\.js|config\.json|config\.xml|settings\.json|settings\.xml)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:wp-config\.php|wp-settings\.php|wp-load\.php|wp-blog-header\.php|wp-includes|wp-admin)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:id_rsa|id_dsa|authorized_keys|known_hosts|htpasswd|.bash_history|.zsh_history|.mysql_history)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:credentials|secret|token|apikey|password|passwd|admin|login|user|username|key|cert|private|dump|backup)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:log|logs|access_log|error_log|debug_log|trace_log|event_log|app_log|application_log|web_log|server_log)",
        r"(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,10}(?:config|conf|settings|init|ini|cfg|properties|prop|yaml|yml|json|xml|env|environment)",
        r"(?:php|asp|aspx|jsp|jspx|do|action|cgi|pl|py|rb|go|cfm|json|xml|ini|inc|old|bak|backup|swp|txt|shtm|shtml|phtm|html|xhtml|css|js)\.(?:php|asp|aspx|jsp|jspx|do|action|cgi|pl|py|rb|go|cfm|json|xml|ini|inc)",
        r"(?:php://|file://|glob://|phar://|zip://|rar://|ogg://|data://|expect://|input://|view-source://|gopher://|ssh2://|telnet://|dict://|ldap://|ldapi://|ldaps://|ftp://|ftps://)",
        r"(?:ph\%70|php|php\:\\/\\/|piph|file\:\\/\\/|glob\:\\/\\/|phar\:\\/\\/|zip\:\\/\\/|rar\:\\/\\/|ogg\:\\/\\/|data\:\\/\\/|expect\:\\/\\/|input\:\\/\\/|view-source\:\\/\\/|gopher\:\\/\\/|ssh2\:\\/\\/|telnet\:\\/\\/|dict\:\\/\\/|ldap\:\\/\\/|ldapi\:\\/\\/|ldaps\:\\/\\/|ftp\:\\/\\/|ftps\:\\/\\/)",
        r"(?:php://|file://|glob://|phar://|zip://|rar://|ogg://|data://|expect://|input://|view-source://|gopher://|ssh2://|telnet://|dict://|ldap://|ldapi://|ldaps://|ftp://|ftps://)/(?:etc/passwd|shadow|group|hosts|motd|mtab|fstab|issue|bash_history|bash_logout|bash_profile|profile)",
        r"(?:php://|file://|glob://|phar://|zip://|rar://|ogg://|data://|expect://|input://|view-source://|gopher://|ssh2://|telnet://|dict://|ldap://|ldapi://|ldaps://|ftp://|ftps://)/(?:windows/win.ini|system32/drivers/etc/hosts|boot.ini|autoexec.bat|config.sys)",
        r"(?:php://|file://|glob://|phar://|zip://|rar://|ogg://|data://|expect://|input://|view-source://|gopher://|ssh2://|telnet://|dict://|ldap://|ldapi://|ldaps://|ftp://|ftps://)/(?:WEB-INF/web.xml|META-INF/MANIFEST.MF|weblogic.xml|server.xml|context.xml)",
        r"data:(?:text|application|image)/(?:html|plain|png|gif|jpg|jpeg);base64,",
        r"php://(?:filter|input|memory|temp|stdin|stdout|stderr)/(?:resource|convert\.base64-encode|convert\.base64-decode|convert\.quoted-printable-encode|convert\.quoted-printable-decode|string\.rot13|string\.toupper|string\.tolower|string\.strip_tags)",
        r"(?:file|php|glob|phar|zip|rar|ogg|data|expect|input|view-source|gopher|ssh2|telnet|dict|ldap|ldapi|ldaps|ftp|ftps):%252f%252f",  # Double URL encoding
],
    "command_injection": [
         # Enhanced command injection patterns
        r"(?:\||&|;|`|\$\(|\${|\$\{|\$\(|\$\[|\?\$|\$|\(|\)|\[|\]|\{|\}|\$|\^|~|<|>|\\\\|\\'|\\\"|\\'|\\\`|\\\(|\\\)|\\\[|\\\]|\\\{|\\\}|\\\\|\\\/|\\r|\\n|\r|\n|\s|\+|\*|%|\$#|@|\?|!|\^|\(|\)|\[|\]|\{|\}|\/\/|\/\*|\*\/|<!--)[\s\S]*?(?:ls|dir|cat|type|more|less|head|tail|vi|vim|emacs|nano|ed|cd|pwd|mkdir|rmdir|cp|mv|rm|touch|chmod|chown|chgrp|find|locate|grep|egrep|fgrep|sed|awk|cut|sort|uniq|wc|tr|diff|patch|wget|curl|lynx|links|fetch|telnet|nc|netcat|ncat|nmap|ping|traceroute|dig|nslookup|whois|ifconfig|ipconfig|netstat|route|ps|top|htop|kill|pkill|killall|sleep|usleep|python|perl|ruby|php|bash|sh|ksh|csh|zsh|ssh|scp|netstat|id|whoami|uname|hostname|host|net|systeminfo|ver|tasklist|taskkill|sc|reg|wmic|powershell|cmd|command|start|runas)",
        r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder|Process|pb\.start|pb\.command|new ProcessBuilder|createProcess|spawnProcess|popen|system|shell_exec|passthru|proc_open|pcntl_exec|exec|execl|execlp|execle|execv|execvp|execvpe|fork|popen|system|posix_spawn)",
        r"(?:(?:[$|%])[({][\s\S]*?[})])|(?:(?:`|'|\"|\))\s*(?:;|\||&&|\|\||$)[\s\S]*?(?:`|'|\"|$))",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*[a-zA-Z0-9_\-]{1,15}\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:[\"'`].*?[\"'`])\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:<?[^>]*>?)\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:.*?)\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:\/[^\/]*\/[a-z]*)\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:\$\([^)]*\))\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:\${[^}]*})\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:\$[a-zA-Z0-9_\-]{1,15})\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:[%$])\((?:[^)]*)\)",
        r"(?:\$\{(?:.*?)\})",
        r"(?:\${(?:.*?)})",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:\/[^\/]*\/[a-z]*)\s*(?:;|\||&&|\|\||\n|\r|`)",
        r"(?:^|\s)(?:\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/|\/sbin\/|\/usr\/sbin\/|\/usr\/local\/sbin\/|\/etc\/|\/tmp\/|\/var\/|\/home\/|\/root\/|\/opt\/|\/usr\/|\/lib\/|\.\/|\.\.\/|\/\.\/|\/\.\.\/)(?:[a-zA-Z0-9_\-\/]{1,50})",
        r"(?:%0A|%0D|\\n|\\r)(?:[a-zA-Z0-9_\-]{1,15})",
        r"(?:%0A|%0D|\\n|\\r)(?:[\"'`].*?[\"'`])",
        r"(?:%0A|%0D|\\n|\\r)(?:\/[^\/]*\/[a-z]*)",
        r"(?:%0A|%0D|\\n|\\r)(?:\$\([^)]*\))",
        r"(?:%0A|%0D|\\n|\\r)(?:\${[^}]*})",
        r"(?:%0A|%0D|\\n|\\r)(?:\$[a-zA-Z0-9_\-]{1,15})",
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:[a-zA-Z0-9_\-]{1,15})", # URL encoded operators
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:[\"'`].*?[\"'`])",
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:\/[^\/]*\/[a-z]*)",
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:\$\([^)]*\))",
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:\${[^}]*})",
        r"(?:%26|%7C|%3B|%60|%24%28|%24%7B|%5C%60|%5C%27|%5C%22)\s*(?:\$[a-zA-Z0-9_\-]{1,15})",
        r"(?:%E2%80%A8|%E2%80%A9)(?:[a-zA-Z0-9_\-]{1,15})", # Unicode line separators
        r"(?:%E2%80%A8|%E2%80%A9)(?:[\"'`].*?[\"'`])",
        r"(?:%E2%80%A8|%E2%80%A9)(?:\/[^\/]*\/[a-z]*)",
        r"(?:%E2%80%A8|%E2%80%A9)(?:\$\([^)]*\))",
        r"(?:%E2%80%A8|%E2%80%A9)(?:\${[^}]*})",
        r"(?:%E2%80%A8|%E2%80%A9)(?:\$[a-zA-Z0-9_\-]{1,15})",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:curl|wget|fetch|lynx|links|get|lwp-request)\s+(?:http|https|ftp|ftps|tftp|sftp|scp|file|php|data|expect|input|view-source|gopher|ssh2|telnet|dict|ldap|ldapi|ldaps|smb|smbs)://",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:python|perl|ruby|php|node|deno|lua|bash|sh|ksh|csh|zsh|pwsh|powershell)\s+(?:-c|-e|-eval|-exec|-command|-EncodedCommand)",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:nslookup|dig|host|whois|ping|traceroute|tracepath|mtr|netstat|ss|ip|ifconfig|ipconfig|arp|route|netsh|systeminfo|ver|uname|id|whoami|groups|last|history|env|printenv|set)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:base64|xxd|hexdump|od|hd|strings|xxd|hexedit|ghex|bless|hexcurse|dhex|hexer|hexeditor|hexcurse|bvi|bmore|xxd|hexdump)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:openssl|ssleay|gnutls-cli|stunnel|socat|ncat|netcat|nc)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:awk|sed|grep|egrep|fgrep|cut|tr|head|tail|sort|uniq|wc|diff|cmp|comm|join|paste|split|csplit|fmt|nl|pr|fold|column)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:find|locate|xargs|which|whereis|type|command|compgen|dpkg|rpm|apt|yum|dnf|pacman|pkg|brew|port|emerge|zypper)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:ssh|scp|sftp|rsync|rcp|rdp|rdesktop|rsh|rlogin|telnet|ftp|tftp|curl|wget|lynx|links|elinks|w3m|aria2c|axel)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:cat|tac|nl|more|less|head|tail|xxd|hexdump|strings|od|hd|vi|vim|nano|ed|emacs|pico|joe|jed|gedit|kate|kwrite|mousepad|leafpad|gvim|neovim|nvim)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:mail|mailx|sendmail|mutt|pine|alpine|elm|nail|balsa|thunderbird|evolution|outlook|kmail|claws-mail|sylpheed|icedove)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:at|batch|cron|crontab|anacron|systemctl|service|chkconfig|update-rc.d|rc-update|launchctl|schtasks|taskschd.msc|task|atq|atrm|batch)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:kill|pkill|killall|skill|snice|top|htop|ps|pstree|pgrep|pidof|pidstat|pmap|lsof|fuser|strace|ltrace|trace|truss|gdb|objdump|nm|size|strings|readelf|file)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:chmod|chown|chgrp|chattr|lsattr|setfacl|getfacl|umask|touch|mknod|mkfifo|mkdir|rmdir|rm|mv|cp|ln|ls|dir|vdir|lsblk|df|du|mount|umount|losetup|fdisk|parted|gparted|mkfs)\s+",
        r"(?:;|\||&&|\|\||\n|\r|`)\s*(?:zip|unzip|tar|gzip|gunzip|bzip2|bunzip2|xz|unxz|compress|uncompress|lzma|unlzma|7z|rar|unrar|arj|unarj|arc|unarc|cab|uncab|lha|unlha|lzh|unlzh|zoo|unzoo)\s+",
        r"\bcd\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bls\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bcat\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bmore\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bless\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bhead\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\btail\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bgrep\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bfind\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bcp\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bmv\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\brm\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bchmod\s+(?:[0-7]{3,4}|[ugoa][+-=][rwxstugo]+)\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bchown\s+(?:[a-zA-Z0-9_\-]+(?::[a-zA-Z0-9_\-]+)?)\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bchgrp\s+(?:[a-zA-Z0-9_\-]+)\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\btouch\s+(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bmkdir\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\brmdir\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\bln\s+(?:-[a-zA-Z]+\s+)*(?:/|\./|\.\./|\\|\.\\|\.\.\\|~)",
        r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\[0-7]{1,3}", # Possible character encoding
        r"&#x[0-9a-fA-F]+;|&#[0-9]+;", # HTML encoding
        r"\\[nrt]", # Special characters
        r"\$[a-zA-Z0-9_]+", # Environment variables
        r"\$\{[^}]*\}", # Complex variables
        r"(?:%00|%0A|%0D|%09|%20|%25|%26|%2B|%2F|%3A|%3B|%3C|%3D|%3E|%3F|%40|%5B|%5C|%5D|%5E|%60|%7B|%7C|%7D|%7E)+", # URL encoding
        r"(?:%[0-9a-fA-F]{2}){2,}", # URL encoding
        r"(?:\\x[0-9a-fA-F]{2}){2,}", # Hex encoding
        r"(?:\\u[0-9a-fA-F]{4}){2,}", # Unicode encoding
        r"(?:\\[0-7]{1,3}){2,}", # Octal encoding
        r"(?:&#x[0-9a-fA-F]+;){2,}", # HTML hex encoding
        r"(?:&#[0-9]+;){2,}", # HTML decimal encoding
        #
        r"\|\s*[a-zA-Z]+",
        r"\&\s*[a-zA-Z]+",
        r";\s*[a-zA-Z]+",
        r"`[^`]+`",
        r"\$\([^)]+\)",
        r"\$\{[^}]+\}",
        r"\|\s*cat\s+",
        r"\|\s*ls",
        r"\|\s*id",
        r"\|\s*dir",
        r"\|\s*pwd",
        r"\|\s*whoami",
        r"\|\s*wget",
        r"\|\s*curl",
        r"\|\s*nc",
        r"\|\s*netcat",
        r"\|\s*nslookup",
        r"\|\s*ping",
        r"\|\s*telnet",
        r"\|\s*bash",
        r"\|\s*sh",
        r"\|\s*python",
        r"\|\s*perl",
        r"\|\s*ruby",
        r"\|\s*nmap",
        r"\$\(whoami\)",
        r";\s*ping\s+-c\s+[0-9]",
        r";\s*sleep\s+[0-9]",
        r"&&\s*ping\s+-c\s+[0-9]",
        r"&&\s*sleep\s+[0-9]",
        r"\|\s*nc\s+",
        r"&&\s*curl\s+",
        r";\s*bash\s+-i\s+>&\s*/dev/tcp/",
        r"2>&1",
        r">/dev/null",
        r"><script>",
        r"\|\s*base64",
        r"\|\s*xxd",
        r"\|\s*hexdump",
        r"%0A[a-zA-Z]+",  # URL encoded newline followed by command
        r"%0D[a-zA-Z]+",  # URL encoded carriage return followed by command
        r"\$\{\{[^}]+\}\}",  # Template injection
        r"\{\{[^}]+\}\}"   # Template injection
    ],
   "deserialization": [
        # Deserialization attack patterns
        r"(?:O|N|S|P|C):[0-9]+:\"(?:.*?)\"",  # PHP serialized object signature
        r"(?:s|i|d|a|O|b|N):[0-9]+:",  # PHP serialization types
        r"__(?:sleep|wakeup|construct|destruct|call|callStatic|get|set|isset|unset|toString|invoke|set_state|clone)",  # PHP magic methods
        r"rO0+(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",  # Base64-encoded PHP serialized objects
        r"YToy(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",  # Base64-encoded PHP array serialization
        r"Tz[0-9]+:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",  # Base64-encoded PHP object serialization
        r"java\.(?:util|lang|io)\.(?:[a-zA-Z]+);",  # Java serialization signatures
        r"javax\.(?:xml|naming|management|swing|sql)\.(?:[a-zA-Z]+);",  # More Java packages
        r"org\.(?:apache|springframework|hibernate|jboss|aspectj)\.(?:[a-zA-Z]+);",  # Common Java frameworks
        r"com\.(?:sun|oracle|ibm|microsoft|google|apple)\.(?:[a-zA-Z]+);",  # Java company packages
        r"(?:sun|java|javax|org|com)\.(?:[a-zA-Z0-9_$.]+)",  # Java class pattern
        r"(?:marshal|unmarshal|deserialize|unserialize|load|read|fromXML|fromJson|parseXML|parseJson|readObject|readExternal|readResolve|valueOf|fromString)",  # Deserialization method patterns
        r"xmldecoder|ObjectInputStream|XStream|yaml\.(?:load|unsafe_load)|jackson\.(?:readValue|convertValue)|ObjectMapper|readObject|XMLDecoder|JacksonPolymorphicDeserialization",  # Deserialization classes
        r"SerialVersionUID|serialVersionUID|writeObject|readObject|Serializable|Externalizable",  # Java serialization markers
        r"XMLDecoder|XmlDecoder|SAXReader|DocumentBuilder|SchemaFactory|SAXParserFactory|DocumentBuilderFactory|TransformerFactory",  # XML parsers
        r"readObject|readExternal|readResolve|readExternalData|readObjectNoData",  # Java deserialization methods
        r"extends\s+ObjectInputStream|implements\s+(?:Serializable|Externalizable)",  # Java serialization classes
        r"SerializationUtils\.(?:deserialize|clone)|SerializeUtil|SerializationHelper",  # Common serialization utilities
        r"JNDI|RMI|JMX|LDAP|CORBA|EJB|JMS|MBean|ObjectFactory|InitialContext",  # Java context technologies
        r"Runtime\.(?:getRuntime|exec)|ProcessBuilder|ProcessImpl|UNIXProcess|CommandLine",  # Potential command execution
        r"(?:org\.)?yaml\.(?:load|unsafe_load)",  # YAML deserialization
        r"ObjectMapper\.(?:readValue|convertValue)",  # Jackson deserialization
        r"Json(?:Deserializer|Decoder|Parser|Reader)\.(?:parse|read|deserialize)",  # JSON deserialization
        r"BeanUtils\.(?:populate|copyProperties)|PropertyUtils",  # Bean population
        r"MethodInvoker|MethodUtils\.invokeMethod|InvocationHandler",  # Method invocation
        r"ScriptEngine|Nashorn|JavaScript|Rhino|BeanShell|Groovy|JRuby|Jython",  # Scripting engines
        r"pyc\\x|marshal\.loads|pickle\.(?:loads|load)",  # Python serialization
        r"CONSTR\$|METACLASS\$|functools\._reconstructor",  # Python serialization markers
        r"c__builtin__(?:\\r\\n|\\n)(?:eval|exec|open|file|os|sys|subprocess)",  # Python dangerous builtins
        r"c__main__(?:\\r\\n|\\n).+",  # Python main module serialization
        r"(?:GLOBAL|INST|OBJ|NEWOBJ|TUPLE|LIST|DICT|SET|FROZENSET|CODE)",  # Python pickle opcodes
        r"pickle\.loads?\(|marshal\.loads?\(|cPickle\.loads?\(",  # Python serialization methods
        r"node(?:Serialization|Deserialization)|NodeSerial|node-serialize|_\_proto\_\_",  # Node.js serialization
        r"Message(?:Pack|Serialization|Deserialization)|BSON|Avro|Thrift|Protobuf",  # Binary serialization formats
        r"(?:json|yaml|xml|plist|bson|protobuf)(?:\.parse|\.load|\s*=>)",  # Generic serialization
        r"Marshal\.(?:load|restore)|YAML\.(?:load|parse)",  # Ruby serialization
        r"ActiveSupport::(?:JSON|MessageVerifier|MessageEncryptor)",  # Rails serialization
        r"Oj\.(?:load|safe_load)|ActiveRecord::Base\.(?:serialize|attr_encrypted)",  # More Ruby serialization
        r"System\.(?:Runtime\.Serialization|Xml|Web\.Script\.Serialization)",  # .NET serialization namespaces
        r"TypeNameHandling\.(?:All|Objects|Arrays)",  # .NET JSON.NET TypeNameHandling
        r"(?:Binary|Object|Data|Soap|Json|Xml)(?:Serializer|Formatter)",  # .NET serialization classes
        r"LosFormatter|ObjectStateFormatter|SimpleTypeResolver|JavaScriptSerializer",  # ASP.NET serialization
        r"BinaryFormatter|NetDataContractSerializer|DataContractJsonSerializer",  # More .NET serializers
        r"SoapFormatter|XmlSerializer|LosFormatter|JavaScriptSerializer",  # Additional .NET serializers
        r"FormatterServices\.GetUninitializedObject|FormatterServices\.GetSafeUninitializedObject",  # .NET object creation
        r"DataContractSerializer|DataContractJsonSerializer|NetDataContractSerializer",  # WCF serializers
        r"SerializationBinder|SerializationInfo|StreamingContext|ISerializable|IDeserializationCallback",  # .NET serialization interfaces
        r"MemberInfo|FieldInfo|MethodInfo|Assembly\.Load|Assembly\.GetType|Activator\.CreateInstance",  # .NET reflection
        r"Base64InputStream|Base64OutputStream|base64_decode|base64_encode|base64decode|base64encode",  # Base64 manipulation
],

"jwt_manipulation": [
        # JWT manipulation patterns
        r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+",  # JWT token format
        r"alg[\"\']?\s*:\s*[\"\']?none[\"\']?",  # JWT algorithm none
        r"alg[\"\']?\s*:\s*[\"\']?HS(?:256|384|512)[\"\']?",  # JWT HMAC algorithms
        r"alg[\"\']?\s*:\s*[\"\']?RS(?:256|384|512)[\"\']?",  # JWT RSA algorithms
        r"alg[\"\']?\s*:\s*[\"\']?ES(?:256|384|512)[\"\']?",  # JWT ECDSA algorithms
        r"alg[\"\']?\s*:\s*[\"\']?PS(?:256|384|512)[\"\']?",  # JWT RSASSA-PSS algorithms
        r"alg[\"\']?\s*:\s*[\"\']?EdDSA[\"\']?",  # JWT EdDSA algorithm
        r"\"kid\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT Key ID
        r"\"typ\"(?:\s*):(?:\s*)\"(?:JWT|JWE|JWS|JWK)\"",  # JWT type
        r"\"cty\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT content type
        r"\"jku\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT JWK Set URL
        r"\"jwk\"(?:\s*):(?:\s*)\{(?:.+?)\}",  # JWT JWK
        r"\"x5u\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT X.509 URL
        r"\"x5c\"(?:\s*):(?:\s*)\[(?:.+?)\]",  # JWT X.509 Certificate Chain
        r"\"x5t\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT X.509 Certificate SHA-1 Thumbprint
        r"\"x5t#S256\"(?:\s*):(?:\s*)\"(?:.+?)\"",  # JWT X.509 Certificate SHA-256 Thumbprint
        r"\"crit\"(?:\s*):(?:\s*)\[(?:.+?)\]",  # JWT Critical
        r"\"enc\"(?:\s*):(?:\s*)\"(?:A128CBC-HS256|A192CBC-HS384|A256CBC-HS512|A128GCM|A192GCM|A256GCM)\"",  # JWT encryption algorithms
        r"\"zip\"(?:\s*):(?:\s*)\"(?:DEF)\"",  # JWT compression
        r"jwt\.(?:sign|verify|decode|encode)",  # JWT library methods
        r"jws\.(?:sign|verify|decode|encode)",  # JWS library methods
        r"jwe\.(?:encrypt|decrypt|deserialize|serialize)",  # JWE library methods
        r"jsonwebtoken\.(?:sign|verify|decode)",  # Node.js JWT library
        r"jose\.(?:JWT|JWS|JWE|JWK)\.(?:sign|verify|decode|encrypt|decrypt)",  # JOSE library methods
        r"pyjwt\.(?:encode|decode)",  # Python JWT library
        r"jwt_decode|jwt_encode|jwt_verify|jwt_sign",  # Generic JWT functions
        r"header\.alg\s*=\s*[\"\']?none[\"\']?",  # JWT header manipulation
        r"header\.typ\s*=\s*[\"\']?JWT[\"\']?",  # JWT header manipulation
        r"JWKS|JWK Set|\.well-known\/jwks\.json",  # JWKS endpoints
        r"HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA",  # JWT algorithms
        r"\.toJSONString\(\)|\.fromJSONString\(\)|\.toJWS\(\)|\.fromJWS\(\)",  # JWT object methods
        r"HMAC(?:SHA256|SHA384|SHA512)|RSA-(?:SHA256|SHA384|SHA512)",  # Cryptographic algorithms for JWT
        r"RS(?:256|384|512)toPSS(?:256|384|512)",  # Algorithm conversion
        r"jwtDecode|jwtEncode|jwtVerify|jwtSign",  # JWT helper functions
        r"jwtSecret|JWT_SECRET|JWT_PUBLIC_KEY|JWT_PRIVATE_KEY|JWT_KEY|JWT_SIGNING_KEY",  # JWT secrets
        r"base64_decode\((?:.*?)\.split\(['\"]?\.['\"]?\)",  # JWT header/payload splitting
        r"atob\((?:.*?)\.split\(['\"]?\.['\"]?\)",  # JWT Base64 decoding
        r"(?:btoa|Buffer\.from)\((?:.*?)\.join\(['\"]?\.['\"]?\)",  # JWT encoding
        r"\.sign\(\{[^\}]*\},\s*['\"](.*?)['\"]\)",  # JWT signing with secret
        r"\.sign\(\{[^\}]*\},\s*(?:fs|require\(['\"]fs['\"]\))\.readFileSync\(['\"](.*?)['\"]\)",  # JWT signing with key file
        r"\.verify\((?:.*?),\s*['\"](.*?)['\"]\)",  # JWT verification with secret
        r"\.verify\((?:.*?),\s*(?:fs|require\(['\"]fs['\"]\))\.readFileSync\(['\"](.*?)['\"]\)",  # JWT verification with key file
        r"none\.sign|none\.verify",  # 'none' algorithm manipulation
        r"public_to_private|extractPublicKey|convert_certificate",  # Key manipulation
        r"from_pem|to_pem|from_jwk|to_jwk",  # Key format conversion
        r"\.setIssuer\(['\"]?.*?['\"]?\)|\.setSubject\(['\"]?.*?['\"]?\)|\.setAudience\(['\"]?.*?['\"]?\)|\.setExpirationTime\(['\"]?.*?['\"]?\)|\.setIssuedAt\(['\"]?.*?['\"]?\)|\.setNotBefore\(['\"]?.*?['\"]?\)|\.setJwtId\(['\"]?.*?['\"]?\)",  # JWT claims setting
],

"ssrf": [
        # SSRF (Server-Side Request Forgery) patterns
        (r"(?:http|https|ftp|ftps|file|ldap|ldaps|gopher|dict|telnet|ssh|data)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|\[::1\])(?:/|$)", 5.0),
    (r"(?:http|https|ftp|ftps)://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)(?:\d+\.){0,2}\d+(?:/|$)", 5.0),
    (r"(?:http|https)://[^/]+(?:metadata\.google\.internal|169\.254\.169\.254)(?:/|$)", 5.0),
    (r"(?:\?|&)(?:url|uri|target|endpoint|dest|redirect|link)=[^&]*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|\[::1\]|metadata\.google\.internal|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+)(?:/|$)", 5.0),
        r"(?:file|gopher|ftp|ftps|http|https|ldap|ldaps|dict|dns|sftp|tftp|ssh|telnet|mailto|imap|pop3|vnc|rdp|smb|rsync|svn|git|rtsp|rtsps|rtspu)://[a-zA-Z0-9\-\.]+(?::[0-9]+)?(?:/[a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~]*)?",  # URL protocols
        r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})",  # Local/private IP addresses
        r"(?:\/\/0|\/\/127\.|\/@localhost|\/@127\.)",  # Local reference patterns
        r"(^|[^a-zA-Z0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![a-zA-Z0-9.])",  # Raw IP address
        r"(?:^|[^a-zA-Z0-9])(?:0x[a-fA-F0-9]{2}\.){3}0x[a-fA-F0-9]{2}",  # Hexadecimal IP
        r"(?:^|[^a-zA-Z0-9])(?:[0-9]+\.){3}[0-9]+",  # Decimal IP
        r"(?:^|[^a-zA-Z0-9])(?:0[0-7]{1,3}\.){3}0[0-7]{1,3}",  # Octal IP
        r"(?:0+(?:\.0+){3}|127\.0+\.0+\.1)",  # Zero-padded IPs
        r"(?:10|127|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}",  # Private network ranges
        r"(?:169\.254|fe80:|fc00:|fd[0-9a-f]{2}:)",  # Link-local addresses
        r"(?:\/\/|\\\\\\\\\|\\\\|\\\/\\\/)\d",  # URL path slashes with IPs
        r"(?:https?|ftp|file|mailto|smb|afp|sftp|ssh|vnc|telnet|rdp|rtsp|dict|ldap|gopher):\/\/[^\s]+",  # Various URL schemes
        r"(?:curl|wget|fetch|lwp-request|lynx|links|httrack)\s+(?:-[^\s]+\s+)*(?:'[^']+'|\"[^\"]+\"|[^\s'\"]+)",  # HTTP client commands
        r"(?:url|uri|href|src|data|action|location|path|domain|host|origin|referrer|source|destination|connection|connect|proxy|http[_\-]?(?:client|request|get|url|uri|query)|remote|fetch|request|get)(?:\[['\"]\]|\.|->|::)\s*(?:['\"][^'\"]+['\"]|\$[a-zA-Z0-9_]+)",  # URL property access
        r"(?:https?|ftp)%3[aA]%2[fF]%2[fF][^%\s]+",  # URL encoded URLs
        r"(?:https?|ftp)(?:%253[aA]|%3[aA])(?:%252[fF]|%2[fF])(?:%252[fF]|%2[fF])[^%\s]+",  # Double URL encoded URLs
        r"(?:http|https|ftp)\+bypass://[^\s]+",  # URL bypass schemes
        r"\\\\\\\\[a-zA-Z0-9\-\.]+\\\\[a-zA-Z0-9\-\.]+",  # Windows UNC paths
        r"\/\/\/+[a-zA-Z0-9\-\.]+(?:\/[a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~]*)?",  # Triple slash URLs
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",  # IP address format
        r"(?:^|[^a-zA-Z0-9.])(?:(?:0|00|0x0|0b0|0127)\.0\.0\.1|127\.(?:0|00|0x0|0b0)\.(?:0|00|0x0|0b0)\.(?:1|01|0x1|0b1))",  # Obfuscated localhost
        r"(?:^|[^a-zA-Z0-9])(?:[0-9]{8,10}|(?:0x)[0-9a-fA-F]{8}|[0-9]+)",  # Integer IP representation
        r"(?:http|https|ftp)://[0-9]+(?:\.[0-9]+){0,3}",  # Pure numeric domain
        r"(?:http|https|ftp)://0x[0-9a-fA-F]+(?:\.0x[0-9a-fA-F]+){0,3}",  # Hexadecimal domain
        r"(?:http|https|ftp)://[0-9]+(?:\.[0-9]+){0,2}",  # Integer IP with fewer octets
        r"(?:jar|zip|tar|war|ear|cpio|shar|dump|ar|iso|dmg|vhd|vmdk|vdi|ova|ovf):\s*file:",  # Archive with file URL
        r"(?:java|vbscript|javascript|data|php):\s*\S+",  # Script protocols
        r"file:(?:///|\\\\\\\\)[^\s]+",  # File protocol with path
        r"dict://[^\s]+:[^\s]+",  # Dict protocol
        r"gopher://[^\s]+(?:_|\:)(?:[0-9]+|%29)",  # Gopher protocol with port or encoded end parenthesis
        r"ldap://[^\s]+:[^\s]+\??[^\s]+",  # LDAP protocol with query
        r"php://(?:filter|input|phar|expect|data|zip|compress\.zlib|glob)[^\s]*",  # PHP wrappers
        r"expect://[^\s]+",  # Expect protocol
        r"input://[^\s]+",  # Input protocol
        r"data:(?:[^;]+);base64,[a-zA-Z0-9+/]+={0,2}",  # Data URI with base64
        r"netdoc://[^\s]+",  # Netdoc protocol
        r"jar:(?:file|http|https)://[^\s]+!/[^\s]+",  # JAR URL
        r"\\\\[a-zA-Z0-9\-\.]+\\[a-zA-Z0-9\-\.]+",  # Windows share
        r"\/\/[a-zA-Z0-9\-\.]+\/[a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~]*",  # Protocol-relative URL
        r"\\\\localhost\\c\$\\",  # Windows administrative share
        r"\/\/localhost\/c\$\/",  # URL version of Windows share
        r"\/\/127\.0\.0\.1\/c\$\/",  # IP version of Windows share
        r"phar://[^\s]+",  # PHP Phar wrapper
        r"zip://[^\s]+#[^\s]+",  # PHP ZIP wrapper with fragment
        r"glob://[^\s]+",  # PHP glob wrapper
        r"compress\.zlib://[^\s]+",  # PHP compression wrapper
        r"compress\.bzip2://[^\s]+",  # PHP bzip2 wrapper
        r"ogg://[^\s]+",  # OGG protocol
        r"ssh2\.(?:shell|exec|tunnel|sftp|scp)://[^\s]+",  # SSH2 wrappers
        r"rar://[^\s]+",  # RAR protocol
        r"urllib\.(?:request|parse|error)\.(?:urlopen|urlretrieve|urlparse)",  # Python URL libraries
        r"requests\.(?:get|post|put|delete|head|options|patch)",  # Python requests library
        r"http\.(?:client|server)\.(?:HTTPConnection|HTTPSConnection)",  # Python HTTP library
        r"java\.net\.(?:URL|HttpURLConnection|URLConnection)",  # Java networking
        r"org\.apache\.http\.(?:client|impl)",  # Apache HTTP client
        r"javax\.net\.ssl",  # Java SSL
        r"curl_(?:init|exec|setopt)",  # PHP cURL functions
        r"file_get_contents|fopen|readfile|include|require",  # PHP file functions
        r"net\/http|net\/https|net/ftp",  # Ruby networking
        r"OpenURI|URI\.parse|Net::HTTP",  # Ruby URI handling
        r"System\.Net\.(?:WebClient|HttpClient|WebRequest|HttpWebRequest)",  # .NET HTTP clients
        r"axios\.(?:get|post|put|delete|head|options|patch)",  # JavaScript axios library
        r"fetch\(|XMLHttpRequest|ActiveXObject\(['\"]Microsoft\.XMLHTTP['\"]\)",  # JavaScript HTTP
        r"127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost",  # Private network IPs
        r"(^|[\r\n\s])\\\\(?:\*|[a-zA-Z0-9\-\.]+)\\(?:[a-zA-Z0-9\-\._\?\,\'/\\\+&amp;%\$#\=~]*)",  # Windows UNC paths
],
    "nosql_injection": [
        # Enhanced NoSQL injection patterns for MongoDB, CouchDB, and other NoSQL databases
        r"\{\s*\$where\s*:\s*(?:'|\"|\`).*?(?:'|\"|\`)\s*\}",  # MongoDB $where operator with string payloads
        r"\{\s*\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|not|nor|exists|type|mod|regex|all|size|elemMatch)\s*:\s*(?:\{.*?\}|\[.*?\]|[0-9]+|true|false|null|'.*?'|\".*?\")\s*\}",  # MongoDB operators
        r"\{\s*\$expr\s*:\s*\{.*?\}\s*\}",  # MongoDB $expr operator for complex expressions
        r"\{\s*\$regex\s*:\s*(?:'|\").*?(?:'|\").*?\}",  # MongoDB $regex operator with potential malicious patterns
        r"\{\s*\$function\s*:\s*\{.*?\}\s*\}",  # MongoDB $function operator for JavaScript execution
        r"\{\s*\$accumulator\s*:\s*\{.*?\}\s*\}",  # MongoDB $accumulator for custom aggregation
        r"\[\s*\$match\s*,\s*\{.*?\}\s*\]",  # MongoDB aggregation pipeline $match
        r"\[\s*\$lookup\s*,\s*\{.*?\}\s*\]",  # MongoDB aggregation pipeline $lookup
        r"\[\s*\$unwind\s*,\s*(?:'|\").*(?:'|\").*?\]",  # MongoDB aggregation pipeline $unwind
        r"\{\s*\$javascript\s*:\s*(?:'|\").*?(?:'|\").*?\}",  # Generic JavaScript injection in NoSQL queries
        r"\{\s*eval\s*:\s*(?:'|\").*?(?:'|\").*?\}",  # CouchDB _show/_list or eval injection
        r"\{\s*mapReduce\s*:\s*\{.*?\}\s*\}",  # MongoDB mapReduce with JavaScript
        r"\{\s*\$where\s*:\s*function\s*\(.*?\)\s*\{.*?\}\s*\}",  # MongoDB $where with function
        r"\{\s*\$code\s*:\s*(?:'|\").*?(?:'|\").*?\}",  # MongoDB $code operator for JavaScript
        r"\{\s*\$script\s*:\s*(?:'|\").*?(?:'|\").*?\}",  # Generic script injection
        r"\bthis\s*\.\s*[a-zA-Z0-9_]+\s*=\s*(?:true|false|[0-9]+|'.*?'|\".*?\")",  # MongoDB this-based property manipulation
        r"\breturn\s+[a-zA-Z0-9_]+\s*(?:==|!=|>|<|>=|<=)\s*(?:true|false|[0-9]+|'.*?'|\".*?\")",  # MongoDB return-based comparisons
        r"\$where\s*:\s*['\"]?this\..*?(?:==|!=|>|<|>=|<=).*?['\"]? ",  # MongoDB $where with this and comparisons
        r"\bfunction\s*\(.*?\)\s*\{\s*return\s+.*?\s*\}",  # Inline JavaScript function
        r"\bne\s*:\s*\{\s*\$ne\s*:\s*.*?\s*\}",  # Nested $ne operator
        r"\$or\s*:\s*\[\s*\{.*?\}\s*,\s*\{.*?\}\s*\]",  # MongoDB $or with multiple conditions
        r"\$and\s*:\s*\[\s*\{.*?\}\s*,\s*\{.*?\}\s*\]",  # MongoDB $and with multiple conditions
        r"\$nin\s*:\s*\[\s*(?:'.*?'|\".*?\"|[0-9]+)\s*,\s*(?:'.*?'|\".*?\"|[0-9]+)\s*\]",  # MongoDB $nin with array
        r"\$in\s*:\s*\[\s*(?:'.*?'|\".*?\"|[0-9]+)\s*,\s*(?:'.*?'|\".*?\"|[0-9]+)\s*\]",  # MongoDB $in with array
        r"(?:%24|%2524)(?:where|regex|expr|function|code|script)",  # URL-encoded MongoDB operators
        r"\btoString\s*\(\s*\)|valueOf\s*\(\s*\)",  # JavaScript object method calls
        r"\bArray\s*\(\s*\)|Object\s*\(\s*\)",  # JavaScript object/array instantiation
        r"\bJSON\.parse\s*\(\s*(?:'|\").*?(?:'|\").*?\s*\)",  # JSON parsing with potential injection
        r"\{\s*['\"]?_id['\"]?\s*:\s*\{\s*\$oid\s*:\s*(?:'|\").*?(?:'|\").*?\}\s*\}",  # MongoDB _id with $oid
        r"\{\s*['\"]?timestamp['\"]?\s*:\s*\{\s*\$timestamp\s*:\s*\{.*?\}\s*\}\s*\}",  # MongoDB timestamp
        r"\{\s*['\"]?\$gt['\"]?\s*:\s*\{\s*['\"]?\$date['\"]?\s*:\s*(?:[0-9]+|'.*?'|\".*?\")\s*\}\s*\}",  # MongoDB $gt with $date
        r"(?:\\u0024|\\x24)(?:where|regex|expr|function|code|script)",  # Unicode/hex-encoded MongoDB operators
        r"\bRegExp\s*\(\s*(?:'|\").*?(?:'|\").*?\s*\)",  # JavaScript RegExp instantiation
    ],
    "xxe": [
        # XML External Entity (XXE) injection patterns
        r"<!DOCTYPE\s+[^\>]*?\[.*?\]>",  # DOCTYPE with internal subset
        r"<!ENTITY\s+[^\s]+?\s+SYSTEM\s*['\"][^'\"]+?['\"]\s*>",  # External entity definition
        r"<!ENTITY\s+[^\s]+?\s+PUBLIC\s*['\"][^'\"]+?['\"]\s*['\"][^'\"]+?['\"]\s*>",  # Public entity definition
        r"&[a-zA-Z0-9_]+?;",  # Entity reference
        r"<!ENTITY\s+%\s+[^\s]+?\s+['\"][^'\"]+?['\"]\s*>",  # Parameter entity definition
        r"<!ENTITY\s+%\s+[^\s]+?\s+SYSTEM\s*['\"][^'\"]+?['\"]\s*>",  # Parameter entity with SYSTEM
        r"<!ENTITY\s+%\s+[^\s]+?\s+PUBLIC\s*['\"][^'\"]+?['\"]\s*['\"][^'\"]+?['\"]\s*>",  # Parameter entity with PUBLIC
        r"%[a-zA-Z0-9_]+?;",  # Parameter entity reference
        r"file:///[^\s]+",  # File protocol in entity
        r"http://[^\s]+",  # HTTP protocol in entity
        r"ftp://[^\s]+",  # FTP protocol in entity
        r"php://[^\s]+",  # PHP wrapper in entity
        r"expect://[^\s]+",  # Expect protocol in entity
        r"data://[^\s]+",  # Data protocol in entity
        r"(?:/etc/passwd|/etc/shadow|/etc/group|/proc/self/environ|/proc/self/status)",  # Sensitive file paths
        r"(?:win\.ini|system\.ini|boot\.ini|ntuser\.dat)",  # Windows sensitive files
        r"<!DOCTYPE\s+[^\>]*?\[\s*<!ELEMENT\s+.*?\]\s*>",  # DOCTYPE with ELEMENT definition
        r"<!DOCTYPE\s+[^\>]*?\[\s*<!ATTLIST\s+.*?\]\s*>",  # DOCTYPE with ATTLIST definition
        r"<!DOCTYPE\s+[^\>]*?\[\s*<!NOTATION\s+.*?\]\s*>",  # DOCTYPE with NOTATION definition
        r"&#x[0-9a-fA-F]+;",  # Hex-encoded entity reference
        r"&#[0-9]+;",  # Decimal-encoded entity reference
        r"(?:%25|%23|%3C|%3E|%26)[0-9a-fA-F]{2}",  # URL-encoded XML characters
        r"<!\[CDATA\[(?:.*?)]]>",  # CDATA section with potential payload
        r"<\?xml\s+version\s*=\s*['\"][^'\"]+?['\"]\s*encoding\s*=\s*['\"][^'\"]+?['\"]\s*\?>",  # XML declaration
        r"<\?xml-stylesheet\s+.*?\?>",  # XML stylesheet processing instruction
        r"(?:libxml|DOMDocument|SimpleXMLElement|XMLReader|XMLWriter|XmlParser)",  # XML parsing libraries
        r"(?:xml_parse|xml_parse_into_struct|simplexml_load_string|simplexml_load_file)",  # PHP XML functions
        r"DocumentBuilder|DocumentBuilderFactory|SAXParser|SAXParserFactory|TransformerFactory",  # Java XML parsers
        r"XMLDecoder|SAXReader|XmlReader|XmlDocument|XmlTextReader",  # Other XML parsers
        r"(?:disableEntityResolver|setFeature|setExpandEntityReferences|setEntityResolver)",  # XML parser configurations
        r"(?:file|http|ftp|php|expect|data):%2f%2f",  # URL-encoded protocols
        r"\\u0026\\u0023\\u0078[0-9a-fA-F]+;",  # Unicode-encoded entity reference
    ],
    "csrf": [
        # Cross-Site Request Forgery (CSRF) patterns
        r"<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*?>",  # POST form without CSRF token
        r"<\s*form\s+[^>]*?action\s*=\s*['\"][^'\"]+?['\"][^>]*?>\s*(?![^<]*?<\s*input\s+[^>]*?name\s*=\s*['\"]?_csrf|_token|csrf_token|X-CSRF-TOKEN[^'\"]*?['\"]?[^>]*?>)",  # Form without CSRF input
        r"<\s*a\s+[^>]*?href\s*=\s*['\"][^'\"]+?['\"][^>]*?onclick\s*=\s*['\"][^'\"]*?['\"][^>]*?>",  # Anchor with onclick performing state-changing action
        r"XMLHttpRequest\s*\.\s*open\s*\(\s*['\"](?:POST|PUT|DELETE)['\"],",  # AJAX POST/PUT/DELETE without CSRF header
        r"fetch\s*\(\s*['\"][^'\"]+?['\"],.*?\bmethod\s*:\s*['\"](?:POST|PUT|DELETE)['\"].*?\)",  # Fetch API without CSRF token
        r"axios\s*\.\s*(?:post|put|delete)\s*\(\s*['\"][^'\"]+?['\"]",  # Axios without CSRF token
        r"<\s*meta\s+[^>]*?name\s*=\s*['\"]?csrf-token['\"]?[^>]*?content\s*=\s*['\"][^'\"]+?['\"][^>]*?>",  # CSRF token in meta tag
        r"X-CSRF-TOKEN|X-XSRF-TOKEN|CSRF-TOKEN|_csrf|_token|csrf_token",  # Common CSRF token names
        r"(?:form|ajax|fetch|axios)\s*\.\s*submit\s*\(\s*\)",  # Form submission without token validation
        r"<\s*input\s+[^>]*?type\s*=\s*['\"]?hidden['\"]?[^>]*?name\s*=\s*['\"]?_csrf|_token|csrf_token|X-CSRF-TOKEN[^'\"]*?['\"]?[^>]*?>",  # Hidden CSRF input field
        r"(?:POST|PUT|DELETE)\s*['\"][^'\"]+?['\"]\s*,\s*\{[^}]*?headers\s*:\s*\{[^}]*?\}",  # HTTP requests with headers but no CSRF
        r"(?:POST|PUT|DELETE)\s*['\"][^'\"]+?['\"]\s*,\s*\{[^}]*?withCredentials\s*:\s*true[^}]*?\}",  # Requests with credentials but no CSRF
        r"<\s*form\s+[^>]*?enctype\s*=\s*['\"]?multipart/form-data['\"]?[^>]*?>",  # Multipart form without CSRF
        r"(?:sessionStorage|localStorage)\s*\.\s*setItem\s*\(\s*['\"](?:_csrf|_token|csrf_token|X-CSRF-TOKEN)['\"]",  # CSRF token in storage
        r"<\s*script\s+[^>]*?src\s*=\s*['\"][^'\"]+?['\"][^>]*?>\s*<\s*/script\s*>",  # External script loading sensitive actions
        r"(?:form|ajax|fetch|axios)\s*\.\s*(?:submit|send|post|put|delete)\s*\(\s*(?![^)]*?csrf|_token|X-CSRF-TOKEN)",  # Form/action without CSRF
        r"(?:%25|%26|%3C|%3E)[0-9a-fA-F]{2}",  # URL-encoded CSRF token bypass attempts
        r"\\u005f\\u0063\\u0073\\u0072\\u0066|\\u0074\\u006f\\u006b\\u0065\\u006e",  # Unicode-encoded CSRF token names
    ],
    "file_upload": [
        # File upload vulnerability patterns
        r"<\s*input\s+[^>]*?type\s*=\s*['\"]?file['\"]?[^>]*?>",  # File input field
        r"<\s*form\s+[^>]*?enctype\s*=\s*['\"]?multipart/form-data['\"]?[^>]*?>",  # Multipart form for file upload
        r"(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh)\s*['\"][^'\"]*?\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh)['\"]",  # Server-side script extensions
        r"(?:exe|dll|bat|cmd|ps1|vbs|js|jar|war|zip|tar|gz|rar|7z|sh|bash)\s*['\"][^'\"]*?\.(?:exe|dll|bat|cmd|ps1|vbs|js|jar|war|zip|tar|gz|rar|7z|sh|bash)['\"]",  # Executable/dangerous file extensions
        r"<\s*input\s+[^>]*?accept\s*=\s*['\"][^'\"]*?(?:\.php|\.asp|\.exe|\.bat|\.js|\.vbs|\.sh)[^'\"]*?['\"][^>]*?>",  # File input with dangerous accept types
        r"(?:move_uploaded_file|copy|rename|file_put_contents|fwrite)\s*\(\s*['\"][^'\"]+?\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh|exe|dll|bat|cmd|ps1|vbs|js)['\"]",  # File handling functions with dangerous extensions
        r"(?:Content-Type|content-type)\s*:\s*(?:application/x-php|text/x-shellscript|application/x-msdownload|application/x-msdos-program)",  # Dangerous MIME types
        r"(?:Content-Disposition|content-disposition)\s*:\s*attachment;\s*filename\s*=\s*['\"][^'\"]*?\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh|exe|dll|bat|cmd|ps1|vbs|js)['\"]",  # Dangerous filename in disposition
        r"<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*?>\s*(?![^<]*?<\s*input\s+[^>]*?name\s*=\s*['\"]?_csrf|_token|csrf_token|X-CSRF-TOKEN[^'\"]*?['\"]?[^>]*?>)",  # File upload form without CSRF
        r"(?:\.htaccess|web\.config|wp-config\.php|settings\.php|config\.php|configuration\.php)",  # Sensitive configuration files
        r"(?:data|php|file|zip|compress\.zlib|compress\.bzip2|phar)://[^\s]+",  # Stream wrappers in file upload
        r"(?:%2e|%252e|%c0%ae|%e0%80%ae)\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi|sh|exe|dll|bat|cmd|ps1|vbs|js)",  # Encoded dangerous extensions
        r"filename\s*=\s*['\"][^'\"]*?(?:\.\.|%2e%2e|%252e%252e)[^'\"]*?['\"]",  # Path traversal in filename
        r"<\s*input\s+[^>]*?name\s*=\s*['\"][^'\"]+?['\"][^>]*?>\s*(?![^>]*?max-size|size\s*=\s*['\"]?[0-9]+['\"]?[^>]*?)",  # File input without size restriction
        r"(?:exec|shell_exec|system|passthru|proc_open|pcntl_exec)\s*\(\s*['\"][^'\"]+?\.(?:sh|bash|cmd|bat|ps1)['\"]",  # Execution of uploaded files
        r"(?:include|require|require_once|eval)\s*\(\s*['\"][^'\"]+?\.(?:php|inc)['\"]",  # Inclusion of uploaded files
        r"<\s*form\s+[^>]*?action\s*=\s*['\"][^'\"]+?\.(?:php|asp|aspx|jsp|cfm|pl|py|rb|cgi)['\"][^>]*?>",  # Form action to server-side script
        r"(?:%25|%26|%2e|%3a|%3b)[0-9a-fA-F]{2}",  # URL-encoded file upload bypass
        r"\\u002e\\u002f|\\u002e\\u005c",  # Unicode-encoded path traversal
    ],
    "http_response_splitting": [
        # HTTP Response Splitting patterns
        r"(?:\r\n|\n|\r|%0d%0a|%0a|%0d)",  # CR/LF injection
        r"(?:%0d%0a|%0a|%0d)\s*(?:Content-Type|Set-Cookie|Location|Status|HTTP/1\.[0-1])",  # CR/LF with HTTP headers
        r"(?:%0d%0a|%0a|%0d)\s*(?:HTTP/1\.[0-1]\s+[0-9]{3}\s+[^\r\n]*)",  # CR/LF with HTTP status line
        r"(?:%0d%0a|%0a|%0d)\s*(?:Content-Length\s*:\s*[0-9]+)",  # CR/LF with Content-Length
        r"(?:%0d%0a|%0a|%0d)\s*(?:Location\s*:\s*[^\r\n]+)",  # CR/LF with Location header
        r"(?:%0d%0a|%0a|%0d)\s*(?:Set-Cookie\s*:\s*[^\r\n]+)",  # CR/LF with Set-Cookie
        r"(?:%0d%0a|%0a|%0d)\s*(?:Content-Type\s*:\s*[^\r\n]+)",  # CR/LF with Content-Type
        r"(?:\r\n|\n|\r|%0d%0a|%0a|%0d)\s*<!DOCTYPE\s+html",  # CR/LF with HTML injection
        r"(?:\r\n|\n|\r|%0d%0a|%0a|%0d)\s*<\s*html",  # CR/LF with HTML start
        r"(?:\r\n|\n|\r|%0d%0a|%0a|%0d)\s*<\s*script",  # CR/LF with script injection
        r"(?:%25|%23|%26|%3c|%3e)[0-9a-fA-F]{2}",  # URL-encoded CR/LF characters
        r"(?:\\r\\n|\\n|\\r|\\u000d\\u000a|\\u000a|\\u000d)",  # Unicode/escaped CR/LF
        r"header\s*\(\s*['\"][^'\"]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^'\"]*?['\"]\s*\)",  # PHP header function with CR/LF
        r"setcookie\s*\(\s*['\"][^'\"]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^'\"]*?['\"]\s*\)",  # PHP setcookie with CR/LF
        r"Response\.AddHeader\s*\(\s*['\"][^'\"]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^'\"]*?['\"]\s*\)",  # .NET AddHeader with CR/LF
        r"Response\.Redirect\s*\(\s*['\"][^'\"]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^'\"]*?['\"]\s*\)",  # .NET Redirect with CR/LF
        r"res\.writeHead\s*\(\s*[0-9]+,\s*\{[^}]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^}]*?\}\s*\)",  # Node.js writeHead with CR/LF
        r"res\.setHeader\s*\(\s*['\"][^'\"]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^'\"]*?['\"]\s*\)",  # Node.js setHeader with CR/LF
        r"(?:Location|Set-Cookie|Content-Type)\s*:\s*[^\r\n]*?(?:\r\n|\n|\r|%0d%0a|%0a|%0d)[^\r\n]*",  # Header injection
        r"(?:%0d%0a|%0a|%0d)\s*(?:Cache-Control|Pragma|Expires)[^\r\n]*",  # CR/LF with cache headers
    ],
    "ldap_injection": [
        # LDAP Injection patterns
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?\)",  # LDAP filter syntax
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?\*\)",  # LDAP wildcard filter
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?\&[^\)]*?\)",  # LDAP AND operator
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?\|[^\)]*?\)",  # LDAP OR operator
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?![^\)]*?\)",  # LDAP NOT operator
        r"\(\s*objectClass\s*=\s*[^\)]*?\)",  # LDAP objectClass filter
        r"\(\s*cn\s*=\s*[^\)]*?\)",  # LDAP common name filter
        r"\(\s*uid\s*=\s*[^\)]*?\)",  # LDAP user ID filter
        r"\(\s*sn\s*=\s*[^\)]*?\)",  # LDAP surname filter
        r"\(\s*mail\s*=\s*[^\)]*?\)",  # LDAP email filter
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:admin|root|user|manager)[^\)]*?\)",  # LDAP privileged account filter
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?%2a[^\)]*?\)",  # URL-encoded wildcard
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:%26|%7c|%21)[^\)]*?\)",  # URL-encoded logical operators
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:%28|%29)[^\)]*?\)",  # URL-encoded parentheses
        r"(?:%25|%26|%2a|%3d|%3e|%3c)[0-9a-fA-F]{2}",  # URL-encoded LDAP characters
        r"\\u0028\\u0029|\\u003d|\\u002a",  # Unicode-encoded LDAP filter characters
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:password|pass|pwd|credential|secret|token)[^\)]*?\)",  # LDAP sensitive attribute filter
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:dc|ou|o|cn|sn|givenName|mail|uidNumber|gidNumber)[^\)]*?\)",  # LDAP directory attributes
        r"ldap://[^\s]+",  # LDAP protocol in query
        r"ldaps://[^\s]+",  # LDAPS protocol in query
        r"LDAPSearch|LDAPConnection|DirContext|InitialDirContext|NamingEnumeration",  # LDAP API classes
        r"search\s*\(\s*['\"][^'\"]*?\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?\)[^'\"]*?['\"]\s*\)",  # LDAP search filter
        r"(?:%5c|%5e|%7c|%26|%21)[0-9a-fA-F]{2}",  # URL-encoded LDAP special characters
        r"\(\s*[a-zA-Z0-9_]+\s*=\s*[^\)]*?(?:[\x00-\x1f\x7f-\xff])[^\)]*?\)",  # LDAP filter with control characters
    ],
    "ssrf_dns_rebinding": [
        # SSRF DNS Rebinding patterns
        r"(?:http|https|ftp)://(?:[a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}(?:/[^?\s]*)?(?:\?[^#\s]*)?(?:#[^\s]*)?",  # Suspicious dynamic DNS domains
        r"(?:http|https|ftp)://(?:[0-9]{1,3}\.){3}[0-9]{1,3}",  # Direct IP access
        r"(?:http|https|ftp)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)",  # Localhost access
        r"(?:http|https|ftp)://(?:10|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}",  # Private network access
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.[0-9]+(?:\.[0-9]+)?",  # DNS rebinding with numeric suffix
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.[0-9]+\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",  # DNS rebinding with numeric subdomain
        r"(?:http|https|ftp)://[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}",  # UUID-based DNS rebinding
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.local(?:/[^?\s]*)?",  # mDNS (.local) access
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.lan(?:/[^?\s]*)?",  # LAN domain access
        r"(?:%2e|%252e|%c0%ae|%e0%80%ae)\.",  # Encoded dot for domain manipulation
        r"(?:%25|%26|%3a|%3b|%3d)[0-9a-fA-F]{2}",  # URL-encoded DNS characters
        r"\\u002e|\\u003a",  # Unicode-encoded dot or colon
        r"(?:curl|wget|fetch|lwp-request|lynx|links)\s+(?:-[^\s]+\s+)*(?:http|https|ftp)://(?:[a-zA-Z0-9\-]+\.)*[a-zA-Z0-9\-]+\.[0-9]+",  # HTTP client with numeric DNS
        r"dns://[^\s]+",  # DNS protocol in URL
        r"(?:http|https|ftp)://[0-9]+(?:\.[0-9]+){0,3}",  # Numeric domain access
        r"(?:http|https|ftp)://0x[0-9a-fA-F]+(?:\.0x[0-9a-fA-F]+){0,3}",  # Hexadecimal domain access
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.nip\.io",  # nip.io DNS rebinding service
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.xip\.io",  # xip.io DNS rebinding service
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.sslip\.io",  # sslip.io DNS rebinding service
        r"(?:http|https|ftp)://[a-zA-Z0-9\-]+\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:\.[a-zA-Z0-9\-]+)*",  # IP-embedded domain
        r"urllib\.(?:request|parse|error)\.(?:urlopen|urlretrieve|urlparse)",  # Python URL libraries
        r"requests\.(?:get|post|put|delete|head|options|patch)",  # Python requests library
        r"java\.net\.(?:URL|HttpURLConnection|URLConnection)",  # Java networking
        r"curl_(?:init|exec|setopt)",  # PHP cURL functions
        r"file_get_contents|fopen|readfile|include|require",  # PHP file functions
        r"System\.Net\.(?:WebClient|HttpClient|WebRequest|HttpWebRequest)",  # .NET HTTP clients
        r"axios\.(?:get|post|put|delete|head|options|patch)",  # JavaScript axios library
        r"fetch\(|XMLHttpRequest|ActiveXObject\(['\"]Microsoft\.XMLHTTP['\"]\)",  # JavaScript HTTP
        (r"(?:\?|&)(?:url|uri|target|endpoint|dest|redirect|link)=[^&]*(?:[a-zA-Z0-9-]+\.)*(?:localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1|\[::1\])(?:/|$)", 3.0),
    ]
}
