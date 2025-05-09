import json
import sys
import os
import numpy as np
import pickle
import time
import hashlib
from typing import Dict, List, Any, Union, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from sklearn.inspection import permutation_importance
from xgboost import XGBClassifier
import joblib
from imblearn.over_sampling import SMOTE
# from ATTACK_PATTERNS import ATTACK_PATTERNS

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
    ]
}

# Constants
MODEL_DIR = "microservices/models"
MODEL_VERSION = "v1.0"
FEATURES_FILE = f"{MODEL_DIR}/features_{MODEL_VERSION}.json"
MODEL_FILE = f"{MODEL_DIR}/ml_model_{MODEL_VERSION}.joblib"
SCALER_FILE = f"{MODEL_DIR}/scaler_{MODEL_VERSION}.joblib"
META_FILE = f"{MODEL_DIR}/meta_{MODEL_VERSION}.json"
LOG_FILE = f"{MODEL_DIR}/ml_service_{MODEL_VERSION}.log"

# Suspicious keywords for feature extraction
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "verify", "account", "auth", "banking", "payment",
    "admin", "update", "confirm", "session", "token", "password", "credential"
]

def ensure_directories():
    """Create necessary directories if they don't exist."""
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR, exist_ok=True)

def log(message, data=None, level="INFO"):
    """Enhanced logging with levels and file output."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {"timestamp": timestamp, "level": level, "message": message}
    if data is not None:
        log_entry.update(data)
    
    print(json.dumps(log_entry), file=sys.stderr)
    
    ensure_directories()
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} [{level}] {message} {json.dumps(data) if data else ''}\n")


def detect_base64_params(url: str) -> float:
    """Detect Base64-encoded parameters in the URL query string."""
    import re
    import base64
    from urllib.parse import urlparse, parse_qs

    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        query = parsed.query
        if not query:
            return 0.0

        # Parse query parameters
        query_params = parse_qs(query)
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')

        # Check each parameter value for Base64 encoding
        for param_values in query_params.values():
            for value in param_values:
                # Look for strings that look like Base64 (at least 16 chars to avoid false positives)
                chunks = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', value)
                for chunk in chunks:
                    if base64_pattern.match(chunk):
                        try:
                            decoded = base64.b64decode(chunk).decode('utf-8')
                            if any(c.isprintable() for c in decoded):
                                return 1.0  # Base64-encoded parameter detected
                        except:
                            pass
        return 0.0

    except Exception:
        return 0.0

def extract_advanced_features(input_data: Union[str, Dict]) -> Dict[str, float]:
    """Extract advanced features from input data (URL or parsed features)."""
    features = {}
    
    if isinstance(input_data, dict):
        return input_data
    
    url = input_data
    features["length"] = len(url)
    features["entropy"] = calculate_entropy(url)
    features["digit_ratio"] = len([c for c in url if c.isdigit()]) / max(len(url), 1)
    
    special_chars = len([c for c in url if not c.isalnum() and c not in ['/', '?', '=', '&', ':', '-', '.']])
    features["special_char_ratio"] = min(special_chars / max(len(url), 1), 0.3)
    
    # Check for URL shorteners
    shortener_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly"]
    features["is_shortened"] = 1.0 if any(domain in url.lower() for domain in shortener_domains) else 0.0
    
    # Detect punycode/IDN homograph attacks
    features["has_punycode"] = 1.0 if "xn--" in url.lower() else 0.0
    
    # Detect AWS/Azure/GCP metadata service targeting
    cloud_metadata = ["169.254.169.254", "metadata.google.internal", "instance-data", "metadata"]
    features["targets_cloud_metadata"] = 1.0 if any(target in url.lower() for target in cloud_metadata) else 0.0
    
    # Detect evasion techniques
    features["has_base64_params"] = detect_base64_params(url)
    
    features["char_diversity_ratio"] = len(set(url)) / max(len(url), 1)
    features["percent_encoded_chars"] = url.count('%') / max(len(url), 1)
    features["double_encoded"] = 1.0 if '%25' in url else 0.0
    features["hex_ratio"] = len([i for i in range(len(url)-1) if url[i:i+2].lower() in 
                              ['0x', '\\x']]) / max(len(url)-1, 1)
    
    attack_pattern_count = 0
    for pattern_type, patterns in ATTACK_PATTERNS.items():
        features[f"has_{pattern_type}"] = 0
        for pattern in patterns:
            import re
            if re.search(pattern, url, re.IGNORECASE):
                # Further increase weight for SSRF and Path Traversal detection
                weight = 5.0 if pattern_type in ["ssrf", "path_traversal"] else 1.0
                features[f"has_{pattern_type}"] = weight
                attack_pattern_count += 1
                print(f"Detected {pattern_type} with weight {weight} for URL: {url}")  # Debug print
                break
    features["attack_pattern_count"] = min(attack_pattern_count, 3) / 3.0
    
    features["suspicious_keyword_count"] = min(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw.lower() in url.lower() and kw.lower() not in ['login', 'secure']), 2) / 2.0
    
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        
        features["domain_length"] = len(parsed.netloc)
        features["path_length"] = len(parsed.path)
        
        features["query_length"] = min(len(parsed.query), 20) / 20.0
        query_params = parse_qs(parsed.query)
        features["param_count"] = min(len(query_params), 2) / 2.0
        
        features["subdomain_count"] = parsed.netloc.count('.')
        features["path_depth"] = parsed.path.count('/')
        features["fragment_length"] = len(parsed.fragment)
        
        features["url_entropy_segments"] = calculate_segment_entropy(url)
        features["url_length_ratio"] = len(parsed.path) / max(len(url), 1)
        features["avg_param_length"] = calculate_avg_param_length(query_params)
        features["js_obfuscation_score"] = detect_js_obfuscation(url)
        features["consecutive_special_chars"] = count_consecutive_specials(url)

        tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
        features["tld_length"] = len(tld)
        features["is_common_tld"] = 1.0 if tld.lower() in ['com', 'org', 'net', 'edu', 'gov'] else 0.0
        
        if ':' in parsed.netloc:
            port = parsed.netloc.split(':')[1]
            features["unusual_port"] = 1.0 if port not in ['80', '443'] else 0.0
        else:
            features["unusual_port"] = 0.0
            
        features["domain_similarity"] = calculate_domain_similarity(parsed.netloc)
        
        if "domain_length" in features:
            try:
                features["brand_impersonation"] = detect_brand_impersonation(parsed.netloc)
            except:
                features["brand_impersonation"] = 0.0

    except Exception:
        url_features = [
            "domain_length", "path_length", "query_length", "subdomain_count",
            "path_depth", "param_count", "fragment_length", "tld_length",
            "is_common_tld", "unusual_port", "domain_similarity",
            "url_entropy_segments", "url_length_ratio", "avg_param_length",
            "js_obfuscation_score", "consecutive_special_chars"
        ]
        for feature in url_features:
            features[feature] = 0.0
    
    import base64
    import re
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
    features["contains_base64"] = 0.0
    
    chunks = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', url)
    for chunk in chunks:
        if base64_pattern.match(chunk):
            try:
                decoded = base64.b64decode(chunk).decode('utf-8')
                if any(c.isprintable() for c in decoded):
                    features["contains_base64"] = 1.0
                    break
            except:
                pass
    
    return features

def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += -p_x * np.log2(p_x)
    return entropy

def calculate_domain_similarity(domain: str) -> float:
    """Calculate similarity to common domains using Levenshtein distance."""
    common_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "facebook.com"]
    min_distance = float('inf')
    
    for common in common_domains:
        distance = levenshtein_distance(domain.lower(), common)
        min_distance = min(min_distance, distance)
    
    # Normalize to 0-1 (lower distance = higher similarity)
    return 1.0 / (1.0 + min_distance)

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def preprocess_features(features_dict: Dict[str, float]) -> np.ndarray:
    """Convert a features dictionary to a numpy array with consistent ordering."""
    ensure_directories()
    
    feature_names = []
    if os.path.exists(FEATURES_FILE):
        with open(FEATURES_FILE, "r") as f:
            feature_names = json.load(f)
    else:
        feature_names = sorted(features_dict.keys())
        with open(FEATURES_FILE, "w") as f:
            json.dump(feature_names, f)
    
    feature_vector = []
    for feature in feature_names:
        feature_vector.append(features_dict.get(feature, 0.0))
    
    missing_features = set(features_dict.keys()) - set(feature_names)
    if missing_features:
        log("New features detected but not used", {"new_features": list(missing_features)}, "WARNING")
        
    return np.array(feature_vector).reshape(1, -1)



def create_ensemble_model():
    """Create a more efficient ensemble model for production."""
    rf = RandomForestClassifier(
        n_estimators=50,
        max_depth=8,
        min_samples_split=50,
        min_samples_leaf=20,
        n_jobs=-1,  # Use all available cores
        random_state=42
    )
    
    # XGBoost is very efficient for production
    xgb = XGBClassifier(
        n_estimators=100,  # Increased for better performance
        learning_rate=0.1,  # Slightly higher learning rate
        max_depth=5,        # Slightly deeper trees
        tree_method='hist', # Histogram-based algorithm for faster training
        reg_lambda=1.0,     # L2 regularization
        random_state=42
    )
    
    # Simplified ensemble with just two models for speed
    ensemble = VotingClassifier(
        estimators=[
            ('rf', rf),
            ('xgb', xgb)
        ],
        voting='soft',
        weights=[1, 2]  # Give more weight to XGBoost
    )
    
    return ensemble

def train_model(inputs, outputs):
    """Train the model with the given inputs and outputs."""
    ensure_directories()
    
    start_time = time.time()
    log("Processing training data")
    
    if isinstance(inputs[0], (list, np.ndarray)):
        X = np.array(inputs, dtype=np.float32)
    else:
        features_list = []
        for input_item in inputs:
            features = extract_advanced_features(input_item)
            features_list.append(features)
        
        feature_vecs = []
        for features in features_list:
            vec = preprocess_features(features).flatten()
            feature_vecs.append(vec)
        X = np.array(feature_vecs, dtype=np.float32)
    
    y = np.array(outputs, dtype=np.int32)
    
    # Handle imbalanced data with SMOTE
    smote = SMOTE(random_state=42)
    X, y = smote.fit_resample(X, y)
    log("Applied SMOTE for data balancing", {"new_sample_count": len(y)})
    
    # Split data for validation
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    # Hyperparameter tuning with a smaller search space
    param_grid = {
        'xgb__n_estimators': [50, 100],
        'xgb__max_depth': [2, 3],
        'rf__n_estimators': [50, 100],
        'rf__max_depth': [5, 8]
    }
    
    model = create_ensemble_model()
    grid_search = GridSearchCV(
        model, param_grid, cv=3, scoring='roc_auc', n_jobs=-1
    )
    grid_search.fit(X_train_scaled, y_train)
    
    model = grid_search.best_estimator_
    log("Best hyperparameters", {"params": grid_search.best_params_})
    
    # Cross-validation scores
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
    log("Cross-validation completed", {"cv_scores": cv_scores.tolist(), "mean_cv_score": float(cv_scores.mean())})
    
    # Evaluate model
    train_score = model.score(X_train_scaled, y_train)
    val_score = model.score(X_val_scaled, y_val)
    
    y_val_probs = model.predict_proba(X_val_scaled)[:, 1]
    auc_score = roc_auc_score(y_val, y_val_probs)
    
    precision, recall, _ = precision_recall_curve(y_val, y_val_probs)
    pr_auc = auc(recall, precision)
    
    # Permutation importance
    perm_importance = permutation_importance(model, X_val_scaled, y_val, n_repeats=10, random_state=42)
    
    feature_names = []
    with open(FEATURES_FILE, "r") as f:
        feature_names = json.load(f)
    
    # Get top features by permutation importance
    top_indices = np.argsort(perm_importance.importances_mean)[::-1][:10]
    top_features = [feature_names[i] for i in top_indices]
    top_importance = [float(perm_importance.importances_mean[i]) for i in top_indices]
    
    # Save model and metadata
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    
    meta = {
        "training_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "model_version": MODEL_VERSION,
        "num_samples": len(inputs),
        "num_features": X.shape[1],
        "train_accuracy": float(train_score),
        "validation_accuracy": float(val_score),
        "auc_score": float(auc_score),
        "pr_auc": float(pr_auc),
        "cv_scores": cv_scores.tolist(),
        "mean_cv_score": float(cv_scores.mean()),
        "top_features": top_features,
        "top_importance": top_importance,
        "pos_class_ratio": float(np.mean(y))
    }
    
    with open(META_FILE, "w") as f:
        json.dump(meta, f)
    
    training_time = time.time() - start_time
    log("Model trained and saved", {
        "model_path": MODEL_FILE,
        "train_accuracy": train_score,
        "validation_accuracy": val_score,
        "auc_score": auc_score,
        "pr_auc": pr_auc,
        "training_time_sec": training_time,
        "top_features": top_features
    })
    
    return meta

def predict(inputs):
    """Make predictions with enhanced output."""
    ensure_directories()
    
    start_time = time.time()
    
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        log("Model and scaler loaded")
        
        results = []
        feature_vectors = []
        extracted_features = []
        
        for input_item in inputs:
            features = extract_advanced_features(input_item)
            extracted_features.append(features)
            vec = preprocess_features(features).flatten()
            feature_vectors.append(vec)
            
        X = np.array(feature_vectors, dtype=np.float32)
        X_scaled = scaler.transform(X)
        probabilities = model.predict_proba(X_scaled)[:, 1]
        
        # Check for model drift
        drift_result = check_model_drift(extracted_features)
        
        # Get top contributing features for each prediction
        top_features = get_top_contributing_features(model, X_scaled, extracted_features)
        
        for i, input_item in enumerate(inputs):
            prob = probabilities[i]
            classification = "malicious" if prob > 0.5 else "benign"
            confidence = prob if prob > 0.5 else 1.0 - prob
            threat_types = identify_threat_types(extracted_features[i])
            
            results.append({
                "input": input_item,
                "probability": float(prob),
                "classification": classification,
                "confidence": float(confidence),
                "threat_types": threat_types,
                "top_features": top_features[i]
            })
        
        prediction_time = time.time() - start_time
        
        return {
            "status": "success",
            "model_version": MODEL_VERSION,
            "prediction_time_ms": round(prediction_time * 1000, 2),
            "model_drift": drift_result["status"] if "status" in drift_result else "unknown",
            "probabilities": probabilities.tolist(),
            "detailed_results": results
        }
    
    except Exception as e:
        log("Prediction failed", {"error": str(e)}, "ERROR")
        return {
            "status": "error",
            "message": f"Prediction failed: {str(e)}"
        }

def generate_training_data(num_samples=1000, malicious_ratio=0.5):
    """Generate synthetic training data for model development with improved variability."""
    log("Generating synthetic training data", {
        "num_samples": num_samples,
        "malicious_ratio": malicious_ratio
    })
    
    benign_count = int(num_samples * (1 - malicious_ratio))
    malicious_count = num_samples - benign_count
    
    urls = []
    labels = []
    attack_types = []  # Track attack types for better logging
    
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
        # Determine the attack type 
        attack_type = next((key for key, patterns in ATTACK_PATTERNS.items() if any(p in url for p in patterns)), "unknown")
        attack_types.append(attack_type)
    
    # Shuffle the data
    data = list(zip(urls, labels, attack_types))
    random.shuffle(data)  # Use random.shuffle for simplicity
    urls, labels, attack_types = zip(*data)
    
    # Log detailed statistics
    attack_type_counts = {}
    for at in attack_types:
        attack_type_counts[at] = attack_type_counts.get(at, 0) + 1
    
    log("Synthetic data generation complete", {
        "benign_count": benign_count,
        "malicious_count": malicious_count,
        "attack_type_distribution": attack_type_counts
    })
    
    return list(urls), list(labels)
def generate_benign_url():
    """Generate a synthetic benign URL."""
    domains = [
        "example.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
        "github.com", "stackoverflow.com", "linkedin.com", "twitter.com", "facebook.com",
        "youtube.com", "instagram.com", "reddit.com", "wikipedia.org", "yahoo.com",
        "netflix.com", "zoom.us", "slack.com", "spotify.com", "adobe.com"
    ]
    
    tlds = ["com", "org", "net", "edu", "gov", "io", "co", "ai", "app"]
    
    paths = [
        "", "/", "/index.html", "/about", "/contact", "/products", "/services",
        "/blog", "/news", "/faq", "/help", "/support", "/login", "/register",
        "/dashboard", "/account", "/settings", "/profile", "/search", "/terms"
    ]
    
    query_params = [
        "", "?id=123", "?page=1", "?q=search", "?ref=home", "?source=direct",
        "?utm_source=google", "?lang=en", "?category=tech", "?filter=recent"
    ]
    
    domain = np.random.choice(domains)
    path = np.random.choice(paths)
    query = np.random.choice(query_params)
    
    if np.random.random() < 0.3:
        subdomains = ["www", "blog", "shop", "support", "docs", "help", "dev"]
        domain = f"{np.random.choice(subdomains)}.{domain}"
    
    protocol = "https://" if np.random.random() < 0.8 else "http://"
    
    return f"{protocol}{domain}{path}{query}"

#begin
# model_enhancements.py

import re
import numpy as np
import json
import os
from urllib.parse import urlparse, parse_qs
from collections import Counter
from microservices.nehonix_shield_model import log

def calculate_segment_entropy(url):
    """Calculate entropy on different URL segments."""
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        
        domain_entropy = calculate_entropy(parsed.netloc) if parsed.netloc else 0
        path_entropy = calculate_entropy(parsed.path) if parsed.path else 0
        query_entropy = calculate_entropy(parsed.query) if parsed.query else 0
        
        # Weight segments by their security importance
        weighted_entropy = (domain_entropy * 0.3) + (path_entropy * 0.3) + (query_entropy * 0.4)
        return min(weighted_entropy, 5.0)  # Cap at 5.0
    except:
        return 0.0

def calculate_entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data or len(data) == 0:
        return 0
    
    entropy = 0
    char_count = Counter(data)
    data_len = len(data)
    
    for count in char_count.values():
        p_x = count / data_len
        entropy += -p_x * np.log2(p_x)
    
    return entropy

def calculate_avg_param_length(query_params):
    """Calculate average length of parameter values."""
    if not query_params:
        return 0.0
        
    total_length = 0
    param_count = 0
    
    for param, values in query_params.items():
        for value in values:
            total_length += len(value)
            param_count += 1
    
    return min((total_length / max(param_count, 1)) / 10.0, 1.0)  # Normalize and cap

def detect_js_obfuscation(url):
    """Detect JavaScript obfuscation techniques."""
    js_obfuscation_patterns = [
        r'eval\s*\(', r'atob\s*\(', r'unescape\s*\(', r'decodeURIComponent\s*\(',
        r'escape\s*\(', r'String\.fromCharCode', r'\\\d{2,3}',
        r'\\[ux][0-9a-f]{2,4}', r'\+\s*\+\s*\[', r'\[\s*[\'"][^\'"]*[\'"]\s*\]\s*\[\s*[\'"][^\'"]*[\'"]\s*\]'
    ]
    
    obfuscation_score = 0.0
    
    for pattern in js_obfuscation_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            obfuscation_score += 0.125  # Each pattern adds to the score
    
    return min(obfuscation_score, 1.0)  # Cap at 1.0

def count_consecutive_specials(url):
    """Count sequences of consecutive special characters."""
    special_chars = set('!@#$%^&*()_+-=[]{}|;:\'",.<>/?\\~`')
    
    max_consecutive = 0
    current_consecutive = 0
    
    for char in url:
        if char in special_chars:
            current_consecutive += 1
            max_consecutive = max(max_consecutive, current_consecutive)
        else:
            current_consecutive = 0
    
    return min(max_consecutive / 5.0, 1.0)  # Normalize and cap at 1.0

def detect_brand_impersonation(domain):
    """Detect if domain is trying to impersonate popular brands."""
    popular_brands = [
        "google", "microsoft", "apple", "amazon", "facebook", 
        "netflix", "paypal", "twitter", "instagram", "linkedin",
        "dropbox", "gmail", "yahoo", "outlook", "spotify",
        "chase", "wellsfargo", "bankofamerica", "citibank", "amex"
    ]
    
    # Remove TLD and common subdomain prefixes
    clean_domain = domain.lower()
    for prefix in ["www.", "mail.", "login.", "secure.", "account."]:
        if clean_domain.startswith(prefix):
            clean_domain = clean_domain[len(prefix):]
    
    # Extract main domain without TLD
    parts = clean_domain.split('.')
    main_domain = parts[0] if len(parts) > 0 else ""
    
    # Check for brand impersonation with typosquatting
    for brand in popular_brands:
        # Exact match
        if brand == main_domain:
            return 0.0  # Likely legitimate
        
        # Levenshtein distance for close matches
        if levenshtein_distance(brand, main_domain) <= 2 and brand != main_domain:
            return 1.0  # Likely impersonation
        
        # Brand contained with additions
        if brand in main_domain and main_domain != brand:
            return 0.8  # Suspicious
        
        # Check for homograph attacks (similar looking characters)
        homograph_score = check_homograph_attack(brand, main_domain)
        if homograph_score > 0.5:
            return homograph_score
    
    return 0.0

def check_homograph_attack(original, test):
    """Check for homograph attacks (similar looking characters)."""
    homographs = {
        'a': ['а', '@', '4', 'α', 'а'],
        'b': ['b', 'ƅ', 'ь', 'β'],
        'c': ['с', 'ϲ', '¢', 'ℂ'],
        'd': ['ԁ', 'ð', 'đ'],
        'e': ['е', 'ė', 'ё', 'є', 'ε'],
        'g': ['ɡ', 'ց', 'ǵ', 'ģ'],
        'h': ['һ', 'ħ', 'ή'],
        'i': ['і', 'ị', 'ı', '1', 'l', '|', 'ι'],
        'j': ['ј', 'ʝ'],
        'k': ['ḳ', 'қ', 'κ'],
        'l': ['1', 'ӏ', 'ḷ', 'ι'],
        'm': ['ṃ', 'м', 'ɱ'],
        'n': ['ո', 'ν', 'η'],
        'o': ['о', '0', 'ο', 'ө', 'ӧ'],
        'p': ['р', 'ρ', 'ṗ'],
        'q': ['ԛ', 'գ'],
        'r': ['г', 'ṛ', 'ŗ'],
        's': ['ѕ', 'ṣ', 'ś'],
        't': ['т', 'ţ', 'ṭ'],
        'u': ['υ', 'ս', 'μ'],
        'v': ['ν', 'v', 'ѵ'],
        'w': ['ԝ', 'ѡ', 'ա'],
        'x': ['х', '×', 'ҳ'],
        'y': ['у', 'ý', 'ÿ'],
        'z': ['ż', 'ź', 'ʐ']
    }
    
    # If lengths are very different, not a homograph attack
    if abs(len(original) - len(test)) > len(original) * 0.3:
        return 0.0
    
    match_count = 0
    check_chars = min(len(original), len(test))
    
    for i in range(check_chars):
        original_char = original[i].lower()
        test_char = test[i].lower()
        
        # Exact match
        if original_char == test_char:
            match_count += 1
            continue
            
        # Check homograph
        if original_char in homographs and test_char in homographs[original_char]:
            match_count += 0.8  # Partial match for homograph
    
    return (match_count / len(original)) if len(original) > 0 else 0.0

def enhance_training(training_urls, training_labels):
    """Enhance training data with additional examples and augmentation."""
    from microservices.nehonix_shield_model import log
    import numpy as np
    
    log("Enhancing training data")
    
    urls = list(training_urls)
    labels = list(training_labels)
    
    # Generate targeted augmented examples
    augmented_count = min(len(urls) // 5, 2000)  # 20% augmentation or max 2000
    
    for i in range(augmented_count):
        idx = np.random.randint(0, len(urls))
        url = urls[idx]
        label = labels[idx]
        
        if label == 1:  # Malicious
            # Create variant with different encoding or obfuscation
            augmented_url = augment_malicious_url(url)
            urls.append(augmented_url)
            labels.append(1)
        else:  # Benign
            # Create benign variant
            augmented_url = augment_benign_url(url)
            urls.append(augmented_url)
            labels.append(0)
    
    log(f"Training data enhanced", {
        "original_size": len(training_urls),
        "augmented_size": len(urls),
        "augmented_count": len(urls) - len(training_urls)
    })
    
    return urls, labels

def augment_malicious_url(url):
    """Create augmented variants of malicious URLs."""
    parsed = urlparse(url)
    
    # Choose a random augmentation technique
    technique = np.random.choice([
        'encode_path',
        'obfuscate_payload',
        'add_benign_params',
        'change_case'
    ])
    
    if technique == 'encode_path':
        # URL encode some characters in the path
        path_chars = list(parsed.path)
        for i in range(len(path_chars)):
            if np.random.random() < 0.3 and path_chars[i].isalnum():
                path_chars[i] = f"%{ord(path_chars[i]):02x}"
        new_path = ''.join(path_chars)
        return url.replace(parsed.path, new_path)
        
    elif technique == 'obfuscate_payload':
        # Replace spaces in payloads with variants
        if 'script' in url:
            variations = ['script', 'scr ipt', 'scr+ipt', 'scr%20ipt', 's%63ript']
            choice = np.random.choice(variations)
            return url.replace('script', choice)
        else:
            return url
            
    elif technique == 'add_benign_params':
        # Add benign-looking parameters
        benign_params = ['ref=home', 'source=direct', 'lang=en', 'view=1', 'theme=dark']
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}{np.random.choice(benign_params)}"
        
    elif technique == 'change_case':
        # Mix upper and lower case in the URL
        return ''.join([c.upper() if np.random.random() < 0.3 else c.lower() for c in url])
    
    return url

def augment_benign_url(url):
    """Create augmented variants of benign URLs."""
    parsed = urlparse(url)
    
    # Choose a random augmentation technique
    technique = np.random.choice([
        'add_params',
        'add_fragment',
        'change_path',
        'add_subdomain'
    ])
    
    if technique == 'add_params':
        # Add legitimate query parameters
        params = ['page=1', 'sort=newest', 'filter=all', 'view=grid', 'size=20']
        separator = '&' if '?' in url else '?'
        return f"{url}{separator}{np.random.choice(params)}"
        
    elif technique == 'add_fragment':
        # Add a fragment identifier
        fragments = ['top', 'content', 'main', 'section1', 'results']
        return f"{url}#{np.random.choice(fragments)}"
        
    elif technique == 'change_path':
        # Add or modify path component
        paths = ['/index.html', '/about', '/products', '/services', '/contact']
        if parsed.path and parsed.path != '/':
            return url
        else:
            base_url = url.split('?')[0]
            query = f"?{parsed.query}" if parsed.query else ""
            return f"{base_url}{np.random.choice(paths)}{query}"
            
    elif technique == 'add_subdomain':
        # Add a subdomain if none exists
        if parsed.netloc and '.' in parsed.netloc and not parsed.netloc.startswith('www.'):
            subdomains = ['www', 'blog', 'shop', 'support', 'help']
            scheme = f"{parsed.scheme}://" if parsed.scheme else ""
            return url.replace(f"{scheme}{parsed.netloc}", f"{scheme}{np.random.choice(subdomains)}.{parsed.netloc}")
    
    return url

def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]
#end

#new 2
def identify_threat_types(features, prediction_prob):
    """Identify likely attack types based on features."""
    threat_types = []
    
    # Debug: Print all relevant feature values
    print(f"Features for threat type identification: {[(key, value) for key, value in features.items() if key.startswith('has_')]}")
    
    # Check each attack pattern
    for pattern_type in ATTACK_PATTERNS.keys():
        # Adjust threshold for weighted features (SSRF and Path Traversal use 3.0, others 1.0)
        if features.get(f"has_{pattern_type}", 0) > 0.1:  # Lower threshold to catch all non-zero values
            threat_types.append(pattern_type)
    
    # Add brand impersonation as a threat type
    if features.get("brand_impersonation", 0) > 0.7:
        threat_types.append("brand_impersonation")
        
    # Add cloud metadata targeting
    if features.get("targets_cloud_metadata", 0) > 0.5:
        threat_types.append("cloud_metadata_access")
        
    return threat_types if threat_types else ["unknown"] if prediction_prob > 0.5 else []

def predict(inputs):
    """Make predictions with enhanced output."""
    ensure_directories()
    
    start_time = time.time()
    
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        log("Model and scaler loaded")
        
        results = []
        feature_vectors = []
        extracted_features = []
        
        for input_item in inputs:
            features = extract_advanced_features(input_item)
            extracted_features.append(features)
            vec = preprocess_features(features).flatten()
            feature_vectors.append(vec)
            
        X = np.array(feature_vectors, dtype=np.float32)
        X_scaled = scaler.transform(X)
        probabilities = model.predict_proba(X_scaled)[:, 1]
        
        # Check for model drift
        drift_result = check_model_drift(extracted_features)
        
        # Get top contributing features for each prediction
        top_features = get_top_contributing_features(model, X_scaled, extracted_features)
        
        for i, input_item in enumerate(inputs):
            prob = probabilities[i]
            classification = "malicious" if prob > 0.5 else "benign"
            confidence = prob if prob > 0.5 else 1.0 - prob
            threat_types = identify_threat_types(extracted_features[i], prob)  # Pass prediction probability
            
            results.append({
                "input": input_item,
                "probability": float(prob),
                "classification": classification,
                "confidence": float(confidence),
                "threat_types": threat_types,
                "top_features": top_features[i]
            })
        
        prediction_time = time.time() - start_time
        
        return {
            "status": "success",
            "model_version": MODEL_VERSION,
            "prediction_time_ms": round(prediction_time * 1000, 2),
            "model_drift": drift_result["status"] if "status" in drift_result else "unknown",
            "probabilities": probabilities.tolist(),
            "detailed_results": results
        }
    
    except Exception as e:
        log("Prediction failed", {"error": str(e)}, "ERROR")
        return {
            "status": "error",
            "message": f"Prediction failed: {str(e)}"
        }

def get_top_contributing_features(model, X_scaled, extracted_features, top_n=3):
    """Get the top contributing features for each prediction."""
    feature_names = []
    with open(FEATURES_FILE, "r") as f:
        feature_names = json.load(f)
    
    all_top_features = []
    
    # For ensemble models, check if we can get feature importances
    if hasattr(model, "estimators_") and len(model.estimators_) > 0:
        if hasattr(model.estimators_[0], "feature_importances_"):
            importances = model.estimators_[0].feature_importances_
            
            for i in range(X_scaled.shape[0]):
                # Get feature values for this sample
                sample_values = X_scaled[i]
                
                # Calculate contribution (importance * value)
                contributions = importances * sample_values
                
                # Get top contributing features
                top_indices = np.argsort(contributions)[-top_n:]
                
                top_feats = []
                for idx in reversed(top_indices):
                    feat_name = feature_names[idx]
                    contrib = float(contributions[idx])
                    orig_value = extracted_features[i].get(feat_name, 0)
                    
                    top_feats.append({
                        "name": feat_name,
                        "contribution": contrib,
                        "value": orig_value
                    })
                
                all_top_features.append(top_feats)
    else:
        # If we can't get feature importances, return empty lists
        all_top_features = [[] for _ in range(X_scaled.shape[0])]
    
    return all_top_features

def check_model_drift(new_data_features, labels=None):
    """Monitor if the feature distribution has changed, suggesting model drift."""
    try:
        # Load reference statistics from training
        if not os.path.exists(f"{MODEL_DIR}/feature_stats_{MODEL_VERSION}.json"):
            return {"status": "unknown", "message": "Reference statistics not found"}
            
        with open(f"{MODEL_DIR}/feature_stats_{MODEL_VERSION}.json", 'r') as f:
            reference_stats = json.load(f)
        
        # Compare distributions
        drift_detected = False
        drift_features = []
        
        # Calculate mean and std for each feature in new data
        new_stats = {}
        for feature in new_data_features[0].keys():
            if feature in reference_stats:
                values = [d.get(feature, 0) for d in new_data_features]
                new_mean = sum(values) / len(values)
                new_std = (sum((x - new_mean) ** 2 for x in values) / len(values)) ** 0.5
                
                # Check if mean is more than 2 std deviations from reference
                ref_mean = reference_stats[feature]["mean"]
                ref_std = reference_stats[feature]["std"]
                
                if abs(new_mean - ref_mean) > 2 * ref_std:
                    drift_detected = True
                    drift_features.append(feature)
                    
                new_stats[feature] = {"mean": new_mean, "std": new_std}
        
        return {
            "status": "drift_detected" if drift_detected else "normal",
            "drift_features": drift_features,
            "new_stats": new_stats
        }
        
    except Exception as e:
        log("Drift detection failed", {"error": str(e)}, "ERROR")
        return {"status": "error", "message": str(e)}

def save_feature_stats(X):
    """Save feature statistics for drift detection."""
    stats = {}
    feature_names = []
    with open(FEATURES_FILE, "r") as f:
        feature_names = json.load(f)
    
    for i, feature in enumerate(feature_names):
        values = X[:, i]
        stats[feature] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values)),
            "min": float(np.min(values)),
            "max": float(np.max(values))
        }
    
    with open(f"{MODEL_DIR}/feature_stats_{MODEL_VERSION}.json", 'w') as f:
        json.dump(stats, f)

    
#end 2

def generate_malicious_url():
    """Generate a synthetic malicious URL with attack patterns."""
    attack_types = list(ATTACK_PATTERNS.keys())
    # Increase probability of SSRF and Path Traversal to generate more examples
    probabilities = [0.2 if at in ["ssrf", "path_traversal"] else 0.1 for at in attack_types]
    probabilities = [p / sum(probabilities) for p in probabilities]
    attack_type = np.random.choice(attack_types, p=probabilities)
    
    patterns = ATTACK_PATTERNS[attack_type]
    attack_pattern = np.random.choice(patterns)
    
    domains = [
        "example.com", "login-secure.com", "account-verify.net", "secure-payment.org",
        "banking-online.com", "verification-required.net", "customer-support.org"
    ]
    
    suspicious_tlds = ["xyz", "info", "top", "club", "pw", "cn", "ru", "tk"]
    
    domain = np.random.choice(domains)
    
    if np.random.random() < 0.7:
        domain_parts = domain.split('.')
        domain = f"{domain_parts[0]}.{np.random.choice(suspicious_tlds)}"
    
    if np.random.random() < 0.6:
        suspicious_subdomains = ["secure", "login", "account", "verify", "banking", "update"]
        domain = f"{np.random.choice(suspicious_subdomains)}.{domain}"
    
    if attack_type == "sql_injection":
        path = "/login.php"
        query = f"?id=1{attack_pattern.replace(r'(\s|\+)*', '')}"
    elif attack_type == "xss":
        path = "/search"
        query = f"?q={attack_pattern.replace(r'(\s|\+)*', '')}"
    elif attack_type == "path_traversal":
        path_variants = ["/download.php", "/getfile", "/resources", "/static", "/assets"]
        path = np.random.choice(path_variants)
        payloads = [
            f"?file={attack_pattern.replace(r'(\s|\+)*', '')}etc/passwd",
            f"?path=../{attack_pattern.replace(r'(\s|\+)*', '')}windows/win.ini",
            f"?dir=../../{attack_pattern.replace(r'(\s|\+)*', '')}etc/shadow",
            f"?file=..%2F..%2F..%2Fetc%2Fpasswd",
            f"?resource=../etc/passwd%00"
        ]
        query = np.random.choice(payloads)
    elif attack_type == "command_injection":
        path = "/process"
        query = f"?cmd=ls{attack_pattern.replace(r'(\s|\+)*', '')}"
    elif attack_type == "prototype_pollution":
        path = "/api/user"
        query = f"?{attack_pattern.replace(r'(\s|\+)*', '')}=1"
    elif attack_type == "deserialization":
        path = "/api/data"
        query = f"?data={attack_pattern.replace(r'(\s|\+)*', '')}"
    elif attack_type == "jwt_manipulation":
        path = "/auth"
        query = f"?token={attack_pattern.replace(r'(\s|\+)*', '')}"
    elif attack_type == "ssrf":
        path_variants = ["/fetch", "/proxy", "/api/external", "/get", "/redirect"]
        path = np.random.choice(path_variants)
        ssrf_targets = [
            f"http://{attack_pattern.replace(r'(\s|\+)*', '')}/admin",
            f"http://169.254.169.254/latest/meta-data/",
            f"gopher://127.0.0.1:22/_test",
            f"file:///etc/passwd",
            f"http://[::1]/admin"
        ]
        query = f"?url={np.random.choice(ssrf_targets)}"
    else:
        path = "/index.php"
        query = f"?id={attack_pattern.replace(r'(\s|\+)*', '')}"
    
    if np.random.random() < 0.4:
        attack_components = list(query)
        for i in range(len(attack_components)):
            if np.random.random() < 0.2 and attack_components[i].isalnum():
                attack_components[i] = f"%{ord(attack_components[i]):02x}"
        query = ''.join(attack_components)
    
    fragment = ""
    if np.random.random() < 0.3:
        fragments = ["#login", "#redirect", "#payload", "#exec", "#admin"]
        fragment = np.random.choice(fragments)
    
    protocol = "http://" if np.random.random() < 0.7 else "https://"
    
    return f"{protocol}{domain}{path}{query}{fragment}"

if __name__ == "__main__":
    ensure_directories()
    
    try:
        try:
            data = json.load(sys.stdin)
            log("Command received", {"command": data.get("command")})
        except json.JSONDecodeError:
            log("Invalid JSON input", level="ERROR")
            sys.exit(1)
        
        if "command" not in data or data["command"] not in ["train", "predict", "generate"]:
            log("Invalid or missing command", level="ERROR")
            sys.exit(1)
        
        if data["command"] == "train":
            if "inputs" not in data or "outputs" not in data:
                log("Missing inputs or outputs for training", level="ERROR")
                sys.exit(1)
            
            try:
                meta = train_model(data["inputs"], data["outputs"])
                print(json.dumps({"status": "success", "metadata": meta}))
            except Exception as e:
                log(f"Training failed: {str(e)}", level="ERROR")
                print(json.dumps({"status": "error", "message": str(e)}))
                sys.exit(1)
        
        elif data["command"] == "predict":
            if "inputs" not in data:
                log("Missing inputs for prediction", level="ERROR")
                sys.exit(1)
            
            try:
                result = predict(data["inputs"])
                print(json.dumps(result))
            except Exception as e:
                log(f"Prediction failed: {str(e)}", level="ERROR")
                print(json.dumps({"status": "error", "message": str(e)}))
                sys.exit(1)
                
        elif data["command"] == "generate":
            try:
                num_samples = data.get("num_samples", 1000)
                malicious_ratio = data.get("malicious_ratio", 0.5)
                urls, labels = generate_training_data(num_samples, malicious_ratio)
                print(json.dumps({
                    "status": "success", 
                    "urls": urls, 
                    "labels": labels
                }))
            except Exception as e:
                log(f"Data generation failed: {str(e)}", level="ERROR")
                print(json.dumps({"status": "error", "message": str(e)}))
                sys.exit(1)
    
    except Exception as e:
        log(f"Unexpected error: {str(e)}", level="ERROR")
        print(json.dumps({"status": "error", "message": str(e)}))
        sys.exit(1)