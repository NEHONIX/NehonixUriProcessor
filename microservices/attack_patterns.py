ATTACK_PATTERNS = {
    "sql_injection": [
        # Base SQL injection patterns with improved specificity
        r"(?:^|\s|\(|;)(?:'|\"|`)?(\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(OR|AND)(\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:'|\"|`)?(?:\d+(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:=|<|>|\bIS\b)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:'|\"|`)?(?:\d+|true|false)|\s*?(?:true|false|1|0)\s*)",
        r"(?:^|\s|\(|;)(?:SELECT|UNION\s+ALL|UNION)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+(?:(?:TOP|FIRST|DISTINCT)\s+[\d]+\s+)?[\w\*]+(?: AS \w+)?(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:,(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?[\w\*]+(?:\s+AS\s+\w+)?)*(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+FROM(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+\w+",
        r"(?:^|\s|\(|;)INSERT(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+INTO(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+\w+(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*\([^)]*\)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*VALUES(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*\(",
        r"(?:^|\s|\(|;)(?:UPDATE)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+\w+(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+SET(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+[\w\d]+(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*=(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*(?:'|\"|`)?",
        r"(?:^|\s|\(|;)(?:DELETE)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+FROM(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+\w+",
        r"(?:^|\s|\(|;)(?:DROP|ALTER|CREATE|TRUNCATE)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+(?:TABLE|DATABASE|PROCEDURE|FUNCTION|TRIGGER|VIEW|INDEX)",
        r"(?:^|\s|\(|;)(?:EXEC|EXECUTE)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+(?:sp_|xp_|master\.)",
        r"(?:^|\s|\(|;)(?:DECLARE|SET)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+(?:@|#)[\w]+",
        # Authentication bypass patterns
        r"(?:^|\s)(?:admin|administrator|root|superuser)['\"]\s*(?:--|#|\/\*|;|$)(?:\s|$)",
        r"(?:^|\s)(?:--|\")(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?$",
        r"(?:'|\")(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:OR|AND)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:true|1|'1'|\"1\")(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?(?:--|#|\/\*|;|$)",
        # Time-based and blind injection
        r"(?:SLEEP|BENCHMARK|PG_SLEEP|WAITFOR\s+DELAY|GENERATE_SERIES)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?\(\s*\d+\s*\)",
        r"(?:LOAD_FILE|INFILE|OUTFILE|DUMPFILE)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?\((?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?['\"](?:[^\"\n]+)['\"](?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*?\)",
        # Advanced SQL injection with reduced false positives
        r"(?:^|\s|\(|;)(?:'|\"|`)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*(?:OR|AND)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*[\w]+(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*(?:=|LIKE|<>|!=)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*(?:'|\"|`)[\w]+(?:'|\"|`)",
        r"(?:ORDER|GROUP)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+BY(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)+(?:\d+|\w+)(?:\s|\+|\/\*.*?\*\/|\-\-|\%20|\%09|\%0a|\%0d)*(?:ASC|DESC)?(?:--|#|\/\*|;|$)",
    ],
    "xss": [
        # Standard script tags
        r"<\s*script[\s\S]*?>[\s\S]*?<\s*/\s*script\s*>",
        r"<\s*script\b(?:[^>])*(?:src\s*=\s*(?:'[^']*'|\"[^\"]*\"|[^>'\"]+)|>[\s\S]*?)",
        # Event handlers
        r"<[a-zA-Z][^>]*\s(?:on[a-zA-Z]+)\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`)",
        r"\bon(?:load|error|click|mouseover|mouseout|submit|focus|blur|change|select|unload|readystatechange|message|storage)\s*=\s*(?:\"[^\"]*\"|'[^']*'|`[^`]*`)",
        # JavaScript protocols
        r"(?:href|src|action|data|formaction)\s*=\s*(?:\"|'|`)?javascript\s*:",
        # r"javascript\s*:[^'"]*(?:alert|confirm|prompt|eval|document\.cookie|document\.location|document\.referrer|document\.write|window\.location|location\.href)",
        # CSS expressions and behaviors
        r"<\s*style[^>]*>[\s\S]*?(expression|behavior)[\s\S]*?<\s*/\s*style\s*>",
        r"style\s*=\s*(?:\"|'|`)[^\"'`]*(?:expression|behavior|url\s*\(|import)[^\"'`]*(?:\"|'|`)",
        # Element pollution attacks
        r"<\s*(?:iframe|object|embed|applet|meta|base|form|input|button|textarea|select|img)[^>]*(?:src|href|action|data|formaction)\s*=",
        r"<\s*meta[^>]*(?:http-equiv|charset)\s*=\s*(?:\"|'|`)?[^\"'`>]*(?:\"|'|`)?",
        # Encoded XSS vectors
        r"(?:%3C|&lt;)(?:%73|%53|s)(?:%63|%43|c)(?:%72|%52|r)(?:%69|%49|i)(?:%70|%50|p)(?:%74|%54|t).*?(?:%3E|&gt;)",
        r"\\u003c\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074.*?\\u003e",
        # DOM-based XSS vectors
        r"(?:document|window)\s*\.\s*(?:location|origin|href|host|hostname|pathname|search|hash)\s*(?:=|\.assign\s*\(|\.replace\s*\()",
        r"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln|eval|setTimeout|setInterval|execScript)\s*\(",
        # Sanitization bypasses
        r"><\s*script\b|\balert\s*\(|javascript\s*:|\bonerror\s*=|\bsvg\s*\/\s*onload\s*=",
        r"<\s*(?:svg|img|image|iframe|audio|video)\b[^>]*\bon(?:load|error)\s*=",
        # Content type overrides
        r"<\s*meta[^>]*content-type[^>]*>",
        r"<\s*object[^>]*type\s*=\s*(?:\"|'|`)(?:text|application)\/(?:html|javascript|x-javascript)(?:\"|'|`)",
    ],
    "path_traversal": [
        # Advanced path traversal detection
        r"(?:^|[\?\&\;\=\:\%2f])(?:\.\.|%2e%2e|%252e%252e|%c0%ae%c0%ae|\.\.\.|%2e%2e%2e|%252e%252e%252e)(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f|%u2215|%u2216){1,10}",
        # Multiple encoding variations
        r"(?:[\?\&\;\=\:\%2f])(?:%c0%ae|%e0%80%ae|%u002e|%u2024|%uff0e|%u3002){2,}(?:/|%2f|%u2215|%u2216)",
        # Unicode/UTF-8 path traversal
        r"(?:^|[\?\&\;\=\:])(?:\\x2e\\x2e|\\xc0\\xae\\xc0\\xae|\\xe0\\x80\\xae|\\xc0\\xae\\xe0\\x80\\xae)(?:/|\\|\\xc0\\xaf|\\xe0\\x80\\xaf)",
        r"(?:^|[\?\&\;\=\:])((?:%2e|%252e|%c0%ae|%c0%2e|%e0%80%ae|%e0%40%ae|%25c0%25ae|%ef%bc%8e|%ef%bc%ae){2,}(?:/|%2f|%252f|%255c|%5c|\\|\|/|\\\\|/\\|\\x2f|\\u002f){1,3})",
    ],
    "command_injection": [
        # Advanced shell command detection
        r"(?:^|[\&;|`\n\r\s])(?:\/bin\/|\/usr\/bin\/|\/usr\/local\/bin\/)?(?:sh|bash|dash|ksh|zsh|csh|tcsh|pwsh|powershell)\s+(?:-[a-zA-Z]{1,10}\s+)*(?:-[cepix]|--(?:command|exec|interactive))(?:\s+|=)(?:'|\"|`)?.+?(?:'|\"|`|\s|;|\||\&|$)",
        # Command execution with improved coverage
        r"(?:^|[\&;|`\n\r\s])(?:exec|eval|system|passthru|shell_exec|popen|proc_open|pcntl_exec|subprocess\.(?:Popen|call|check_output)|os\.(?:system|popen|exec[lpe]*)|Runtime\.(?:exec|getRuntime\(\)\.exec))\s*(?:\(|\s+)(?:'|\"|`)?.+?(?:'|\"|`|\)|\s|;|\||\&|$)",
        # PowerShell specific commands
        r"(?:^|[\&;|`\n\r\s])(?:Get|Set|New|Remove|Start|Stop|Invoke)-[a-zA-Z]+\s+(?:-[a-zA-Z]+\s+)*(?:-[a-zA-Z]+\s+(?:'[^']*'|\"`[^`]*\"|[^\s]+))*",
        # Command execution with improved coverage
        r"(?:^|[\&;|`\n\r\s])(?:exec|eval|system|passthru|shell_exec|popen|proc_open|pcntl_exec|subprocess\.(?:Popen|call|check_output)|os\.(?:system|popen|exec[lpe]*)|Runtime\.(?:exec|getRuntime\(\)\.exec))\s*(?:\(|\s+)(?:'|\"|`)?.+?(?:'|\"|`|\)|\s|;|\||\&|$)",
        # Shell builtins and file operations
        r"(?:^|[\&;|`\n\r\s])(?:cd|pwd|ls|cat|echo|rm|cp|mv|touch|chmod|chown|chgrp|mkdir|rmdir|find|grep|awk|sed|vi|vim|nano|emacs)\s+(?:-[a-zA-Z]{1,10}\s+)*(?:\/[a-zA-Z0-9_\.-]+|[\w\.-]+)+",
        # Network and system commands
        r"(?:^|[\&;|`\n\r\s])(?:nc|netcat|wget|curl|lynx|ping|telnet|ftp|ssh|nmap|tcpdump|wireshark|netstat|ifconfig|ipconfig|route|traceroute|dig|nslookup|whois)\s+(?:-[a-zA-Z]{1,10}\s+)*(?:[a-zA-Z0-9_\.-]+)",
        # Process and service manipulation
        r"(?:^|[\&;|`\n\r\s])(?:kill|killall|pkill|ps|top|htop|pgrep|service|systemctl|start|stop|restart|status)\s+(?:-[a-zA-Z]{1,10}\s+)*(?:[0-9]+|[a-zA-Z][a-zA-Z0-9_-]*)",
        # Advanced file operations
        r"(?:^|\s|=|\(|`)(?:cp|mv|rm|touch|mkdir|rmdir|chmod|chown|chgrp|ln|tar|gzip|gunzip|zip|unzip|7z|rar|unrar)\s+(?:-[a-zA-Z]{1,10}\s+)*(?:\/[a-zA-Z0-9_\.-]+)+",
        # Command substitution and variable expansion
        r"\$\((?:[^)]*)\)|\$\{(?:[^}]*)\}|`(?:[^`]*)`",
        r"\$\{[!#]?[a-zA-Z0-9_]+(?::\-[^}]+)?\}|\$\{[!#]?[a-zA-Z0-9_]+(?:\/[^\/}]+\/[^}]+)?\}",
        # Encoded commands and obfuscation
        r"(?:%(?:25)*(?:7[ce]|26|24|60|2[fF]|5[cC]))(?:[a-zA-Z0-9_\/\.-]+)(?:\s+(?:[^\s]+))*\s*(?:%(?:25)*(?:7[ce]|26|3[bB]|60))",
        r"(?:\\x(?:25)*[0-9a-fA-F]{2}|\\u(?:00)*[0-9a-fA-F]{4}|\\[0-7]{1,3})(?:[^\s]+)*\s*(?:\\x(?:25)*[0-9a-fA-F]{2}|\\u(?:00)*[0-9a-fA-F]{4}|\\[0-7]{1,3})",
        # PowerShell specific commands
        r"(?:^|[\&;|`\n\r\s])(?:Get|Set|New|Remove|Start|Stop|Invoke)-[a-zA-Z]+\s+(?:-[a-zA-Z]+\s+)*(?:-[a-zA-Z]+\s+(?:'[^']*'|\"`[^`]*\"|[^\s]+))*",
    ],
    "deserialization": [
        # PHP serialization with improved specificity
        r"^[OS]:[0-9]+:\"[a-zA-Z0-9_\\\]+\":[0-9]+:\{(?:[^}])*(?:protected|private|public)(?:[^}])*\}$",
        r"(?:^|[=&?])(?:[OS]:[0-9]+:\{|a:[0-9]+:\{|s:[0-9]+:\"(?:[^\"]|\\\"){0,500}\";|i:[0-9]+;|b:[01];|N;|O:[0-9]+:\"[^\"]{1,100}\":[0-9]+:\{)",
        # Base64 encoded serialized data
        r"(?:^|[=&?])(?:rO0[A-Za-z0-9+/]{10,}={0,2}|YToy[A-Za-z0-9+/]{10,}={0,2}|Tzo[A-Za-z0-9+/]{10,}={0,2})",
        # Java serialization markers
        r"(?:^|[=&?])(?:\\xac\\xed\\x00\\x05|rO0ABX|H4sIAAAAAAAA|PD94bWwgdmVyc2lv|TVqQAAMAA|UEsDBBQA)",
        r"(?:java|javax|org|com|sun)\.(?:[a-zA-Z0-9_$.]{1,60}(?:;|\$))(?:[a-zA-Z0-9_.]{1,50})",
        # Magic method indicators in serialized data
        r"__(?:sleep|wakeup|construct|destruct|call|callStatic|get|set|isset|unset|toString|invoke|set_state|clone|autoload|serialize|unserialize|__halt_compiler)(?:\"|\\\\\")",
        # Deserialization class and method indicators
        r"(?:ObjectInputStream|XMLDecoder|XStream|JsonParser|Jackson|ObjectMapper|readObject|fromXML|parseXML|loadXML|yaml\.(?:load|unsafe_load)|JsonSlurper)",
        # .NET specific deserialization
        r"(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)",
        r"(?:TypeNameHandling\.(?:All|Objects|Arrays)|JavaScriptSerializer|DataContractJsonSerializer)",
        # Ruby, Python deserialization
        r"(?:Marshal\.(?:load|restore)|YAML\.(?:load|parse|unsafe_load)|Psych\.(?:load|parse))",
        r"(?:pickle\.(?:loads?|dumps?)|cPickle\.(?:loads?|dumps?)|marshal\.(?:loads?|dumps?))",
        # Gadget chains
        r"(?:Runtime|Process|ProcessBuilder|ScriptEngine|JdbcRowSet|TemplatesImpl|Transformer|InvokerTransformer|InstantiateTransformer|CommonsCollections)",
        r"(?:DynamicProxy|ChainedTransformer|LazyMap|PriorityQueue|SerializableTypeWrapper|FileUpload|BadAttributeValueExpException)",
    ],
    "jwt_manipulation": [
        # Better JWT token format matching
        r"(?:^|[&?;=])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})",
        r"(?:^|[&?;=])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.?)",
        # JWT header manipulation
        r"\"alg\"(?:\s*):(?:\s*)\"none\"",
        r"\"alg\"(?:\s*):(?:\s*)\"(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512|EdDSA)\"",
        # JWT key ID manipulation
        r"\"kid\"(?:\s*):(?:\s*)\"(?:file:|https?:|data:|ldap:|ftp:|\\\\|\.\.|\/|eval|exec|system).*?\"",
        r"\"kid\"(?:\s*):(?:\s*)\"(?:[a-zA-Z0-9+/]+={0,2})\"",
        # JWT type manipulation
        r"\"typ\"(?:\s*):(?:\s*)\"(?:JWT|JWE|JWS|JWK|JOSE)\"",
        # JWT payload manipulation
        r"\"(?:sub|iss|aud|exp|nbf|iat|jti)\"(?:\s*):(?:\s*)(?:[\"'](?:[^\"']+)[\"']|\d+|true|false|null)",
        r"\"(?:role|group|permission|isAdmin|admin|superuser|privileged)\"(?:\s*):(?:\s*)(?:[\"'](?:[^\"']+)[\"']|true|false|\d+)",
        # JWT library functions
        r"(?:jwt|jsonwebtoken)\.(?:sign|verify|decode|encode)\(",
        r"\.(?:setSignature|setHeader|setClaim|setPayload|setKey|setAlgorithm|setIssuer|setSubject|setAudience|setExpirationTime|setIssuedAt|setNotBefore)\(",
        # JWT tampering and weaknesses
        r"\"jwk\"(?:\s*):(?:\s*)\{(?:[^{}]*\"[kn]\"(?:\s*):(?:\s*)\"[A-Za-z0-9+/=_-]+\"[^{}]*)\}",
        r"\"x5[ctu]\"(?:\s*):(?:\s*)(?:\"[^\"]*\"|\\[[^\\]]*\\])",
        # JWT algorithms and operations
        r"\"enc\"(?:\s*):(?:\s*)\"(?:A128CBC-HS256|A192CBC-HS384|A256CBC-HS512|A128GCM|A192GCM|A256GCM)\"",
        r"\"crit\"(?:\s*):(?:\s*)\[(?:[^\]]*)\]",
    ],
    "ssrf": [
        # IP-based SSRF detection
        r"https?://(?:(?:0x[0-9a-fA-F]{1,8}|0[0-7]{1,11}|[0-9]+)(?:\.(?:0x[0-9a-fA-F]{1,8}|0[0-7]{1,11}|[0-9]+)){0,3}|\[(?:[0-9a-fA-F:]+)?(?:::(?:[0-9a-fA-F:]+)?)?\])(?::\d+)?(?:/[^\s]*)?",
        # Internal network targeting
        r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|[fF][eE]80:|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|fc00:|fe[89ab][0-9a-fA-F]:)(?::\d+)?(?:/[^\s]*)?",
        # Cloud metadata endpoints
        r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.internal|169\.254\.170\.2|[^/]+\.compute\.internal)(?::\d+)?(?:/[^\s]*)?",
        # Network libraries
        r"(?:Net::HTTP|URI\.parse|OpenURI|RestClient|HTTPClient|Faraday|Typhoeus|Excon|http\.get|http\.post)\.(?:new|get|post|put|delete|head|patch|open|read)",
        r"(?:HttpClient|WebClient|HttpWebRequest|WebRequest|RestSharp|HttpURLConnection|URL\.openConnection)\.(?:getInput|getOutput|send|execute|GetResponse|OpenRead|DownloadString)",
        # Internal network access
        r"https?://(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|::1)(?::\d+)?(?:/[^\s]*)?",
        r"https?://[a-zA-Z0-9\-\.]+(?:\.(?:local|localhost|lan|intranet|internal|corp|private|home|test))(?::\d+)?(?:/[^\s]*)?",
        # SSRF protocol abuse
        r"(?:file|gopher|dict|php|jar|ldap|ldaps|tftp|ssh|smb|smtp|ftps?|nfs)://[^\s]+",
        r"http://(?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(?:$|[/?#:])",
        r"http://(?:0x[0-9a-fA-F]{8}|\d{8,10})(?:$|[/?#:])",
        # JavaScript HTTP clients
        r"(?:fetch|axios|XMLHttpRequest|$.(?:ajax|get|post))(?:\s*)\((?:\s*)(?:['\"][^'\"]*['\"]|(?:\{[^\}]*url(?:\s*):(?:\s*)['\"][^'\"]*['\"][^\}]*\}))",
    ],
 "nosql_injection": [
        r"\{\s*\$where\s*:\s*(?:'|\"|`)(?:[^'\"`;]|\\['\"`;])*(?:return|emit|execute|eval|process|require|set|get)\s*\(.*?\)\s*(?:'|\"|`)\s*\}",
        r"\{\s*(?:['\"]?[\w-]+['\"]?)?\s*:\s*\{\s*\$(?:ne|gt|lt|gte|lte|in|nin|all|regex|size|exists|type|mod|text)\s*:\s*(?:['\"][^'\"]+['\"]|\d+|true|false|\[[^\]]*\])\s*\}\s*\}",
        r"\{\s*\$(?:or|and|nor)\s*:\s*\[\s*(?:\{(?:['\"]?[\w-]+['\"]?)?\s*:\s*(?:['\"][^'\"]+['\"]|\d+|true|false|\{[^\}]*\}|\[[^\]]*\])\s*\}\s*,?\s*)+\]\s*\}",
        r"(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=(?:[^&;]*(?:return|emit|execute|eval|process|require|set|get)\s*\(.*?\)|[^&;]*)",
        r"function\s*\(\s*\)\s*{\s*(?:[^{}]|\{[^{}]*\})*(?:return|emit|execute|eval|process|require|set|get)\s*\(.*?\)\s*;?\s*}",
        r"new\s+(?:Function|RegExp|Date)\s*\(\s*(?:'|\"|`)?[^'\"`;]*(?:return|emit|execute|eval|process|require|set|get)[^'\"`;]*(?:'|\"|`)?\s*\)",
        r"\{\s*['\"]?\$[a-zA-Z0-9]+['\"]?\s*:\s*(?:['\"][^'\"]+['\"]|\d+|true|false|\{[^\}]*\}|\[[^\]]*\])\s*\}",
        r"ObjectId\s*\(\s*(?:'|\"|`)[0-9a-fA-F]{24}(?:'|\"|`)\s*\)",
        r"ISODate\s*\(\s*(?:'|\"|`)[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z)?(?:'|\"|`)\s*\)",
        r"(?:%7B|%7D|%5B|%5D|%24|%3A|%3D)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)[^&;]*(?:%7B|%7D|%5B|%5D|%24|%3A|%3D)",
        r"\[\s*(?:['\"]?[\w-]+['\"]?)?\s*,\s*\$(?:ne|gt|lt|gte|lte|in|nin|all|regex|size|exists|type|mod|text)\s*:\s*(?:['\"][^'\"]+['\"]|\d+|true|false|\[[^\]]*\])\s*\]",
        r"(?<!lang=)(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*",
        r"(?<!page=)(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*",
        r"(?<!filter=)(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*",
        r"(?<!sort=)(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*",
        r"(?<!id=)(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*",
        r"(?:[$]|%24|\\u0024)(?:where|regex|ne|gt|lt|gte|lte|in|nin|all|size|exists|type|mod|text|or|and|nor)\s*=[^&;]*"
    ],
    "xxe": [
        # XML entity declarations
        r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|http|ftp|php|expect|data)://[^'\"]+['\"]",
        r"<!DOCTYPE\s+\w+\s*\[\s*<!ENTITY\s+\w+\s+(?:PUBLIC\s+['\"][^'\"]*['\"]\s+)?['\"][^'\"]+['\"]\s*>\s*\]",
        # External entity references
        r"&[a-zA-Z0-9_]+;",
        r"&#x[0-9a-fA-F]+;",
        # XML processing instructions
        r"<\?xml[^>]*stylesheet[^>]*href\s*=\s*['\"](?:file|http|ftp)://[^'\"]+['\"][^>]*\?>",
        # Encoded XXE payloads
        r"(?:%3C|&lt;)(?:!DOCTYPE|!ENTITY)[^>]+(?:%3E|&gt;)",
        r"(?:%26|&amp;)[a-zA-Z0-9_]+(?:%3B|;)",
        # XXE in XML content
        r"<\s*xml[^>]*>(?:[\s\S]*?<!ENTITY[\s\S]*?>)+[\s\S]*?</\s*xml\s*>",
        # Protocol-based XXE attacks
        r"(?:file|http|ftp|php|expect|data):%2f%2f[^'\"&;]+",
      ],
     "csrf": [
        # Suspicious form tags without CSRF tokens
        r"<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*>(?:(?!<\s*input\s+[^>]*?name\s*=\s*['\"]?_?token['\"]?).)*?</\s*form\s*>",
        # JavaScript-driven form submissions
        r"<\s*form\s+[^>]*?on(?:submit|click)\s*=\s*['\"][^'\"]*?(?:fetch|axios|XMLHttpRequest|$.(?:ajax|post)|submit\s*\()[^'\"]*['\"][^>]*>",
        # Missing CSRF token in headers
        r"(?:fetch|axios|$.(?:ajax|post))\s*\(\s*['\"]?https?://[^'\"]+['\"]?,\s*\{[^}]*headers\s*:\s*\{(?![^{}]*X-CSRF-Token|X-XSRF-Token|CSRF-Token)[^{}]*\}\s*\}",
        # Encoded CSRF payloads
        r"(?:%3C|<)(?:form|input|button)[^>]+(?:method|action|onsubmit)\s*=\s*[^>]+(?:%3E|>)",
        # Avoid false positives for common form fields with exclusions
        r"(?<!lang=)<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*>(?:(?!<\s*input\s+[^>]*?name\s*=\s*['\"]?_?token['\"]?).)*?</\s*form\s*>",
        r"(?<!filter=)<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*>(?:(?!<\s*input\s+[^>]*?name\s*=\s*['\"]?_?token['\"]?).)*?</\s*form\s*>",
        r"(?<!sort=)<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*>(?:(?!<\s*input\s+[^>]*?name\s*=\s*['\"]?_?token['\"]?).)*?</\s*form\s*>"
    ],
    "file_upload": [
        # Simplified file upload patterns with atomic groups
        r"(?><\s*form\s+[^>]*method\s*=\s*['\"]?POST['\"]?[^>]*>).*?(?></\s*form\s*>)",
        r"(?:^|[?&;=])(?:upload|file)=(?:[^&;]*\.(?:php|asp|exe|sh|py|rb|jsp|cgi|pl)[^&;]*)",
        # File upload functions - simplified
        r"(?:move_uploaded_file|copy|rename)\s*\([^)]*\.[a-zA-Z]{2,4}\s*\)",
        # Base64-encoded file uploads - optimized
        r"(?:^|[?&;=])(?:file|upload)=data:(?:application|text)/[^;]{1,50};base64,[A-Za-z0-9+/=]{20,100}",
        # File inclusion - simplified
        r"(?:include|require)(?:_once)?\s*\([^)]*\.[a-zA-Z]{2,4}\s*\)",
        # Dangerous file extensions - optimized
        r"[?&;](?:file|upload)=[^&;]*\.(?:php\d*|p[ly]|[jr]b|[aj]sp|cgi|exe|sh|bat|cmd|ps1|vb[se]|wsf|hta|war)(?:$|&|;)"
    ],
    "http_response_splitting": [
        # CRLF injection
        r"(?:%0D|%0A|\r|\n)(?:%0D|%0A|\r|\n)*(?:Set-Cookie|Location|Status|Content-Type|Content-Length):",
        # Header injection
        r"(?:^|[?&;=])(?:header|response)=[^&;]*(?:%0D|%0A|\r|\n)[^&;]*(?:Set-Cookie|Location|Status|Content-Type|Content-Length):",
        # Encoded CRLF
        r"(?:%250D|%250A|%0D%0A|%0A%0D)[^&;]*(?:Set-Cookie|Location|Status|Content-Type|Content-Length):",
        # HTTP header manipulation
        r"(?:addHeader|setHeader|putHeader)\s*\(\s*['\"](?:Set-Cookie|Location|Status|Content-Type|Content-Length)['\"],",
        # Avoid false positives for benign newlines
    ],
    "ldap_injection": [
        # LDAP filter injection
        r"(?:\(|&|\|)(?:[a-zA-Z0-9_]+)\s*=\s*\*[^\)]*",
        r"(?:^|[?&;=])(?:filter|query)=[^&;]*(?:\*\([a-zA-Z0-9_]+=|\([a-zA-Z0-9_]+=\*|\([a-zA-Z0-9_]+=.*?\*\))",
        # LDAP attribute manipulation
        r"(?:^|[?&;=])(?:uid|cn|dn|ou|dc|objectClass)=[^&;]*(?:[\(\)\|&*]|\%28|\%29|\%7C|\%26|\%2A)",
        # Encoded LDAP payloads
        r"(?:%28|%29|%7C|%26|%2A)[a-zA-Z0-9_]+=(?:%2A|\*|\%28|\%29|\%7C|\%26)",
        # LDAP query functions
        r"(?:ldap_search|ldap_bind|ldap_connect|ldap_query)\s*\(\s*['\"]?[^'\"]+(?:[\(\)\|&*]|\%28|\%29|\%7C|\%26|\%2A)[^'\"]*['\"]?"
    ],
    "ssrf": [
        # IP-based SSRF detection
        r"https?://(?:(?:0x[0-9a-fA-F]{1,8}|0[0-7]{1,11}|[0-9]+)(?:\.(?:0x[0-9a-fA-F]{1,8}|0[0-7]{1,11}|[0-9]+)){0,3}|\[(?:[0-9a-fA-F:]+)?(?:::(?:[0-9a-fA-F:]+)?)?\])(?::\d+)?(?:/[^\s]*)?",
        # Internal network targeting
        r"https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|[fF][eE]80:|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|fc00:|fe[89ab][0-9a-fA-F]:)(?::\d+)?(?:/[^\s]*)?",
        # Cloud metadata endpoints
        r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.internal|169\.254\.170\.2|[^/]+\.compute\.internal)(?::\d+)?(?:/[^\s]*)?",
        # DNS rebinding patterns
        r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:127\.0\.0\.1|localhost|0\.0\.0\.0|internal|local|private|corp|dev|test|stage|prod|admin)\.(?:[a-zA-Z]{2,}|[0-9]+)(?::\d+)?(?:/[^\s]*)?",
        # Encoded and obfuscated patterns
        r"https?://(?:%(?:25)*(?:30|31|32|33|34|35|36|37|38|39|61|62|63|64|65|66|67|68|69|6[aA]|6[bB]|6[cC]|6[dD]|6[eE]|6[fF])[0-9a-fA-F])(?::\d+)?(?:/[^\s]*)?",
        # Protocol handlers and wrappers
        r"(?:file|gopher|dict|php|jar|data|ftp|ldap|smtp|imap|tftp)://[^\s]+",
        # URL parameters indicating SSRF
        r"[?&](?:url|uri|path|src|dest|redirect|location|site|server|host|next|target|to|out|load|file)=(?:https?://|\\\\|//)[^&\s]+",
        # Advanced encoding detection
        r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}@[^/]+|https?://[^/@]+@(?:[0-9]{1,3}\.){3}[0-9]{1,3}",
        # DNS rebinding with timing
        r"https?://(?:[a-zA-Z0-9\-]+\.)*(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168|169\.254)\.[0-9]{1,3}\.[0-9]{1,3}(?::\d+)?(?:/[^\s]*)?",
        # Avoid false positives for common domains
        r"(?<!\.(?:com|org|net|edu|gov|mil))https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/[^\s]*)?"    
    ]
}

