export class PATTERNS {
  // ========== SQL INJECTION PATTERNS ==========
  static readonly SQL_INJECTION_PATTERNS = [
    // Master pattern with improved context awareness
    /(?<=(\?|&|\s|;|=|:))(('|\s|\+|%20)+(or|and|union|select|insert|update|delete|drop|alter|create|exec|from|where)\s+(('|\+|%20|%27)*(\d+\s*=\s*\d+|\d+\s*>\s*\d+|'[^']*'\s*=\s*'[^']*'|x=x|1=1|true|false)|\(|--|#|\/\*))/i,

    // Improved detection of SQL operators in conditional context
    /\b(or|and)\s+(['"]?\d+['"]?\s*(=|<|>|<=|>=|<>|!=)\s*['"]?\d+['"]?|['"][^'"]*['"]?\s*(=|<|>|<=|>=|<>|!=)\s*['"][^'"]*['"]|x\s*=\s*x)/i,

    // Better boundaries for SQL commands
    /\b(union\s+select|select\s+.*?\bfrom\b|delete\s+from|update\s+.*?\bset\b|insert\s+into)\b(?!\s+[-\w]+\s*\()/i,

    // Comment-based attacks with improved boundaries
    /(?<=(\?|&|\s|;|=|:))(--\s+|;\s*--|#|\/\*.*?\*\/)/i,

    // Function-based injections with better context
    /(?<=(\?|&|\s|;|=|:))['"]?\s*(\+|%2B)\s*['"]?|\bwaitfor\s+delay\b|\bsleep\s*\(|\bchar\s*\(|\bconcat\s*\(|\bcast\s*\(|\bconvert\s*\(|benchmark\s*\(/i,

    // Dangerous operations with context awareness
    /(?<=(\?|&|\s|;|=|:))(;\s*shutdown|;\s*drop\s+table|;\s*drop\s+database|;\s*truncate|;\s*delete|xp_cmdshell)/i,

    // Hex encoding detection
    /(?<=(\?|&|\s|;|=|:))(0x[0-9a-fA-F]{4,}|0b[01]{8,})/i,

    // LIKE operator misuse
    /\blike\s+['"]{1}%[^%]*[']{1}/i,

    // Batch commands
    /(?<=(\?|&|\s|;|=|:))(;\s*begin|;\s*if|;\s*while)/i,

    // Stack queries with better boundaries
    /(?<=(\?|&|\s|;|=|:))(['"];)(\s*[^;]*?;)+/i,

    // Careful detection of schema/information-gathering attacks
    /\b(information_schema|user_tables|all_tables|user_tab_columns|sqlite_master)\b/i,
  ];

  // ========== XSS PATTERNS ==========
  static readonly XSS_PATTERNS = [
    // Script tag variations with improved boundaries
    /(?:<|&lt;|\%3C)([^>]*)script([^>]*)(?:>|&gt;|\%3E)/i,

    // Event handlers with word boundaries and attribute context
    /(?:\s|^|=|:|&)(on(?:abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload|readystatechange|beforeunload))\s*=\s*(['"`]|&quot;|&#39;|&#96;)/i,

    // JavaScript protocol in links/redirects with improved encoding detection
    /(?:\s|=|:)(href|src|action|data|formaction)\s*=\s*(['"`]|&quot;|&#39;|&#96;)(?:javascript:|data:|vbscript:|\s*&#0*106;&#0*97;&#0*118;&#0*97;&#0*115;&#0*99;&#0*114;&#0*105;&#0*112;&#0*116;|\s*&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;)/i,

    // DOM manipulation functions with better context
    /(?:document|window|location|cookie|localStorage|sessionStorage)\.(cookie|innerHTML|outerHTML|write|writeln|location|href|replace|assign|open|eval|setTimeout|setInterval)/i,

    // Encoded script/alert detection
    /(?:%3C|\<)([^>]*)(?:%73|s)(?:%63|c)(?:%72|r)(?:%69|i)(?:%70|p)(?:%74|t)([^>]*)(?:%3E|\>)/i,
    /(?:a|%61|&#0*97;)(?:l|%6C|&#0*108;)(?:e|%65|&#0*101;)(?:r|%72|&#0*114;)(?:t|%74|&#0*116;)/i,

    // SVG-based attacks with better context
    /<svg(?:\s+[^>]*)?(?:\s+on\w+\s*=\s*['"]+)/i,

    // Base64 content detection in XSS context
    /(?:src|href|data|action)\s*=\s*(['"`]|&quot;|&#39;|&#96;)\s*data:(?:text\/html|application\/javascript|application\/x-javascript);base64,[a-zA-Z0-9+/=]{10,}/i,

    // CSP bypass attempts
    /<meta\s+http-equiv\s*=\s*['"]?content-security-policy/i,

    // Advanced expression-based XSS (AngularJS, Vue, etc.)
    /{{.*?(?:constructor|__proto__|__defineGetter__|__defineSetter__|toString|fromCharCode).*?}}/i,

    // Better iframe detection
    /<iframe\s+(?:[^>]*?\s+)?(?:src|srcdoc)\s*=\s*(['"`]|&quot;|&#39;|&#96;)/i,

    // Detection of obfuscated eval
    /(?:\(\s*['"`]?\s*.*?\s*[`'"]\s*\)|\[['"]+.*?['"]+\])\s*(?:\[\s*['"]+.*?['"]+\s*\]|\([^)]*\))/i,
  ];

  // ========== COMMAND INJECTION PATTERNS ==========
  static readonly COMMAND_INJECTION_PATTERNS = [
    // Command separators with improved context
    /(?<=\s|=|&|;|\(|^)(?:;|\||`|\$\(|\$\{|&+|\|\||\|&|\${|&&)(?:\s*[a-zA-Z0-9_\/.-]+)/i,

    // Shell commands with better boundaries
    /(?<=\s|=|&|;|\(|^|\|\||&&)((?:ping|nslookup|netstat|ipconfig|ifconfig|wget|curl|lynx|nc|netcat|telnet|bash|sh|ksh|zsh|csh|python|perl|ruby|gcc|cc|go|nasm|as)\s+[-\w\s\/.$*"']*)/i,

    // Filter evasion techniques
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:b"'\s*\+\s*a"sh|python\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|node\s+-e|cmd\s+\/c|powershell\s+-\w+)/i,

    // Command completion context for dangerous operations
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:rm\s+-[rf]+\s+\/|chmod\s+(?:777|a\+x)\s+|chown\s+(?:root|0+:0+)\s+|kill\s+-9\s+|reboot|shutdown)/i,

    // Input/output redirection with better context
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:[><]\s*\/(?:dev|etc|home|root|proc|sys|tmp|var)\/[a-zA-Z0-9_.-]+|[><]\s*[a-zA-Z0-9_.-]+\.(?:txt|log|sh|conf|php|pl|py|rb))/i,

    // Environment variable manipulation
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:env|export|set)\s+[A-Z_]+=(?:.*?;|.*?`|.*?\$\()/i,

    // Base64-encoded command execution
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:echo|printf)\s+['"]?[a-zA-Z0-9+\/=]{10,}['"]?\s*\|\s*(?:base64|openssl)\s+(?:-d|--decode|dec)/i,

    // Command execution through programming languages
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:python|perl|ruby|php|node)\s+(?:-[a-z]\s+)?['"]?\s*(?:import|require|exec|eval|system|popen|subprocess|child_process)/i,

    // Directory traversal combined with command execution
    /(?:\.\.\/){1,}(?:bin|usr\/bin|sbin)\/(?:bash|sh|dash|zsh|csh|ksh|tcsh)/i,

    // Special command execution patterns for Windows
    /(?<=\s|=|&|;|\(|^|\|\||&&)(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?)\s+(?:\/c|\/k|-\w+)?\s*['"]?/i,
  ];

  // ========== PATH TRAVERSAL PATTERNS ==========
  static readonly PATH_TRAVERSAL_PATTERNS = [
    // Classic path traversal with better boundaries and encoding variations
    /(?:\/|\\|%2F|%5C|%252F|%255C)(?:\.\.(?:\/|\\|%2F|%5C|%252F|%255C)){1,}(?:bin|etc|home|var|root|sys|proc|opt|usr|windows|system32|config|boot|inetpub|wwwroot|nginx|apache2|htdocs)/i,

    // Advanced encoding detection
    /(?:%c0%ae|%c0%af|%c1%9c|%25c0%25ae|%ef%bc%8e){1,}(?:\/|\\|%2F|%5C)/i,

    // Sensitive file access with context
    /(?:\/|\\|%2F|%5C)(?:etc\/passwd|etc\/shadow|etc\/hosts|etc\/(?:nginx|apache2)\/sites-(?:available|enabled)|proc\/self\/environ|windows\/win\.ini|windows\/system\.ini|boot\.ini|config\.sys|SAM|web\.config|wp-config\.php|configuration\.php|config\.inc\.php)/i,

    // Advanced evasion techniques
    /(?:file|ftps?|https?):\/\/+(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)/i,
    /(?:file|ftps?|https?):\/\/+(?:\/|\\|%2F|%5C){2,}/i,

    // Path normalization bypass
    /(?:\/|\\|%2F|%5C)(?:\.(?:\/|\\|%2F|%5C))(?:\.(?:\/|\\|%2F|%5C)){1,}/i,

    // Drive letter access (Windows)
    /(?:[A-Za-z]:)(?:\\|\/|\%5C|\%2F)(?:windows|program\sfiles|users|documents\sand\ssettings|boot|system32)/i,

    // Stream wrapper/protocol abuse
    /(?:php|zip|phar|glob|data|expect|input|file):\/\/(?:\/|\\|%2F|%5C){0,2}/i,

    // Null byte injection for path truncation
    /(?:%00|\\0|0x00)(?:\.jpg|\.png|\.gif|\.pdf|\.txt|\.html|\.php)/i,

    // Advanced directory operations
    /(?:\/|\\|%2F|%5C)(?:\*|\?)(?:\/|\\|%2F|%5C)|(?:index\sof|directory\slisting\sfor)\//i,
  ];

  // ========== OPEN REDIRECT PATTERNS ==========
  static readonly OPEN_REDIRECT_PATTERNS = [
    // Improved redirect parameter detection with context
    /(?:url|redirect|redir|return|next|goto|target|link|back|path|to|out|view|dir|show|navigate|location|destination|exit|file|reference|continue|site|forward|from|src|action|load)=(?:https?:\/\/(?!(?:[\w.-]+\.)*(?:example\.com|trusted\.org|your-domain\.com|localhost))[\w\-._~:/?#[\]@!$&'()*+,;=]*)/i,

    // Protocol-based open redirect with better detection
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:\/\/|http[s]?:\/\/|ftp:\/\/|data:text\/html|javascript:|vbscript:|file:)/i,

    // Encoded URL parameters for bypassing filters
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:%68|%48)(?:%74|%54)(?:%74|%54)(?:%70|%50)(?:%73|%53)?(?:%3A|:)(?:%2F|\/){2}/i,

    // Double encoding detection
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:%2568|%2548)(?:%2574|%2554)(?:%2574|%2554)(?:%2570|%2550)(?:%2573|%2553)?(?:%253A|%3A)(?:%252F|%2F){2}/i,

    // HTML encoding
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:&#[xX]?0*68;?|&#[xX]?0*48;?)(?:&#[xX]?0*74;?|&#[xX]?0*54;?)(?:&#[xX]?0*74;?|&#[xX]?0*54;?)(?:&#[xX]?0*70;?|&#[xX]?0*50;?)(?:&#[xX]?0*73;?|&#[xX]?0*53;?)?(?:&#[xX]?0*3[aA];?|:)(?:&#[xX]?0*2[fF];?|\/){2}/i,

    // Data URL redirect
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:data:text\/html;base64,[a-zA-Z0-9+/=]{10,})/i,

    // Bypass attempts using embedded credentials
    /(?:url|redirect|redir|return|next|goto|target|link)=(?:https?:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@)/i,
  ];

  // ========== SSRF PATTERNS ==========
  static readonly SSRF_PATTERNS = [
    // Internal/private network targeting with better context
    /(?:url|uri|endpoint|site|server|host|server_url|source|target|load|fetch|read)=(?:https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|fc00::|fe80::)(?::|%3A)?(?:\d+)?(?:\/|%2F)?)/i,

    // Non-HTTP protocol wrappers
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:ftp|gopher|file|dict|mongodb|redis|ldap|tftp|ssh|telnet|smtp|imap|jar|zip|netdoc|php):\/\//i,

    // Cloud metadata services targeting
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.internal|metadata\.gcp\.internal|169\.254\.170\.2|fd00:ec2::254))/i,

    // DNS rebinding protection bypass
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?#?&?[?]?(?:host=|ip=|url=|redirect=|redir=|location=|to=|from=|src=|uri=|path=|ref=|reference=))/i,

    // Service discovery exploitation
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/(?:etcd|consul|eureka|kubernetes|docker|rancher|vault|admin|jenkins|gitlab|elastic|solr|mongo|redis|memcache|smtp)(?::(?:\d+))?\/)/i,

    // Local file inclusion via SSRF
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:file:\/\/\/(?:etc|var|root|home|proc|sys|dev|tmp|usr|bin|sbin))/i,

    // IPv6 localhost variants
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/(?:\[::1\]|\[0:0:0:0:0:0:0:1\]|\[::ffff:127.0.0.1\])(?::|%3A)?(?:\d+)?(?:\/|%2F)?)/i,

    // URL scheme confusion
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/[^\/]+@(?:127\.0\.0\.1|localhost|0\.0\.0\.0))/i,

    // Non-standard ports for internal services
    /(?:url|uri|endpoint|site|server|host|source|target|load|fetch|read)=(?:https?:\/\/[^\/]+:(?:22|445|1433|3306|5432|6379|8086|9000|9090|9200|27017))/i,
  ];

  // ========== CRLF INJECTION PATTERNS ==========
  static readonly CRLF_INJECTION_PATTERNS = [
    // Basic CRLF with context awareness
    /(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|\\n|\\r|%5[cC]r%5[cC]n)(?:(?:[hH][tT][tT][pP]\/(?:1\.0|1\.1|2\.0)\s+\d+|Content-(?:Type|Length|Encoding|Disposition)|Location|Set-Cookie|X-XSS-Protection|X-Frame-Options|Content-Security-Policy): |<script|alert\(|function\s*\(|javascript:|@import|document\.(?:cookie|location|write)|window\.)/i,

    // Advanced encoding detection
    /(?:%E5%98%8A%E5%98%8D|%0[dD]|%0[aA]|%5[cC]r|%5[cC]n|\r|\n){2,}(?:[hH][tT][tT][pP]\/(?:1\.0|1\.1|2\.0)\s+\d+|[a-zA-Z-]+:\s*[^\r\n]*)/i,

    // Advanced detection for HTTP response splitting
    /(?:Content-Length:\s*\d+|Set-Cookie:.*?=|Location:\s*https?:\/\/|Content-Type:\s*text\/html)\s*(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|\\n|\\r)/i,

    // Header injection with context
    /(?:[hH][tT][tT][pP]\/[0-9.]+\s+\d{3}|[sS][eE][tT]-[cC][oO][oO][kK][iI][eE]:|[lL][oO][cC][aA][tT][iI][oO][nN]:|[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]:)(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|\\n|\\r|%5[cC]r%5[cC]n)/i,

    // Response splitting payload detection
    /(?:%0[dD]%0[aA]|%0[aA]%0[dD]|\\r\\n|\\n|\\r|%5[cC]r%5[cC]n){2}(?:<!DOCTYPE|<html|<script|<img|<svg|<iframe)/i,
  ];

  // ========== TEMPLATE INJECTION PATTERNS ==========
  static readonly TEMPLATE_INJECTION_PATTERNS = [
    // Server-side template injection with better context
    /{{[\s\S]*?(?:system|exec|popen|subprocess|os|writeFile|readFile|child_process|eval|[Pp]rocessBuilder|Runtime)[\s\S]*?}}/i,

    // Template expression detection across frameworks
    /(?:{{|<#|<%|\\${|#\{)[\s\S]*?(?:7\*7|2\*3\*2|3\.14|3\+4|5-2|1<<2|system|exec|__proto__|constructor|Object|Function|process\.env|global|module|require|child_process|spawn|forEach|toString|fromCharCode|eval|setTimeout|setInterval|Promise|fetch)[\s\S]*?(?:}}|#>|%>|\}|#\})/i,

    // Framework-specific template injection
    /{{\s*(?:constructor|self|this)(?:\.|(?:\['"\s*)]?)|(?:\[\s*["'`]?\s*)?(?:initializers|rawTemplate|innerTemplate|template|exec|code|script|view|render|compile|evaluate|parse|load|include)\s*(?:]?\s*['"`]?\s*\()?/i,

    // Access control bypass attempts
    /{{\s*(?:config|settings|env|process|app|global|root|GLOBAL|__proto__|constructor|__defineGetter__|__defineSetter__|__lookupGetter__|__lookupSetter__|prototype)\s*[.[][\s\S]*?\s*}}/i,

    // Framework-specific server-side rendering exploits
    /<(?:%|#)(?:=|:|-)?\s*(?:import|include|require|load|render|process|eval|exec|system|shell_exec|passthru|Request|response|application|session|cookie|end|puts|print|printf|write|system|eval|require|include|import|process|open|spawn)\s*(?:\(|[\s|.|:|\[])[\s\S]*?(?:%|#)>/i,

    // Object property access to bypass restrictions
    /{{\s*['"][\s\S]*?['"]\s*\[\s*['"](?:constructor|__proto__|prototype|__defineGetter__|__lookupGetter__)\s*['"]\s*\][\s\S]*?}}/i,

    // Prevention of false positives in common legitimate template syntax
    /{{(?!\s*(?:@?html\.|@?url\.|\s*(?:if|for|else|elseif|switch|case|default|while|do|try|catch|finally)))[\s\S]*?(?:\.(?:constructor|prototype|__proto__|global|process|child_process|exec|eval)|\[['"](constructor|prototype|__proto__|global|process|child_process|exec|eval)['"]\])[\s\S]*?}}/i,
  ];

  // ========== NOSQL INJECTION PATTERNS ==========
  static readonly NOSQL_INJECTION_PATTERNS = [
    // Operator-based injection with better context
    /(?:\?|&|=|:|\{)(?:[a-zA-Z0-9_$.]+)(?:=|:)\s*(?:\{)?\s*(?:[$](?:gt|gte|lt|lte|ne|in|nin|eq|all|regex|where|elemMatch|exists|type|mod|size|not))\s*(?:\})?/i,

    // MongoDB-specific operator injection
    /(?:\?|&|=|:|\{)(?:[a-zA-Z0-9_$.]+)(?:=|:)\s*(?:\{)?\s*(?:[$](?:and|or|nor|text|expr|jsonSchema|cond))\s*(?:\})?/i,

    // Type conversion/coercion attacks
    /(?:[?&;:=])(?:[a-zA-Z0-9_$.]+)=(?:\{\s*["'][$](?:type|where|size)\s*["']\s*:\s*)/i,

    // JavaScript code injection in expressions
    /(?:[?&;:=])(?:[a-zA-Z0-9_$.]+)=(?:\{\s*["'][$](?:where|expr)\s*["']\s*:\s*["']function\s*\(\)\s*\{[\s\S]*?return[\s\S]*?\}["']\s*\})/i,

    // Object property selector bypass
    /(?:[?&;:=][a-zA-Z0-9_$.]+)=(?:\{\s*["'][$](?!gt|gte|lt|lte|ne|in|nin|eq|all)[a-zA-Z0-9_$]+["']\s*:)/i,

    // Advanced MongoDB operators
    /(?:[?&;:=])(?:q|query|search|find|lookup|match|filter)=(?:\{\s*[$](?:regex|text|expr|func|eval|reduce|map|function)\s*:)/i,

    // Regular expression abuse
    /(?:[?&;:=])(?:[a-zA-Z0-9_$.]+)=(?:\{\s*["'][$]regex["']\s*:\s*["'](?:\(.*\)|\{.*\}|\[.*\]|\\x|\\u|\\.|\^|\$|\[\^|\|\*\+\?.*[\|*+?]?.*[\|*+?]?.*[\|*+?]?)["']\s*(?:,\s*["'][$]options["']\s*:\s*["'](?:i|m|x|s|g)+["'])?\s*\})/i,

    // Array operator manipulation
    /(?:[?&;:=])(?:[a-zA-Z0-9_$.]+)(?:\.\d+|\[\d+\])=(?:[^&]*[$](?:slice|push|addToSet|pop|pull|pullAll))/i,

    // JSON stringification bypass attempts
    /(?:[?&;:=])(?:[a-zA-Z0-9_$.]+)=(?:{"["'][$](?!gt|gte|lt|lte|ne|in|nin|eq|all)[a-zA-Z0-9_$]+["'"]"\s*:)|(?:JSON\.parse\(\s*['"`]\s*\{[\s\S]*?[$](?!gt|gte|lt|lte|ne|in|nin|eq|all)[a-zA-Z0-9_$]+["'\']\s*:)/i,
  ];
  static readonly GRAPHQL_INJECTION_PATTERNS = [
    // Introspection queries with better boundaries and context
    /(?:query\s+[\w_]*\s*\{|query\s*=\s*(?:[^{]*)){?\s*(?:__schema|__type|__typename)\s*(?:\([\s\S]*?\))?\s*\{(?!\s*\w+\s*\{)/i,

    // Deep nesting attacks with improved boundaries and specificity
    /(?:query\s+[\w_]*\s*\{|query\s*=\s*(?:[^{]*)){1}\s*(?:\w+(?:\([\s\S]*?\))?\s*\{){5,}/i,

    // Batch/aliased query detection with reduced false positives
    /(?:query\s+[\w_]*\s*\{|query\s*=\s*(?:[^{]*))(?:\s*[a-zA-Z0-9_]+\s*:\s*\w+(?:\([\s\S]*?\))?\s*\{){4,}/i,

    // Fragments with potential for bypassing controls - more specific context
    /(?:fragment\s+\w+\s+on\s+\w+\s*\{(?:[\s\S]*?__\w+|[\s\S]*?\bid\b|[\s\S]*?\bname\b))|(?:\.{3}\s*\w+Fragment(?:\s|$))/i,

    // Variable manipulation with improved boundary checking
    /(?:query\s+\w+\s*\(\s*\$[\w_]+\s*:\s*\w+!\s*=\s*(?:null|false|0|""|{}|\[\])\s*\))|(?:variables\s*=\s*\{[\s\S]*?(?:\bnull\b|\bfalse\b|\btrue\b|[{}\[\]])[\s\S]*?\}\s*$)/i,

    // Directive abuse with more specific patterns
    /(?:\s@\w+\s*\(\s*(?:if|include|skip)\s*:\s*[^)"']*(?:===|!==|==|!=|>=|<=|>|<|&&|\|\||\!)[^)"']*\))/i,

    // Mutation detection with improved context and specificity
    /(?:mutation\s+\w*\s*\{|mutation\s*=\s*(?:[^{]*)){1}\s*\w+(?:\([\s\S]*?\))?\s*\{(?:[\s\S]*?(?:\bid\b|\bdelete\b|\bremove\b|\bupdate\b|\bcreate\b|\bdrop\b|\badd\b|\binsert\b))(?:[^}]*)\}/i,

    // Custom directive injection with better boundary checking
    /(?:\s@\w+\s*\(\s*[\w]+\s*:\s*(?:["'`][\s\S]*?["'`]|[-\d.]+)\s*\))(?:\s*@|\s*\{|\s*$)/i,

    // Field suggestion exploitation with more precise detection
    /(?:__schema\s*\{[\s\S]*?(?:types|queryType|mutationType|subscriptionType|directives)[\s\S]*?\}|__type\s*\(\s*name\s*:\s*["'`][\w_]+["'`]?\s*\)\s*\{[\s\S]*?(?:fields|interfaces|enumValues|possibleTypes)[\s\S]*?\})/i,

    // Operation name manipulation with improved boundary detection
    /(?:operationName\s*=\s*["'`][\w_]+["'`])(?:\s*[,&]|\s*$)/i,
  ];

  // ========== ENCODED PAYLOAD PATTERNS ==========
  static readonly ENCODED_PAYLOAD_PATTERNS = [
    // Object serialization with improved detection and reduced false positives
    /(?:O:[1-9][0-9]*:"[a-zA-Z0-9_\\\\]+(?<!\\)":[1-9][0-9]*:\{|a:[1-9][0-9]*:\{(?:i:[0-9]+;|s:[1-9][0-9]*:")|N;}\)|C:[1-9][0-9]*:"[a-zA-Z0-9_\\\\]+")/i,

    // JSON type juggling detection with better context
    /(?:\{"[$](?:type|ref|id|class|identity)"\s*:\s*"[^"]*(?:Function|Object|Array|Date|RegExp|Promise|Error|Symbol|Map|Set|WeakMap|WeakSet|ArrayBuffer|SharedArrayBuffer|DataView|JSON|Math|Reflect|Intl|WebAssembly)"|"jsonrpc"\s*:\s*['"]\d+\.?\d*['"])/i,

    // Multi-encoding detection with better context and minimum length
    /(?:%(?:[0-9A-F]{2})){12,}|(?:%[0-9A-F]{2}){2,}(?:%(?:[0-9A-F]{2})){7,}/i,

    // Unicode escape sequence detection with minimum threshold
    /(?:\\u[0-9A-Fa-f]{4}){6,}|(?:%u[0-9A-Fa-f]{4}){6,}/i,

    // HTML entity encoding with minimum threshold and better specificity
    /(?:&#(?:x[0-9a-fA-F]{2}|[0-9]{2,3});){6,}/i,

    // Base64 detection with improved boundaries and character validation
    /(?:base64[,;:=]\s*(?:[A-Za-z0-9+/]){20,}(?:={0,2}))|(?:^|[=:()[\]{}|&!^,;]|url\(|data:)(?:[A-Za-z0-9+/]){30,}(?:={0,2})(?:$|[^A-Za-z0-9+/=])/i,

    // Protocol-independent URL encoding with better context
    /(?:%2F%2F|\/\/|\\\/\\\/|%5C%2F%5C%2F)(?:[\w%.-]+\.[\w%.-]+|\d{1,3}(?:\.\d{1,3}){3})/i,

    // Binary data detection with minimum threshold
    /(?:\\x[0-9A-Fa-f]{2}){12,}/i,

    // Long hexadecimal values with improved boundaries
    /(?:\b0x[0-9a-fA-F]{10,}\b)/i,

    // Data URI with potential payloads - improved specificity
    /(?:data:(?:text\/html|text\/javascript|application\/javascript|application\/x-javascript|image\/svg\+xml);base64,(?:[A-Za-z0-9+/]){20,}(?:={0,2}))/i,

    // Character code conversion with better specificity
    /(?:String\.fromCharCode\((?:\d+(?:\s*,\s*\d+){7,})\))|(?:(?:\\u[0-9A-Fa-f]{4}|\\\d{1,3}|\\x[0-9A-Fa-f]{2})){12,}/i,

    // Advanced sequences detection with improved context and reduced false positives
    /(?:[^\w\s<>=+\-*/\\()\[\]{};&|^%"'`.,][<>=+\-*/&|^%](?:[^\w\s<>=+\-*/\\()\[\]{};&|^%"'`.,])){7,}/i,
  ];

  // ========== SUSPICIOUS TLD PATTERNS ==========
  static readonly SUSPICIOUS_TLD_PATTERNS = [
    // Suspicious TLDs with better context-based detection
    /(?:https?:\/\/|\b)(?:free|get|claim|urgent|verify|access|secure|login|account|update|support|service|prize)[\w-]*\.(?:tk|ml|ga|cf|gq|top|xyz|pw|club|work|date|racing|win|review|stream|accountant|download|bid|loan|party|trade|cricket|faith|science|gdn|men|hosting|webcam|agency|fm|press|wf|report|rocks|band|market|click|host|site|tech|online|website|space|bar|uno|biz|red|eu|cc|in|surf|tokyo|link|world|network|zip|pro|icu|fun|cloud)(?:[/?#]|\s|$)/i,

    // Free subdomain services - only when combined with suspicious keywords
    /(?:https?:\/\/|\b)(?:verify|secure|bank|login|account|payment|wallet|crypto|reset|password|auth)[\w-]*\.(?:blogspot|wordpress|livejournal|tumblr|weebly|yolasite|angelfire|tripod|neocities|wixsite|webs)\.(?:com|net|org|info|biz)(?:[/?#]|\s|$)/i,

    // URL shorteners context - more specific patterns
    /(?:https?:\/\/|\b)(?:bit\.ly|goo\.gl|t\.co|tinyurl\.com|is\.gd|cli\.gs|pic\.gd|DwarfURL\.com|ow\.ly|yfrog|migre\.me|ff\.im|tiny\.cc|url4\.eu|tr\.im|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com|short\.ie|go2\.me|pli\.gs|dfl8\.me|tellyou\.com|prettylinkpro\.com|chod\.sk|adcraft\.co|smsh\.me|x\.co|prettylinkpro\.com|viralurl\.com|EasyURL\.net|simurl\.com|Shrinkify\.com|shrinkr\.com|dai\.ly|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.do|adcrun\.ch|buzzurl\.com|atu\.ca|anonypaste\.pro|twitthis\.com|u\.to|j\.mp|bee4\.biz|mcaf\.ee|scrnch\.me|wp\.me)\/\S+(?=.*(?:password|login|credential|bank|wallet|verify|bitcoin|eth|coin|nft|metamask|wallet|verify|urgent|limited|expires))/i,

    // Suspicious domain combinations with improved context
    /(?:https?:\/\/|\b)(?!nehonix\.space)(?:[\w-]+\.)?(?:link|verify|secure|account|signin|login|auth|confirm|validation|security|access|managment|manage|service|support|update)[\w-]*?-(?:bank|paypal|apple|google|facebook|instagram|microsoft|yahoo|amazon|netflix|ebay|twitter)\.(?:[a-z]{2,})(?:[/?#]|\s|$)/i,

    // Brand impersonation with specific TLDs - excludes legitimate domains
    /(?:https?:\/\/|\b)(?!nehonix\.space)(?:bank|paypal|apple|google|facebook|instagram|microsoft|yahoo|amazon|netflix|ebay|twitter)(?:[\w-]*?)(?:-?secure|-?login|-?verify|-?account|-?support|-?service)\.(?:tk|ml|ga|cf|gq|top|xyz|pw|club|work|date|racing|win|review|stream|accountant|webcam|science)(?:[/?#]|\s|$)/i,

    // Number-heavy domains with suspicious TLDs
    /(?:https?:\/\/|\b)(?!nehonix\.space)[\w-]*?\d{4,}[\w-]*?\.(?:tk|ml|ga|cf|gq|top|xyz|pw|club|work|date|racing)(?:[/?#]|\s|$)/i,
  ];

  // ========== HOMOGRAPH ATTACK PATTERNS ==========
  static readonly HOMOGRAPH_ATTACK_PATTERNS = [
    // Punycode domains with better context
    /(?:https?:\/\/|\b)xn--[\w-]+\.(?:com|net|org|io|edu|gov|mil|co|info|biz|me|tv|cc|name|mobi|cloud|xyz|shop|app|online|site|tech|store|blog)(?:[/?#]|\s|$)/i,

    // Mixed script confusables with improved detection
    /(?:https?:\/\/|\b)(?=.*[a-zA-Z])(?=.*[\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F])[\w\u0400-\u04FF\u0500-\u052F\u2DE0-\u2DFF\uA640-\uA69F.-]+\.(?:[a-z]{2,})(?:[/?#]|\s|$)/i,

    // Greek homographs in domain names
    /(?:https?:\/\/|\b)(?=.*[a-zA-Z])(?=.*[\u0370-\u03FF\u1F00-\u1FFF])[\w\u0370-\u03FF\u1F00-\u1FFF.-]+\.(?:[a-z]{2,})(?:[/?#]|\s|$)/i,

    // Specific confusable character patterns
    /(?:https?:\/\/|\b)(?:[\w-]*?)(?:g[ο0q][\w-]*?gl[e3]|[a@][mɱ][a@]z[o0]n|f[a@][c¢][e3]b[o0][o0]k|[a@]ppl[e3]|p[a@]yp[a@]l|[i1]n[s5]t[a@]gr[a@][mɱ]|[mɱ][i1][c¢]r[o0][s5][o0]ft|w[e3][a@]th[e3]r|g[mɱ][a@][i1]l|y[a@]h[o0][o0]|[i1][o0][s5]|[a@]ndr[o0][i1]d|[i1][o0][s5])(?:[\w-]*?)\.(?:[a-z]{2,})(?:[/?#]|\s|$)/i,

    // IDN homograph attack using similar-looking characters
    /(?:https?:\/\/|\b)(?=.*[a-zA-Z])(?=.*[\u00C0-\u00FF\u0100-\u017F\u0180-\u024F])[\w\u00C0-\u00FF\u0100-\u017F\u0180-\u024F.-]+(?:\.(?:com|net|org|io|edu|gov|mil|co|info|biz|me|tv))(?:[/?#]|\s|$)/i,

    // Common brand name homograph patterns
    /(?:https?:\/\/|\b)(?:[\w-]*?)(?:g[οσ0][\w-]*?gl[eе3]|[aа@][mм][\w-]*?z[oо0]n|f[aа@][cс][\w-]*?b[oо0][oо0]k|[aа@]ppl[eе3]|p[aа@]yp[aа@]l|[iі1]n[sѕ]t[aа@]gr[aа@][mм]|[mм][iі1][cс]r[oо0][sѕ][oо0]ft|g[mм][aа@][iі1]l|y[aа@]h[oо0][oо0])(?:[\w-]*?)\.(?:[a-z]{2,})(?:[/?#]|\s|$)/i,
  ];

  // ========== MULTI_ENCODING_PATTERNS ==========
  static readonly MULTI_ENCODING_PATTERNS = [
    // Double encoding with better detection
    /(?:%25(?:[0-9A-Fa-f]{2})){3,}/i,

    // Mixed hex encoding
    /(?:%[0-9A-Fa-f]{2}){1,}(?:%[0-9A-Fa-f]{2}){1,}(?:%[0-9A-Fa-f]{2}){1,}/i,

    // Unicode + percent encoding combinations
    /(?:%u[0-9A-Fa-f]{4}){1,}(?:%[0-9A-Fa-f]{2}){1,}/i,

    // HTML + URL encoding combinations
    /(?:&#(?:x[0-9a-fA-F]{2}|[0-9]{2,3});){1,}(?:%[0-9A-Fa-f]{2}){1,}/i,

    // Triple encoding detection
    /(?:%25)*(?:%25[0-9A-Fa-f]{2}){3,}/i,

    // Alternative multi-encoding techniques
    /(?:\\u[0-9A-Fa-f]{4}|\\\d{1,3}|\\x[0-9A-Fa-f]{2}){1,}(?:%[0-9A-Fa-f]{2}){1,}/i,

    // Overlong UTF-8 sequences
    /(?:%[CEF][0-9A-Fa-f]%[8-9A-Ba-f][0-9A-Fa-f](?:%[8-9A-Ba-b][0-9A-Fa-f]){1,})/i,

    // Mixed octal, hex, and decimal encoding
    /(?:&#(?:0[0-7]{1,3}|[0-9]{1,3}|x[0-9A-Fa-f]{1,2});){1,}(?:\\[0-7]{1,3}|\\x[0-9A-Fa-f]{1,2}){1,}/i,
  ];

  // ========== SUSPICIOUS_PARAMETER_NAMES ==========
  // ========== SUSPICIOUS_PARAMETER_NAMES ==========
  /**
   * Enhanced list of suspicious parameter names with:
   * - Better organization by category (via comments)
   * - Improved naming patterns to catch variations
   * - Removal of common false positives
   * - Addition of modern attack vectors
   */
  static readonly SUSPICIOUS_PARAMETER_NAMES: string[] = [
    // ----- COMMAND EXECUTION (HIGH RISK) -----
    "cmd",
    "exec",
    "command",
    "shell",
    "execute",
    "ping",
    "query",
    "code",
    "run",
    "exe",
    "payload",
    "invoke",
    "eval",
    "runtime",
    "call",
    "system",
    "spawn",
    "child_process",
    "proc_open",
    "popen",
    "passthru",
    "execute_cmd",
    "exec_shell",
    "syscall",
    "script_exec",
    "shellexec",
    "bash",
    "sh",
    "powershell",
    "cmd.exe",

    // ----- OS & SYSTEM ACCESS (HIGH RISK) -----
    "system",
    "os",
    "kernel",
    "driver",
    "service",
    "proc",
    "process",
    "memory",
    "hardware",
    "device",
    "thread",
    "job",
    "application",
    "binary",
    "sysctrl",
    "sysreq",
    "crash",
    "overflow",
    "buffer",
    "stack",
    "heap",
    "sysconf",

    // ----- PRIVILEGED ACCESS (HIGH RISK) -----
    "admin",
    "root",
    "superuser",
    "supervisor",
    "manager",
    "sudo",
    "su",
    "elevation",
    "privilege",
    "grant",
    "privs",
    "permissions",
    "rights",
    "access",
    "auth",
    "authenticate",
    "runas",
    "elevated",
    "uac",
    "setuid",
    "setgid",
    "chmod",
    "chown",
    "priv_esc",
    "escalate",
    "authority",

    // ----- INJECTION VECTORS (HIGH RISK) -----
    "injection",
    "sql",
    "sqli",
    "nosql",
    "ldap",
    "xpath",
    "template",
    "ssti",
    "expression",
    "render",
    "compile",
    "statement",
    "sanitize",
    "escape",
    "unsafe",
    "raw",
    "unescaped",
    "unfiltered",
    "eval_tpl",
    "jinja",
    "erb",
    "handlebars",
    "vulnerable",
    "deserialize",
    "pickle",

    // ----- FILE OPERATIONS (HIGH RISK) -----
    "file",
    "path",
    "include",
    "require",
    "load",
    "import",
    "open",
    "read",
    "write",
    "upload",
    "download",
    "save",
    "delete",
    "unlink",
    "filepath",
    "pathname",
    "dir",
    "directory",
    "folder",
    "lfi",
    "rfi",
    "path_traversal",
    "directory_traversal",
    "symlink",
    "readfile",
    "writefile",
    "fopen",
    "fread",

    // ----- NETWORK & URL (HIGH RISK) -----
    "url",
    "uri",
    "domain",
    "host",
    "server",
    "endpoint",
    "address",
    "remote",
    "proxy",
    "dns",
    "connect",
    "ssrf",
    "request_uri",
    "redirect_uri",
    "callback_url",
    "webhook",
    "forward_to",
    "next_url",
    "return_url",
    "dest",
    "destination",
    "target",
    "location",
    "referrer",
    "resource",
    "cors",
    "origin",

    // ----- CREDENTIALS & SECRETS (HIGH RISK) -----
    "password",
    "passwd",
    "pwd",
    "pass",
    "secret",
    "key",
    "token",
    "hash",
    "salt",
    "seed",
    "hmac",
    "digest",
    "login",
    "cred",
    "credential",
    "apikey",
    "api_key",
    "jwt",
    "oauth",
    "bearer",
    "cert",
    "certificate",
    "private_key",
    "public_key",
    "sign",
    "signature",
    "crypto",
    "encrypt",
    "decrypt",

    // ----- DATABASE ACCESS (MEDIUM RISK) -----
    "db",
    "database",
    "query",
    "sql",
    "data",
    "source",
    "dsn",
    "db_query",
    "db_name",
    "table",
    "column",
    "select",
    "insert",
    "update",
    "delete",
    "where",
    "from",
    "join",
    "group",
    "order",
    "having",
    "limit",
    "mongo",
    "redis",
    "memcache",
    "dba",

    // ----- CONFIGURATION (MEDIUM RISK) -----
    "config",
    "conf",
    "cfg",
    "setting",
    "setup",
    "option",
    "init",
    "env",
    "environment",
    "registry",
    "boot",
    "startup",
    "module",
    "component",
    "flag",
    "feature",
    "toggle",
    "switch",
    "control",
    "param",
    "parameter",
    "arg",
    "argument",
    "prop",
    "property",

    // ----- DEBUGGING & TESTING (MEDIUM RISK) -----
    "debug",
    "test",
    "dev",
    "development",
    "internal",
    "trace",
    "verbose",
    "info",
    "log",
    "console",
    "dump",
    "profile",
    "bypass",
    "skip_validation",
    "no_check",
    "backdoor",
    "testing",
    "diagnostics",
    "troubleshoot",
    "debug_mode",
    "mock",
    "stub",

    // ----- WEB & FRONTEND (LOWER RISK) -----
    "html",
    "xml",
    "json",
    "yaml",
    "text",
    "script",
    "iframe",
    "embed",
    "object",
    "xss",
    "javascript",
    "js",
    "css",
    "dom",
    "render",
    "view",
    "template",
    "layout",
    "page",
    "content",
    "sanitize",
    "filter",
    "encode",
    "decode",
    "transform",

    // ----- COMMON OPERATION VERBS (CONTEXT-DEPENDENT) -----
    "do",
    "load",
    "process",
    "step",
    "action",
    "act",
    "perform",
    "trigger",
    "dispatch",
    "execute",
    "run",
    "launch",
    "start",

    // ----- MODERN ATTACK VECTORS -----
    "prototype",
    "constructor",
    "proto",
    "__proto__",
    "function",
    "callback",
    "promise",
    "async",
    "await",
    "timeout",
    "interval",
    "worker",
    "child",
    "parent",
    "iframe",
    "window",
    "document",
    "global",
    "fetch",
    "xhr",
    "ajax",
    "jsonp",
    "postmessage",
  ];
  // ========== RFI_PATTERNS ==========
  static readonly RFI_PATTERNS = [
    // External file inclusion with better context
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:https?:\/\/[^/\s,;]+\/[^/\s,;]+\.(?:php|phtml|php[3-7]|pht|phps|php-s|php_s|inc|cgi|asp|aspx|jsp|jspx|json|cfm|tpl|nxt|cshtml|shtml|shtm|xhtml|xml|rss|svg|yaml|yml|txt|conf|config|ini|htaccess))/i,

    // Path traversal combined with RFI
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:(?:%2E|%2e|\.){2}(?:%2F|%2f|\/|\\)+){1,}[^/\s,;]+\.(?:php|phtml|php[3-7]|pht|phps|php-s|php_s|inc|cgi|asp|aspx|jsp|jspx|json|cfm|tpl|nxt|cshtml|shtml|shtm|xhtml|xml)/i,

    // PHP wrapper abuse
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:php:\/\/(?:filter\/(?:convert\.(?:base64-[de]ncode|quoted-printable-[de]ncode)|resource=)|expect|input|stdin|memory|temp|data:|zip:|phar:|glob:|file:|compression\.|rar:|ogg:|ssh2:|ftp:|ftps:|zlib:))/i,

    // Data URI scheme for code injection
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:data:(?:text\/plain|text\/html|text\/xml|application\/xml|application\/json|application\/javascript|application\/x-httpd-php|image\/svg\+xml);(?:base64,)?[a-zA-Z0-9+/=]{10,})/i,

    // Protocol agnostic inclusion
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:\/\/[^/\s,;]+\/[^/\s,;]+\.(?:php|phtml|php[3-7]|pht|phps|inc|cgi|asp|aspx|jsp|jspx|cfm))/i,

    // FTP/SMB protocol inclusion
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:(?:ftp|ftps|smb|ssh|ssh2):\/\/[^/\s,;]+\/[^/\s,;]+\.(?:php|phtml|php[3-7]|pht|phps|inc|cgi|asp|aspx|jsp|jspx|cfm))/i,

    // Code evaluation via import/evaluation functions
    /(?:[?&;](?:eval|code|script|run|exec))=(?:[^&]*(?:base64_decode|eval|assert|passthru|system|exec|shell_exec|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source|highlight_file))/i,

    // Remote content retrieval functions
    /(?:[?&;](?:file|document|template|path|filepath|load|read|include|require|inc|show|display))=(?:[^&]*(?:file_get_contents|fopen|readfile|fread|fgets|file|copy|move_uploaded_file|stream_get_contents|include|require|require_once|include_once))/i,
  ];

  // ========== ADVANCED ATTACK DETECTION ==========
  // New pattern sets for more comprehensive detection

  // Deserialization attacks
  static readonly DESERIALIZATION_PATTERNS = [
    // PHP Object Injection
    /(?:[?&;](?:data|input|obj|object|param|var|payload|p))=(?:O:[0-9]+:"[a-zA-Z0-9_\\\\]+":[0-9]+:{.*?(?:protected|private|public).*?})/i,

    // Java deserialization
    /rO0[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=]{20,}/i,

    // .NET deserialization
    /(?:[?&;](?:data|input|obj|object|payload))=(?:\{["']?\$type["']?:["']?System\.[a-zA-Z0-9_.]+["']?)/i,

    // Python pickle
    /[cgis](?:\(.*?\)|$)(?:\n[cgis](?:\(.*?\)|$))+/i,

    // Ruby Marshal
    /(?:[?&;](?:data|input|obj|object|param|var|payload|p))=(?:\x04\x08[CIUT:@])/i,

    // YAML deserialization
    /(?:[?&;](?:data|input|yaml|yml))=(?:!(?:ruby\/object|ruby\/hash|ruby\/struct|ruby\/module|ruby\/regexp|ruby\/class|ruby\/range|ruby\/encoding)|!!python\/[a-z]+)/i,
  ];

  // Server-Side Request Forgery extended patterns
  static readonly ADVANCED_SSRF_PATTERNS = [
    // AWS metadata service variations
    /(?:[?&;](?:url|uri|endpoint|site|server|host|path|fetch|read|get|load))=(?:https?:\/\/(?:169\.254\.169\.254|fd00:ec2::254|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.ec2\.internal)\/latest\/(?:meta-data|user-data|dynamic))/i,

    // Cloud providers' metadata services
    /(?:[?&;](?:url|uri|endpoint|site|server|host|path|fetch|read|get|load))=(?:https?:\/\/(?:metadata\.google\.internal\/computeMetadata|metadata\.gcp\.internal|metadata\.instance\.internal|169\.254\.169\.254\/computeMetadata|169\.254\.169\.254\/metadata\/v1|metadata\.azure\.internal\/metadata\/instance|169\.254\.169\.254\/metadata\/computeMetadata))/i,

    // Docker / Kubernetes API access
    /(?:[?&;](?:url|uri|endpoint|site|server|host|path|fetch|read|get|load))=(?:https?:\/\/(?:kubernetes\.default\.svc|etcd\.|docker\.socket|docker\.sock|\/var\/run\/docker\.sock|127\.0\.0\.1:(?:2375|2376|4243|4244)))/i,

    // Service discovery exploitation
    /(?:[?&;](?:url|uri|endpoint|site|server|host|path|fetch|read|get|load))=(?:https?:\/\/(?:consul\.|vault\.|eureka\.|zookeeper\.|etcd\.|rancher\.|nomad\.)(?:[\w-]+)?(?::[0-9]+)?(?:\/v[0-9]+)?\/(?:catalog|node|service|kv|discovery|api|client|agent))/i,

    // Database/service direct access
    /(?:[?&;](?:url|uri|endpoint|site|server|host|path|fetch|read|get|load))=(?:(?:mongodb|redis|memcache|postgres|mysql|ldap|smtp|telnet|ssh|ftp|vnc|rdp):\/\/[\w\-.:])/i,
  ];

  // OAuth/JWT exploitation patterns
  static readonly AUTH_BYPASS_PATTERNS = [
    // JWT manipulation (alg:none, weak signatures)
    /(?:eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.(?:[a-zA-Z0-9_-]{0,4}|\{\s*"alg"\s*:\s*"none"\s*\}))/i,

    // OAuth redirection manipulation
    /(?:[?&;](?:redirect_uri|callback|oauth_callback|url|next|return_to))=(?:https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org|your-domain\.com|localhost))[\w-]+\.[\w.-]+)/i,

    // API key/token exfiltration
    /(?:[?&;](?:access_token|api_key|apikey|api-key|token|auth|password|secret|key|hash|pw|user|uid|username))=(?:[A-Za-z0-9_-]{20,})/i,

    // OAuth state parameter tampering
    /(?:[?&;](?:state|nonce|oauth_state))=(?:[A-Za-z0-9+/=]{10,})/i,
  ];
}
