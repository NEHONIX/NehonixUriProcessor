// export class PARTTERNS {
//   // Pattern collections for different attack types
//   static readonly SQL_INJECTION_PATTERNS = [
//     /(?:('|\s)or\s+\d+=\d+|union\s+select|--\s|;\s*--|;\s*drop|;\s*insert|exec\s*\(|\bselect\s+.*?\bfrom\b|\bdelete\s+from\b|\bupdate\s+.*?\bset\b|\bwaitfor\s+delay\b|\bsleep\s*\(|\bchar\s*\(|\bconcat\s*\(|\having\s+\d+=\d+|cast\s*\(|convert\s*\(|;\s*shutdown|xp_cmdshell)/i, // Catches common SQL injection patterns like OR 1=1, UNION SELECT, and dangerous functions
//     /('|\s)or\s+\d+=\d+/i,
//     /union\s+select/i,
//     /--\s|;\s*--/i,
//     /;\s*drop/i,
//     /;\s*insert/i,
//     /exec\s*\(/i,
//     /'\s*\+\s*'/i,
//     /\bselect\s+.*?\bfrom\b/i,
//     /\bdelete\s+from\b/i,
//     /\bupdate\s+.*?\bset\b/i,
//     /\bwhere\s+\d+=\d+/i,
//     /\bwaitfor\s+delay\b/i,
//     /\bsleep\s*\(/i,
//     /\bchar\s*\(/i,
//     /\bconcat\s*\(/i,
//     /\having\s+\d+=\d+/i,
//     /cast\s*\(/i,
//     /convert\s*\(/i,
//     /;\s*shutdown/i,
//     /xp_cmdshell/i,
//     /(\b)(select|insert|update|delete|drop|alter|create|exec|union|truncate|declare|set)(\s+)/gi,
//     /(\b)(from|where|group\s+by|order\s+by|having|join|inner\s+join|outer\s+join|left\s+join|right\s+join)(\s+)/gi,
//     /--/g,
//     /\/\*.*?\*\//g,
//     /'(\s*)(or|and)(\s+)['0-9]/gi,
//   ];

//   static readonly XSS_PATTERNS = [
//     /#.*<script/i,
//     /#.*%3Cscript/i, // Encoded <script in fragment
//     /#.*javascript:/i,
//     /<script/i,
//     /javascript:/i,
//     /on\w+\s*=/i,
//     /alert\s*\(/i,
//     /eval\s*\(/i,
//     /\bdata:\s*text\/html/i,
//     /\bvbscript:/i,
//     /\bbase64/i,
//     /\bxss:/i,
//     /\bimg\s+src/i,
//     /\biframe\s+src/i,
//     /\bdocument\.cookie/i,
//     /\bdocument\.location/i,
//     /\bwindow\.location/i,
//     /\bdocument\.write/i,
//     /\bdocument\.\w+\s*=/i,
//     /fromCharCode/i,
//     /String\.fromCharCode/i,
//     /\bsvg\s+onload/i,
//     /\bobject\s+data/i,
//     /\bembed\s+src/i,
//   ];

//   static readonly COMMAND_INJECTION_PATTERNS = [
//     /;\s*\w+/i,
//     /\|\s*\w+/i,
//     /`\s*\w+/i,
//     /\$\(/i,
//     /\&\s*\w+/i,
//     /\|\|\s*\w+/i,
//     /\&\&\s*\w+/i,
//     /\bping\s+-c\b/i,
//     /\bnc\s+/i,
//     /\bnetcat\b/i,
//     /\bnmap\b/i,
//     /\bcurl\s+/i,
//     /\bwget\s+/i,
//     /\btelnet\s+/i,
//     /\bpowershell\b/i,
//     /\bcmd\b/i,
//     /\bbash\b/i,
//     /\bsh\b/i,
//     /\bch(mod|own|grp)/i,
//     /\brm\s+-rf/i,
//     /;\s*(whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\b/i,
//     /\|\s*(whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\b/i,
//     /`\s*(whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\b/i,
//     /\$\((whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\)/i,
//     /&&\s*(whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\b/i,
//     /\|\|\s*(whoami|ping|curl|wget|nc|netcat|telnet|powershell|cmd|bash|sh|chmod|chown|rm)\b/i,
//     /\bping\s+-c\b/i,
//     /\brm\s+-rf\b/i,
//   ];

//   static readonly PATH_TRAVERSAL_PATTERNS = [
//     /\.\.\//i, // ../
//     /\.\.\/\.\\\//i, // ..\.\/ (Windows-style path traversal)
//     /%2e%2e\//i, // %2e%2e/ (URL encoded ../)
//     /%252e%252e\//i, // %252e%252e/ (Double URL encoded ../)
//     /\.\.%2f/i, // ..%2f (URL encoded slash)
//     /\.\.%5c/i, // ..%5c (URL encoded backslash)
//     /\.\.\+\//i, // ..+/ (With plus character)
//     /\.\.\+\\\//i, // ..+\/ (With plus and escaped backslash)
//     /\/%c0%ae\.\./i, // /%c0%ae../ (Alternative encoding)
//     /\/\.\.\/\.\.\//i, // /../../ (Multiple traversal)
//     /\\\\\.\.\\\\\.\.\\\\\//i, // \\..\\..\\ (Windows UNC style)
//     /etc\/passwd/i, // etc/passwd (Linux sensitive file)
//     /etc\/shadow/i, // etc/shadow (Linux sensitive file)
//     /boot\.ini/i, // boot.ini (Windows sensitive file)
//     /win\.ini/i, // win.ini (Windows sensitive file)
//     /system32/i, // system32 (Windows system directory)
//     /\/proc\/self\//i, // /proc/self/ (Linux proc directory)
//   ];

//   static readonly OPEN_REDIRECT_PATTERNS = [
//     /url=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i, // Allow specific trusted domains
//     /redirect=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /to=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /returnUrl=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /next=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /return=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /destination=https?:\/\/(?!(?:[\w-]+\.)*(?:example\.com|trusted\.org))[\w.-]+/i,
//     /goto=javascript:/i, // Catch JavaScript protocol redirects
//     /link=\/\/[\w.-]+/i, // Protocol-relative redirects
//   ];

//   static readonly SSRF_PATTERNS = [
//     /https?:\/\/127\.0\.0\.1/i,
//     /https?:\/\/localhost/i,
//     /https?:\/\/0\.0\.0\.0/i,
//     /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
//     /https?:\/\/172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}/i,
//     /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/i,
//     /https?:\/\/169\.254\.\d{1,3}\.\d{1,3}/i,
//     /https?:\/\/::1/i,
//     /file:\/\//i,
//     /dict:\/\//i,
//     /gopher:\/\//i,
//     /ldap:\/\//i,
//     /tftp:\/\//i,
//     /http:\/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i, // AWS EC2 metadata endpoint pattern
//     /http:\/\/metadata\./i,
//     /http:\/\/169\.254\.169\.254/i, // Cloud metadata endpoints
//   ];

//   static readonly CRLF_INJECTION_PATTERNS = [
//     /%0D%0A/i,
//     /%0d%0a/i,
//     /%0D%0a/i,
//     /%0d%0A/i,
//     /\r\n/i,
//     /%E5%98%8A%E5%98%8D/i, // Unicode CRLF
//     /%0A/i,
//     /%0a/i,
//     /%0D/i,
//     /%0d/i,
//   ];

//   static readonly TEMPLATE_INJECTION_PATTERNS = [
//     /\{\{>[^}]+}}/i, // Handlebars partials
//     /\{\{#[^}]+}}/i, // Handlebars blocks
//     /\{\{\{[^}]+}}}/i, // Mustache unescaped
//     /<%-[^%]+%>/i, // EJS template
//     /\${.*?}/i,
//     /<#.*?>/i,
//     /<\?.*?\?>/i,
//     /\{\{.*?\}\}/i,
//     /<\%.*?\%>/i,
//     /\$\{7\*7\}/i,
//     /\{\{7\*7\}\}/i,
//     /\{\{.+?\|eval\}\}/i,
//     /\{\{constructor.constructor\('.*?'\)/i,
//     /\{\{request\}}/i,
//   ];

//   static readonly NOSQL_INJECTION_PATTERNS = [
//     /\$where:/i,
//     /\$eq:/i,
//     /\$gt:/i,
//     /\$lt:/i,
//     /\$ne:/i,
//     /\$nin:/i,
//     /\$in:/i,
//     /\$regex:/i,
//     /\$exists:/i,
//     /\$elemMatch:/i,
//     /".*\$ne":/i,
//     /'.*\$ne':/i,
//     /".*\$regex":/i,
//     /'.*\$regex':/i,
//     /\{".*":[\s]*\{.*\}/i,
//     /\{'.*':[\s]*\{.*\}/i,
//   ];

//   static readonly GRAPHQL_INJECTION_PATTERNS = [
//     /introspection.*__schema/i,
//     /\{__schema\{/i,
//     /\{__type\(/i,
//     /mutation\s*\{/i,
//     /\)\s*\{\s*__typename/i,
//     /fragment\s+on\s+/i,
//     /query\s*\{.*\{.*\{.*\{/i, // Deeply nested queries
//     /query\s+\w+\s*\{.*\{.*\{.*\{/i,
//     /query\s+\w+\s*@/i, // Custom directive
//   ];

//   static readonly ENCODED_PAYLOAD_PATTERNS = [
//     /O:\d+:"[a-zA-Z0-9_]+":\d+:\{/i, // PHP serialized object
//     /\{"\$type":"System\.[a-zA-Z0-9_.]+/i, // JSON.NET serialization
//     /(%[0-9a-fA-F]{2}){10,}/i, // Multiple percent encodings
//     /(\\u[0-9a-fA-F]{4}){5,}/i, // Multiple unicode escape sequences
//     /&#x[0-9a-fA-F]{2};/i, // HTML hex encoding
//     /&#\d{2,3};/i, // HTML decimal encoding
//     /base64[,;:=][a-zA-Z0-9+/=]{20,}/i, // Base64 data
//     /[a-zA-Z0-9+/=]{30,}/i, // Potential base64
//     /%u[0-9a-fA-F]{4}/i, // Unicode encoding
//     /\\x[0-9a-fA-F]{2}/i, // Hex escape sequences
//     /0x[0-9a-fA-F]{10,}/i, // Long hex value
//     /data:.*?base64/i, // Data URI with base64
//   ];

//   static readonly SUSPICIOUS_TLD_PATTERNS = [
//     /\.(tk|ml|ga|cf|gq|top|xyz|pw|club|work|date|racing|win|review|stream|accountant|download|bid)\b/i,
//   ];

//   // In attacks_parttens.txt
//   static readonly HOMOGRAPH_ATTACK_PATTERNS = [
//     /xn--/i, // Punycode prefix for IDN
//     /[\u0430\u0435\u043E\u0440\u0441\u0445\u0456\u0458\u0459\u045A\u045B]{2,}/i, // Cyrillic look-alikes
//     /[\u0261\u1D26\u0251\u1D25\u00F8\u038C\u03F4\u03A1\u03F9\u0398]{2,}/i, // Greek look-alikes
//     /[\u00C0-\u00FF][a-zA-Z0-9]*[\u00C0-\u00FF]/i, // Mixed Latin and extended Latin
//     /([a-zA-Z])([\u0400-\u04FF])/i, // Mixed Latin and Cyrillic
//   ];

//   static readonly MULTI_ENCODING_PATTERNS = [
//     /%25[0-9a-fA-F]{2}/i, // Double percent encoding
//     /%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}/i, // Mixed encoding
//     /%u[0-9a-fA-F]{4}%[0-9a-fA-F]{2}/i, // Unicode + percent encoding
//     /&#x[0-9a-fA-F]{2};%[0-9a-fA-F]{2}/i, // HTML + percent encoding
//   ];

//   static readonly SUSPICIOUS_PARAMETER_NAMES = [
//     "cmd",
//     "exec",
//     "command",
//     "shell",
//     "execute",
//     "ping",
//     "query",
//     "jump",
//     "code",
//     "reg",
//     "do",
//     "func",
//     "function",
//     "option",
//     "load",
//     "process",
//     "step",
//     "read",
//     "feature",
//     "admin",
//     "cfg",
//     "config",
//     "password",
//     "passwd",
//     "pwd",
//     "auth",
//     "source",
//     "debug",
//     "test",
//     "secret",
//     "ip",
//     "pass",
//     "priv",
//     "root",
//     "login",
//     "admin",
//     "net",
//     "grant",
//     "host",
//     "superuser",
//     "enable",
//     "system",
//     "internal",
//     "globals",
//     "bypass",
//     "master",
//     "access",
//     "dev",
//     "setup",
//     "account",
//     "module",
//     "app",
//     "db",
//     "sql",
//     "secure",
//     "run",
//     "reg",
//     "registry",
//     "key",
//   ];

//   static readonly RFI_PATTERNS = [
//     /file=https?:\/\/[\w.-]+\/.*\.(php|txt|xml|html)/i, // External file inclusion
//     /include=https?:\/\/[\w.-]+\/.*\.(php|txt|xml|html)/i,
//     /page=https?:\/\/[\w.-]+\/.*\.(php|txt|xml|html)/i,
//     /file=\/\/[\w.-]+\/.*\.(php|txt|xml|html)/i, // Protocol-relative inclusion
//     /file=php:\/\/filter\/.*\/resource=/i, // PHP filter wrapper
//     /file=data:text\/.*base64,/i, // Data URI inclusion
//   ];
// }
