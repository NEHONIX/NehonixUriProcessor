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
    ],
    
    #
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
 }