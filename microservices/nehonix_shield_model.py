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

# Constants
MODEL_DIR = "microservices/models"
MODEL_VERSION = "v1.0"
FEATURES_FILE = f"{MODEL_DIR}/features_{MODEL_VERSION}.json"
MODEL_FILE = f"{MODEL_DIR}/ml_model_{MODEL_VERSION}.joblib"
SCALER_FILE = f"{MODEL_DIR}/scaler_{MODEL_VERSION}.joblib"
META_FILE = f"{MODEL_DIR}/meta_{MODEL_VERSION}.json"
LOG_FILE = f"{MODEL_DIR}/ml_service_{MODEL_VERSION}.log"

# Attack pattern signatures for feature engineering
ATTACK_PATTERNS = {
    "sql_injection": [
        r"'(\s|\+)*(OR|AND)(\s|\+)*[0-9]", r"SELECT(\s|\+)*FROM", r"UNION(\s|\+)*SELECT",
        r"INSERT(\s|\+)*INTO", r"DROP(\s|\+)*TABLE", r"admin'--", r"1'; DROP TABLE users; --",
        r"' OR 1=1 LIMIT 1; --", r"' OR username LIKE '%admin%'", r"'; EXEC xp_cmdshell('net user'); --"
    ],
    "xss": [
        r"<script>", r"javascript:", r"onerror=", r"onload=", r"eval\(", r"document\.cookie",
        r"<img src=['\"]?x['\"]? onerror=", r"<svg/onload=", r"<body onload=", r"<iframe src=['\"]?javascript:",
        r"\"><script>", r"<div style=['\"]?background-image: url\(javascript:"
    ],
    "path_traversal": [
        r"\.\./", r"%2e%2e/", r"\.\.\\", r"file:", r"../etc/passwd", r"..%2f..%2f..%2fetc%2fpasswd",
        r"/var/www/../../etc/passwd", r"php://filter", r"data:text/plain"
    ],
    "command_injection": [
        r"\|\s*[a-zA-Z]+", r"\&\s*[a-zA-Z]+", r";\s*[a-zA-Z]+", r"`[^`]+`", r"\$\(whoami\)",
        r"; ping -c 4", r"\| nc ", r"&& curl ", r"; bash -i >& /dev/tcp/"
    ],
    "prototype_pollution": [
        r"__proto__", r"constructor", r"prototype", r"__proto__\[admin\]", r"constructor\.prototype\.admin",
        r"__lookupGetter__", r"__defineGetter__"
    ],
    "deserialization": [
        r"rO0", r"O:[0-9]+:", r"YToxOntzOjg6ImNsYXNzbmFtZSI7czo2OiJTeXN0ZW0iO30=", r"Tzo5OiJQYWdlTW9kZWwiOjE6e",
        r"eyJyY2UiOiJfJF9GVU5DVC1fMyggJ3Rlc3QnICkiLCJwaHAiOiI8P3BocCBwaHBpbmZvKCk7Pz4ifQ=="
    ],
    "jwt_manipulation": [
        r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.", r"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
        r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ],
    "ssrf": [
        r"localhost", r"127\.0\.0\.1", r"0\.0\.0\.0", r"192\.168\.", r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"169\.254\.169\.254", r"\[::1\]", r"file:///", r"gopher://"
    ]
}

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


def extract_advanced_features(input_data: Union[str, Dict]) -> Dict[str, float]:
    """Extract advanced features from input data (URL or parsed features)."""
    features = {}
    
    if isinstance(input_data, dict):
        return input_data
    
    url = input_data
    features["length"] = len(url)
    features["entropy"] = calculate_entropy(url)
    features["digit_ratio"] = len([c for c in url if c.isdigit()]) / max(len(url), 1)
    
    # Further reduce the impact of special_char_ratio
    special_chars = len([c for c in url if not c.isalnum()])
    features["special_char_ratio"] = min(special_chars / max(len(url), 1), 0.3)  # Lower cap to 0.3
    
    features["percent_encoded_chars"] = url.count('%') / max(len(url), 1)
    features["double_encoded"] = 1.0 if '%25' in url else 0.0
    features["hex_ratio"] = len([i for i in range(len(url)-1) if url[i:i+2].lower() in 
                              ['0x', '\\x']]) / max(len(url)-1, 1)
    
    for pattern_type, patterns in ATTACK_PATTERNS.items():
        features[f"has_{pattern_type}"] = 0
        for pattern in patterns:
            import re
            if re.search(pattern, url, re.IGNORECASE):
                features[f"has_{pattern_type}"] = 1
                break
    
    # Reduce the impact of suspicious keywords
    features["suspicious_keyword_count"] = min(sum(1 for kw in SUSPICIOUS_KEYWORDS if kw.lower() in url.lower()), 2) / 2.0  # Cap at 2, normalize
    
    try:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        
        features["domain_length"] = len(parsed.netloc)
        features["path_length"] = len(parsed.path)
        
        # Further reduce the impact of query_length and param_count
        features["query_length"] = min(len(parsed.query), 20) / 20.0  # Lower cap to 20
        query_params = parse_qs(parsed.query)
        features["param_count"] = min(len(query_params), 2) / 2.0  # Lower cap to 2
        
        features["subdomain_count"] = parsed.netloc.count('.')
        features["path_depth"] = parsed.path.count('/')
        features["fragment_length"] = len(parsed.fragment)
        
        tld = parsed.netloc.split('.')[-1] if '.' in parsed.netloc else ''
        features["tld_length"] = len(tld)
        features["is_common_tld"] = 1.0 if tld.lower() in ['com', 'org', 'net', 'edu', 'gov'] else 0.0
        
        if ':' in parsed.netloc:
            port = parsed.netloc.split(':')[1]
            features["unusual_port"] = 1.0 if port not in ['80', '443'] else 0.0
        else:
            features["unusual_port"] = 0.0
            
        # Domain similarity to common domains
        features["domain_similarity"] = calculate_domain_similarity(parsed.netloc)
        
    except Exception:
        url_features = [
            "domain_length", "path_length", "query_length", "subdomain_count",
            "path_depth", "param_count", "fragment_length", "tld_length",
            "is_common_tld", "unusual_port", "domain_similarity"
        ]
        for feature in url_features:
            features[feature] = 0.0
    
    # Base64 detection
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
    """Create an ensemble of different models for better performance."""
    rf = RandomForestClassifier(
        n_estimators=50,  # Increased
        max_depth=8,     # Increased
        min_samples_split=50,  # Reduced
        min_samples_leaf=20,   # Reduced
        random_state=42
    )
    
    gb = GradientBoostingClassifier(
        n_estimators=50,  # Increased
        learning_rate=0.05,  # Increased
        max_depth=3,     # Increased
        random_state=42
    )
    
    xgb = XGBClassifier(
        n_estimators=50,  # Increased
        learning_rate=0.05,  # Increased
        max_depth=3,     # Increased
        reg_lambda=2.0,  # Reduced
        random_state=42
    )
    
    ensemble = VotingClassifier(
        estimators=[
            ('rf', rf),
            ('gb', gb),
            ('xgb', xgb)
        ],
        voting='soft',
        weights=[1, 1, 1]
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
    # smote = SMOTE(random_state=42)
    # X, y = smote.fit_resample(X, y)
    # log("Applied SMOTE for data balancing", {"new_sample_count": len(y)})
    
    # Split data for validation
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    
    # Hyperparameter tuning
    param_grid = {
        'xgb__n_estimators': [100, 200],
        'xgb__max_depth': [3, 5],
        'rf__n_estimators': [100, 200],
        'rf__max_depth': [10, 15]
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
    """Make predictions using the trained model."""
    ensure_directories()
    
    start_time = time.time()
    
    try:
        model = joblib.load(MODEL_FILE)
        scaler = joblib.load(SCALER_FILE)
        log("Model and scaler loaded")
        
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
        
        X_scaled = scaler.transform(X)
        probabilities = model.predict_proba(X_scaled)[:, 1]
        
        prediction_time = time.time() - start_time
        log("Prediction completed", {
            "num_samples": len(inputs),
            "prediction_time_sec": prediction_time
        })
        
        return {
            "status": "success",
            "probabilities": probabilities.tolist()
        }
    
    except FileNotFoundError:
        log("Model not trained", {"error": "Model files not found"}, "ERROR")
        return {
            "status": "error",
            "message": "Model not trained. Please train model first."
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
        # Determine the attack type (you may need to adjust this based on how generate_malicious_url works)
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

def generate_malicious_url():
    """Generate a synthetic malicious URL with attack patterns."""
    attack_types = list(ATTACK_PATTERNS.keys())
    attack_type = np.random.choice(attack_types)
    
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
        path = f"/download.php"
        query = f"?file={attack_pattern.replace(r'(\s|\+)*', '')}etc/passwd"
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
        path = "/fetch"
        query = f"?url=http://{attack_pattern.replace(r'(\s|\+)*', '')}/admin"
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