import json
import sys
import os
import numpy as np
import time
import hashlib
import base64
import re
import itertools
from typing import Dict, List, Any, Union, Tuple
from urllib.parse import urlparse, parse_qs
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from sklearn.inspection import permutation_importance
from xgboost import XGBClassifier
import joblib
from imblearn.over_sampling import SMOTE
from .attack_patterns import ATTACK_PATTERNS
import random
from collections import Counter



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
    parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
    
    # Basic features
    features["length"] = len(url)
    features["entropy"] = calculate_entropy(url)
    features["digit_ratio"] = len([c for c in url if c.isdigit()]) / max(len(url), 1)
    
    # Enhanced special character detection
    special_chars = len([c for c in url if not c.isalnum() and c not in ['/', '?', '=', '&', ':', '-', '.']])
    features["special_char_ratio"] = min(special_chars / max(len(url), 1), 0.3)
    
    # Path traversal features
    path = parsed.path
    features["path_depth"] = path.count('/')
    features["dot_segments"] = path.count('../') + path.count('..\\')
    features["consecutive_slashes"] = len(re.findall(r'/+', path))
    
    # SSRF features
    query_params = parse_qs(parsed.query)
    features["has_url_param"] = any(param.lower() in ['url', 'uri', 'link', 'redirect', 'redir', 'next', 'return', 'goto'] for param in query_params)
    features["has_internal_ip"] = any(re.search(r'(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)', value) for values in query_params.values() for value in values)
    features["has_cloud_metadata"] = any(re.search(r'169\.254\.169\.254|metadata\.google|169\.254\.170\.2|metadata\.aws', value) for values in query_params.values() for value in values)
    
    # Command injection features
    features["has_shell_chars"] = any(char in url for char in ['`', '$', '|', '&', ';', '(', ')', '<', '>', '{', '}'])
    features["has_encoded_commands"] = any(re.search(r'(%0A|%0D|%7C|%26|%3B|%60)', value) for values in query_params.values() for value in values)
    
    # Additional security features
    features["has_base64"] = detect_base64_params(url)
    features["has_hex_chars"] = len(re.findall(r'%[0-9A-Fa-f]{2}', url)) / max(len(url), 1)
    features["repeated_chars"] = max(len(list(g)) for _, g in itertools.groupby(url)) / max(len(url), 1)
    
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