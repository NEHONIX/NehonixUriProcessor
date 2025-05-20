import re
import time
from typing import Dict, List, Tuple
from microservices.attack_patterns import ATTACK_PATTERNS as ATTACK_PATTERNS_ENHANCED

# Mock model for demonstration (replace with your actual model)
class ThreatModel:
    def __init__(self, patterns: Dict[str, List[str]]):
        self.patterns = patterns

    def extract_features(self, url: str) -> Dict[str, float]:
        # Simplified feature extraction (replace with your actual logic)
        features = {
            "char_diversity_ratio": len(set(url)) / len(url) if url else 0.0,
            "url_length_ratio": len(url) / 100.0,
            "special_char_ratio": sum(1 for c in url if c in "%&;=/?#") / len(url) if url else 0.0,
            "entropy": 1.0,  # Placeholder
            "query_length": len(url.split("?")[1]) if "?" in url else 0.0
        }
        return features

    def detect_threats(self, url: str) -> List[Tuple[str, float]]:
        threats = []
        for threat_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    # Assign weights based on threat type (adjust as needed)
                    weight = 5.0 if threat_type == "ssrf" else 1.0
                    threats.append((threat_type, weight))
                    break
        return threats

    def predict(self, url: str) -> Dict:
        features = self.extract_features(url)
        threats = self.detect_threats(url)
        
        # Simplified scoring (replace with your model's logic)
        probability = sum(weight for _, weight in threats) / 10.0
        probability = min(max(probability, 0.0), 1.0)
        confidence = 1.0 - probability if probability < 0.5 else probability
        classification = "malicious" if probability >= 0.7 else "benign"
        
        return {
            "url": url,
            "classification": classification,
            "probability": probability,
            "confidence": confidence,
            "threats": threats,
            "features": features
        }

# Test URLs
test_urls = [
    # Benign URLs
    "https://stackoverflow.com/terms?lang=en",
    "https://spotify.com/help?lang=en",
    "https://microsoft.com/?lang=en",
    "https://example.com/support?filter=recent",
    "http://zoom.us/faq?page=1",
    "https://amazon.com/product?id=123",
    "https://gov.uk/services",
    "https://github.com/explore?sort=stars",
    "https://news.bbc.co.uk/?category=world",
    "https://cdn.example.com/resource.js?token=abc123",
    # Malicious URLs
    "http://secure.customer-support.ru/get?url=h%74t%70://1%369.254.169.254/lat%65%73t/m%65%74a-data/",
    "http://banking-online.com/api/data?data=BeanUtils\.(?:populate|copyProperties)|PropertyUtils",
    "http://account.banking-online.ru/index.php?id=<\s*form\s+[^>]*?method\s*=\s*['\"]?POST['\"]?[^>]*?>",
    "http://update.customer-support.pw/search?q=<[\s\S]*?div[^>]*?\s+style\s*=\s*(['\"]|...",
    "http://login.login-secure.com/proxy?u%72l=goph%65%72://1%327.0.0.%31:22/_test#exec",
    "http://malicious.com/query?user=admin' OR 1=1--",
    "http://fake.com/upload?file=script.php%00",
    "http://attack.com/ldap?filter=uid=*)(|(uid=*))",
    "http://evil.com/data?q=%0D%0ASet-Cookie:session=malicious",
    "http://test.local/query?filter[$where]=function(){return true;}"
]

# Run tests
model = ThreatModel(ATTACK_PATTERNS_ENHANCED)
results = []
start_time = time.time()

for url in test_urls:
    result = model.predict(url)
    results.append(result)

elapsed_time = time.time() - start_time

# Log results
print(f"Test completed in {elapsed_time:.2f} seconds")
print("\nResults:")
for result in results:
    print(f"\nURL: {result['url']}")
    print(f"Classification: {result['classification']}")
    print(f"Probability: {result['probability']:.4f}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Threats: {result['threats']}")
    print(f"Top Features: {sorted(result['features'].items(), key=lambda x: x[1], reverse=True)[:3]}")

# Summary metrics
benign_urls = test_urls[:10]
malicious_urls = test_urls[10:]
fp = sum(1 for r in results[:10] if r['classification'] == 'malicious')
fn = sum(1 for r in results[10:] if r['classification'] == 'benign')
fpr = fp / len(benign_urls) * 100
tpr = (len(malicious_urls) - fn) / len(malicious_urls) * 100

print(f"\nSummary:")
print(f"False Positive Rate: {fpr:.2f}%")
print(f"True Positive Rate: {tpr:.2f}%")
print(f"Total URLs Tested: {len(test_urls)}")
print(f"Average Processing Time per URL: {elapsed_time / len(test_urls):.4f} seconds")