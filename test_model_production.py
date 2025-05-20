import json
import time
import numpy as np
from typing import List, Dict
from microservices.nehonix_shield_model import predict, ensure_directories, log
from sklearn.metrics import roc_auc_score, precision_recall_curve, average_precision_score

def test_model_readiness():
    """Test if the model is loaded and ready to be use."""
    print("\n=== Testing Model Readiness ===")
    
    # Test URLs representing different scenarios
    test_urls = [
        # Benign URLs
        "https://example.com/products?category=electronics",
        "https://api.github.com/users/test?page=1",
        "https://docs.python.org/3/library/index.html",
        # Potentially malicious URLs
        "https://evil.com/page?id=1' OR '1'='1",
        "https://malicious.site/upload.php?file=../../../etc/passwd",
        "https://fake-bank.com/login?redirect=//evil.com"
    ]
    
    try:
        # Ensure model directory exists
        ensure_directories()
        
        # Test batch prediction
        start_time = time.time()
        results = predict(test_urls)
        processing_time = time.time() - start_time
        
        if results["status"] != "success":
            print(f"[ERROR] Model prediction failed: {results.get('message', 'Unknown error')}")
            return False
        
        # Check prediction structure
        for result in results["detailed_results"]:
            required_fields = ["input", "probability", "classification", "confidence", "threat_types"]
            if not all(field in result for field in required_fields):
                print("[ERROR] Missing required fields in prediction results")
                return False
        
        # Performance checks
        avg_time_per_url = processing_time / len(test_urls)
        if avg_time_per_url > 1.0:  # More than 1 second per URL is too slow
            print(f"[WARNING] Performance warning: {avg_time_per_url:.3f} seconds per URL")
        else:
            print(f"[OK] Performance good: {avg_time_per_url:.3f} seconds per URL")
        
        print("[OK] Model is ready for production use")
        return True
        
    except Exception as e:
        print(f"[ERROR] Model readiness test failed: {str(e)}")
        return False

def test_model_accuracy():
    """Test model accuracy with known good and bad URLs."""
    print("\n=== Testing Model Accuracy ===")
    
    # Test dataset with known labels
    test_data = [
        # Benign URLs (label: 0)
        ("https://google.com/search?q=test", 0),
        ("https://github.com/user/repo", 0),
        ("https://stackoverflow.com/questions/12345", 0),
        ("https://amazon.com/product?id=12345", 0),
        ("https://microsoft.com/downloads", 0),
        # Malicious URLs (label: 1)
        ("https://evil.com/page?id=1' OR '1'='1", 1),  # SQL Injection
        ("https://hack.com/upload?file=../../../../etc/passwd", 1),  # Path Traversal
        ("https://malicious.com/page?input=<script>alert(1)</script>", 1),  # XSS
        ("https://attack.com/exec?cmd=cat+/etc/passwd", 1),  # Command Injection
        ("https://phish.com/bank/login.php?next=//evil.com", 1)  # Open Redirect
    ]
    
    urls = [url for url, _ in test_data]
    true_labels = [label for _, label in test_data]
    
    try:
        # Get predictions
        results = predict(urls)
        if results["status"] != "success":
            print(f"[ERROR] Accuracy test failed: {results.get('message', 'Unknown error')}")
            return
        
        # Extract probabilities and predictions
        probabilities = results["probabilities"]
        predictions = [1 if p >= 0.5 else 0 for p in probabilities]
        
        # Calculate metrics
        accuracy = sum(1 for i in range(len(predictions)) if predictions[i] == true_labels[i]) / len(predictions)
        auc = roc_auc_score(true_labels, probabilities)
        precision, recall, _ = precision_recall_curve(true_labels, probabilities)
        avg_precision = average_precision_score(true_labels, probabilities)
        
        # Print results
        print(f"\nAccuracy: {accuracy:.2%}")
        print(f"AUC-ROC: {auc:.2f}")
        print(f"Average Precision: {avg_precision:.2f}")
        
        # Analyze misclassifications
        for i, (url, true_label) in enumerate(test_data):
            if predictions[i] != true_label:
                print(f"\nMisclassified URL: {url}")
                print(f"True label: {'Malicious' if true_label == 1 else 'Benign'}")
                print(f"Predicted probability: {probabilities[i]:.3f}")
                
        # Performance thresholds
        if accuracy < 0.8:
            print("[WARNING] Model accuracy below 80%")
        if auc < 0.85:
            print("[WARNING] AUC-ROC score below 0.85")
        if avg_precision < 0.8:
            print("[WARNING] Average precision below 0.80")
            
    except Exception as e:
        print(f"[ERROR] Accuracy test failed: {str(e)}")

def test_threat_detection():
    """Test specific threat detection capabilities."""
    print("\n=== Testing Threat Detection ===")
    
    # Test cases for different attack types
    test_cases = {
        "sql_injection": [
            "https://vuln.com/page?id=1' OR '1'='1",
            "https://hack.com/products?category=1;DROP TABLE users--"
        ],
        "xss": [
            "https://site.com/search?q=<script>alert(1)</script>",
            "https://vuln.com/page?input=<img src=x onerror=alert(1)>"
        ],
        "path_traversal": [
            "https://hack.com/file?path=../../../../etc/passwd",
            "https://vuln.com/download?file=../../../windows/system32/config/sam"
        ],
        "command_injection": [
            "https://evil.com/exec?cmd=cat+/etc/passwd",
            "https://hack.com/run?command=|ls -la"
        ],
        "ssrf": [
            "https://vuln.com/proxy?url=http://169.254.169.254/",
            "https://hack.com/fetch?address=http://localhost:3306/"
        ]
    }
    
    try:
        for attack_type, urls in test_cases.items():
            print(f"\nTesting {attack_type} detection:")
            results = predict(urls)
            
            if results["status"] != "success":
                print(f"[ERROR] Test failed: {results.get('message', 'Unknown error')}")
                continue
            
            for i, result in enumerate(results["detailed_results"]):
                detected_threats = [t for t, _ in result.get("threats", [])]
                probability = result["probability"]
                
                print(f"\nURL {i+1}: {urls[i]}")
                print(f"Detected as malicious: {probability >= 0.5}")
                print(f"Confidence: {result['confidence']:.2f}")
                print(f"Detected threats: {detected_threats}")
                
                if attack_type not in detected_threats and probability < 0.5:
                    print(f"[ERROR] Failed to detect {attack_type}")
                else:
                    print("[OK] Successfully detected threat")
                    
    except Exception as e:
        print(f"[ERROR] Threat detection test failed: {str(e)}")

def main():
    """Run all tests and provide summary."""
    print("=== Starting Model Production Readiness Tests ===\n")
    
    # Test 1: Model Readiness
    model_ready = test_model_readiness()
    if not model_ready:
        print("\n[ERROR] Model is not ready for production")
        return
    
    # Test 2: Model Accuracy
    test_model_accuracy()
    
    # Test 3: Threat Detection
    test_threat_detection()
    
    print("\n=== Test Suite Completed ===")

if __name__ == "__main__":
    main()
