import json
import sys
import os
from microservices.nehonix_shield_model import train_model, log

# Path to the training data
TRAINING_DATA_PATH = "microservices/training_data/url_training_data.json"

def load_training_data(file_path):
    """Load training data from JSON file."""
    if not os.path.exists(file_path):
        log("Training data file not found", {"path": file_path}, "ERROR")
        sys.exit(1)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Extract URLs and labels
    urls = [item['url'] for item in data]
    labels = [item['label'] for item in data]
    
    return urls, labels

if __name__ == "__main__":
    try:
        # Load the training data
        urls, labels = load_training_data(TRAINING_DATA_PATH)
        log("Loaded training data", {"num_samples": len(urls), "num_malicious": sum(labels)})
        
        # Train the model
        meta = train_model(urls, labels)
        print(json.dumps({"status": "success", "metadata": meta}, indent=2))
        
    except Exception as e:
        log("Training failed", {"error": str(e)}, "ERROR")
        print(json.dumps({"status": "error", "message": str(e)}, indent=2))
        sys.exit(1)