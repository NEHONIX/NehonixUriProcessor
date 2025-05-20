import json
import numpy as np
from microservices.nehonix_shield_model import generate_training_data, enhance_training, train_model, ensure_directories, log

# Set random seed for reproducibility
np.random.seed(42)

# Parameters for data generation
NUM_SAMPLES = 10000  # Large dataset to cover all attack types
MALICIOUS_RATIO = 0.5  # Balanced dataset

def main():
    ensure_directories()
    
    try:
        # Step 1: Generate synthetic training data
        log("Starting synthetic data generation")
        urls, labels = generate_training_data(
            num_samples=NUM_SAMPLES,
            malicious_ratio=MALICIOUS_RATIO
        )
        
        # Step 2: Enhance training data with augmentation
        log("Enhancing training data with augmentation")
        enhanced_urls, enhanced_labels = enhance_training(urls, labels)
        
        # Step 3: Train the model
        log("Starting model training")
        meta = train_model(enhanced_urls, enhanced_labels)
        
        # Step 4: Save results
        result = {
            "status": "success",
            "metadata": meta,
            "num_samples": len(enhanced_urls),
            "num_malicious": sum(enhanced_labels),
            "num_benign": len(enhanced_urls) - sum(enhanced_labels)
        }
        
        # Save metadata to a file
        with open("training_result.json", "w") as f:
            json.dump(result, f, indent=2)
        
        log("Training completed successfully", {"result": result})
        print(json.dumps(result))
        
    except Exception as e:
        log(f"Training pipeline failed: {str(e)}", level="ERROR")
        print(json.dumps({"status": "error", "message": str(e)}))
        raise

if __name__ == "__main__":
    main()