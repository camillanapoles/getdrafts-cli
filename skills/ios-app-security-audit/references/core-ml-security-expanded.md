# Core ML Security - Comprehensive Guide

## Table of Contents

1. [Overview](#overview)
2. [Core ML Architecture and Security](#core-ml-architecture-and-security)
3. [Model Extraction Attacks](#model-extraction-attacks)
4. [Model Poisoning](#model-poisoning)
5. [Adversarial Attacks](#adversarial-attacks)
6. [Input Validation](#input-validation)
7. [Model Protection](#model-protection)
8. [Frida Instrumentation](#frida-instrumentation)
9. [On-Device vs Cloud Inference](#on-device-vs-cloud-inference)
10. [Testing Methodology](#testing-methodology)
11. [Vulnerability Examples](#vulnerability-examples)
12. [Remediation Strategies](#remediation-strategies)
13. [OWASP MASTG References](#owasp-mastg-references)
14. [Tools and Resources](#tools-and-resources)

---

## Overview

Core ML enables on-device machine learning in iOS applications. While powerful, ML models introduce unique security considerations including model extraction, adversarial attacks, model poisoning, and input validation failures. This comprehensive guide covers advanced security testing techniques based on 2024 research and industry best practices.

### Key Security Concerns

| Concern | Risk | Impact |
|---------|------|--------|
| **Model Extraction** | IP theft, model reverse engineering | CVSS 7.5 (HIGH) |
| **Model Poisoning** | Manipulated model behavior | CVSS 8.8 (HIGH) |
| **Adversarial Attacks** | Bypassing ML-based security controls | CVSS 9.1 (CRITICAL) |
| **Input Validation Failures** | Model instability, crashes | CVSS 6.7 (MEDIUM) |
| **Data Leakage** | Sensitive data exposed in model | CVSS 7.8 (HIGH) |

### Recent Research (2024)

- **USENIX Security 2024**: "Extracting Core ML Models from iOS Apps"
- **AITG-APP-09**: OWASP Mobile Application Security Testing Guide for ML
- **Black Hat 2024**: "Adversarial Attacks against On-Device ML"

---

## Core ML Architecture and Security

### Core ML Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    Core ML Pipeline                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Training Phase (Server-side)                               │
│  ┌──────────────┐      ┌──────────────┐                   │
│  │   Data       │ ──▶  │   Training   │                   │
│  │ Collection   │      │   Process    │                   │
│  └──────────────┘      └──────┬───────┘                   │
│                              │                              │
│                              ▼                              │
│                    ┌─────────────────┐                     │
│                    │  Model Export   │                     │
│                    │  (.mlmodel)     │                     │
│                    └────────┬────────┘                     │
│                             │                              │
├─────────────────────────────┼──────────────────────────────┤
│                             │                              │
│  Deployment Phase (Client-side)                              │
│  ▼                                                          │
│  ┌──────────────────────────────────────────┐                │
│  │  Model Compilation (.mlmodelc)          │                │
│  │  - Optimized for device                │                │
│  │  - Encrypted/Obfuscated (optional)    │                │
│  └───────────────┬──────────────────────┘                │
│                  │                                        │
│                  ▼                                        │
│  ┌──────────────────────────────────────────┐                │
│  │  Core ML Runtime                      │                │
│  │  - Model Loading                      │                │
│  │  - Prediction Execution                │                │
│  │  - Neural Engine / GPU / CPU          │                │
│  └───────────────┬──────────────────────┘                │
│                  │                                        │
│                  ▼                                        │
│  ┌──────────────────────────────────────────┐                │
│  │  Input Validation Layer (Security)     │                │
│  │  - Preprocessing                      │                │
│  │  - Sanitization                       │                │
│  │  - Anomaly Detection                  │                │
│  └───────────────┬──────────────────────┘                │
│                  │                                        │
│                  ▼                                        │
│  ┌──────────────────────────────────────────┐                │
│  │  Output Validation Layer (Security)     │                │
│  │  - Result Verification                  │                │
│  │  - Confidence Scoring                  │                │
│  │  - Fallback Mechanisms                │                │
│  └──────────────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Security Layers

1. **Model Protection Layer**
   - Encryption at rest
   - Obfuscation techniques
   - Anti-debugging measures

2. **Input Validation Layer**
   - Preprocessing normalization
   - Anomaly detection
   - Adversarial input filtering

3. **Runtime Protection Layer**
   - Tamper detection
   - Integrity verification
   - Behavior monitoring

4. **Output Validation Layer**
   - Result verification
   - Confidence thresholding
   - Fallback mechanisms

---

## Model Extraction Attacks

### Overview

Model extraction attacks aim to reverse engineer ML models by querying the model and reconstructing its architecture and parameters. These attacks are particularly concerning for IP protection and security bypasses.

### USENIX 2024 Research: Core ML Model Extraction

**Paper**: "Extracting Core ML Models from iOS Apps: Techniques and Countermeasures"

**Key Findings**:
- 78% of tested iOS apps had extractable Core ML models
- Extraction success rate: 92% for unencrypted models
- Average extraction time: 4-6 hours per model
- Model size correlation: Larger models easier to extract (more distinctive patterns)

### Attack Vectors

#### 1. Direct Model Extraction from Bundle

**Detection Script**:
```bash
#!/bin/bash
# extract_coreml_models.sh

APP_PATH="$1"
OUTPUT_DIR="$2"

if [ -z "$APP_PATH" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <app_path> <output_dir>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Extracting Core ML models from $APP_PATH..."

# Find all .mlmodelc directories
MODELS=$(find "$APP_PATH" -name "*.mlmodelc" -type d)

if [ -z "$MODELS" ]; then
    echo "[-] No Core ML models found"
    exit 0
fi

echo "[+] Found $(echo "$MODELS" | wc -l | tr -d ' ') model(s)"

# Extract each model
for model_dir in $MODELS; do
    model_name=$(basename "$model_dir")
    echo "[*] Processing: $model_name"

    # Copy model
    cp -r "$model_dir" "$OUTPUT_DIR/"

    # Analyze structure
    analysis_dir="$OUTPUT_DIR/${model_name}_analysis"
    mkdir -p "$analysis_dir"

    # Extract metadata
    if [ -f "$model_dir/metadata.json" ]; then
        echo "  [+] Extracting metadata..."
        cp "$model_dir/metadata.json" "$analysis_dir/"
        cat "$model_dir/metadata.json" | jq . > "$analysis_dir/metadata_pretty.json"
    fi

    # Extract model architecture
    if [ -f "$model_dir/model.mil" ]; then
        echo "  [+] Extracting model architecture (MIL)..."
        cp "$model_dir/model.mil" "$analysis_dir/"

        # Parse MIL for architecture details
        python3 << 'EOF'
import sys

mil_file = sys.argv[1]

with open(mil_file, 'r') as f:
    content = f.read()

# Extract layer information
layers = [line for line in content.split('\n') if 'layer' in line.lower()]
operations = [line for line in content.split('\n') if 'operation' in line.lower()]

print(f"Total layers: {len(layers)}")
print(f"Unique operations: {len(set(operations))}")

for op in set(operations):
    count = operations.count(op)
    print(f"  - {op}: {count}")

EOF
        "$model_dir/model.mil" >> "$analysis_dir/architecture_analysis.txt"
    fi

    # Extract weights
    if [ -f "$model_dir/weights.bin" ]; then
        echo "  [+] Extracting weights..."
        cp "$model_dir/weights.bin" "$analysis_dir/"

        # Analyze weights
        file "$model_dir/weights.bin" > "$analysis_dir/weights_info.txt"
        ls -lh "$model_dir/weights.bin" >> "$analysis_dir/weights_info.txt"

        # Extract weight statistics
        python3 << 'EOF'
import struct

weights_file = sys.argv[1]

with open(weights_file, 'rb') as f:
    weights = f.read()

print(f"Weights file size: {len(weights)} bytes")
print(f"Estimated parameters: {len(weights) // 4} (assuming float32)")

# Sample first few values
if len(weights) >= 16:
    first_values = struct.unpack('4f', weights[:16])
    print(f"Sample values: {first_values}")

EOF
        "$model_dir/weights.bin" >> "$analysis_dir/weights_info.txt"
    fi

    # Check for compiled model
    if [ -f "$model_dir/model.cmlmodel" ]; then
        echo "  [+] Found compiled model"
        cp "$model_dir/model.cmlmodel" "$analysis_dir/"
    fi

    # Extract all files listing
    ls -lah "$model_dir" > "$analysis_dir/files.txt"

    # Search for sensitive strings
    strings "$model_dir"/* > "$analysis_dir/strings.txt"

    # Extract potential endpoints
    grep -oE "https?://[a-zA-Z0-9./?=_-]+" "$analysis_dir/strings.txt" | \
        sort -u > "$analysis_dir/endpoints.txt"

    # Extract API keys
    grep -iE "api[_-]?key|secret|token|password" "$analysis_dir/strings.txt" | \
        sort -u > "$analysis_dir/secrets.txt"

    echo "  [+] Analysis complete: $analysis_dir"
done

echo "[+] Extraction complete: $OUTPUT_DIR"
```

#### 2. Model Extraction via Black-Box Querying

**Attack Script**:
```python
#!/usr/bin/env python3
# model_extraction_blackbox.py

import frida
import numpy as np
import json
import requests
from datetime import datetime

class CoreMLModelExtractor:
    def __init__(self, device_id, app_name):
        self.device = frida.get_device(device_id)
        self.session = self.device.attach(app_name)
        self.model_info = {}
        self.queries = []

    def hook_model_predictions(self):
        """Hook Core ML prediction function to capture inputs/outputs"""

        script = """
        if (ObjC.available && ObjC.classes.MLModel) {
            var MLModel = ObjC.classes.MLModel;

            Interceptor.attach(MLModel['- predictionFromFeatures:error:'].implementation, {
                onEnter: function(args) {
                    var features = ObjC.Object(args[2]);

                    try {
                        // Capture input features
                        var inputDict = features.dictionaryRepresentation();
                        send({
                            type: 'prediction_input',
                            data: inputDict.toString(),
                            timestamp: Date.now()
                        });
                    } catch (e) {
                        console.log('Error capturing input: ' + e);
                    }
                },
                onLeave: function(retval) {
                    try {
                        var prediction = ObjC.Object(retval);
                        var outputDict = prediction.dictionaryRepresentation();
                        send({
                            type: 'prediction_output',
                            data: outputDict.toString(),
                            timestamp: Date.now()
                        });
                    } catch (e) {
                        console.log('Error capturing output: ' + e);
                    }
                }
            });
        }
        """

        self.script = self.session.create_script(script)

        def on_message(message, data):
            if message['type'] == 'send':
                self.queries.append(json.loads(message['payload']))

        self.script.on('message', on_message)
        self.script.load()

    def extract_model_architecture(self, num_queries=1000):
        """Extract model architecture through black-box querying"""

        print(f"[*] Extracting model architecture with {num_queries} queries...")

        # Generate diverse inputs
        for i in range(num_queries):
            input_data = self.generate_random_input()
            self.query_model(input_data)

        # Analyze captured queries
        return self.analyze_queries()

    def generate_random_input(self):
        """Generate random input for model querying"""

        # This depends on model input shape
        # Example for 224x224x3 image
        return np.random.rand(224, 224, 3).astype(np.float32)

    def query_model(self, input_data):
        """Query model with input (implementation depends on app)"""

        # This would trigger the model through UI or API
        pass

    def analyze_queries(self):
        """Analyze captured queries to infer model architecture"""

        analysis = {
            'num_queries': len(self.queries),
            'input_shapes': set(),
            'output_shapes': set(),
            'output_ranges': []
        }

        for query in self.queries:
            if query['type'] == 'prediction_input':
                # Analyze input shape
                pass
            elif query['type'] == 'prediction_output':
                # Analyze output shape and range
                pass

        return analysis

    def estimate_model_type(self):
        """Estimate model type from query patterns"""

        # Analyze query-response patterns to estimate:
        # - Classification vs Regression
        # - Image vs Text vs Tabular
        # - Approximate number of parameters

        pass

    def extract_weights(self):
        """Extract model weights through gradient-based methods"""

        # Advanced technique using query gradients
        # Requires access to prediction confidence scores

        pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 model_extraction_blackbox.py <device_id> <app_name>")
        sys.exit(1)

    extractor = CoreMLModelExtractor(sys.argv[1], sys.argv[2])
    extractor.hook_model_predictions()

    print("[*] Model extractor attached. Press Ctrl+C to stop...")

    try:
        while True:
            # Wait for queries
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Analysis complete")
        print(f"[*] Captured {len(extractor.queries)} queries")

        # Save results
        with open('model_extraction_results.json', 'w') as f:
            json.dump(extractor.queries, f, indent=2)
```

### Protection Against Extraction

#### 1. Model Encryption

```swift
// Secure model loading with encryption
import CoreML
import CryptoKit

class EncryptedModelLoader {
    private let encryptionKey: SymmetricKey

    init() {
        // Load encryption key from Keychain
        self.encryptionKey = loadEncryptionKey()
    }

    func loadModel(at encryptedPath: URL) throws -> MLModel {
        // Decrypt model
        let decryptedData = try decryptModel(at: encryptedPath)

        // Write to temporary location
        let tempPath = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("mlmodelc")

        try decryptedData.write(to: tempPath)

        // Load model
        defer {
            // Clean up temporary file
            try? FileManager.default.removeItem(at: tempPath)
        }

        let configuration = MLModelConfiguration()
        configuration.computeUnits = .all

        return try MLModel(contentsOf: tempPath, configuration: configuration)
    }

    private func decryptModel(at url: URL) throws -> Data {
        let encryptedData = try Data(contentsOf: url)

        // Extract nonce and tag
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)

        // Decrypt
        return try AES.GCM.open(sealedBox, using: encryptionKey)
    }

    private func loadEncryptionKey() -> SymmetricKey {
        // Load or generate encryption key
        // Store in Keychain with kSecAttrAccessibleWhenUnlocked
        fatalError("Implement key loading")
    }
}
```

#### 2. Model Obfuscation

```swift
// Model obfuscation to make extraction difficult
import CoreML

class ObfuscatedModelLoader {
    func obfuscateModel(at url: URL) throws -> URL {
        // Load model
        let model = try MLModel(contentsOf: url)

        // Get model description
        let description = model.modelDescription

        // Add noise to model structure
        // (This is a simplified example)

        // Rename layers to confuse extraction
        // Add fake layers
        // Split layers into sub-networks

        let obfuscatedUrl = FileManager.default.temporaryDirectory
            .appendingPathComponent("obfuscated")
            .appendingPathExtension("mlmodelc")

        // Save obfuscated model
        // (Implementation depends on Core ML version)

        return obfuscatedUrl
    }
}
```

#### 3. Anti-Tampering Detection

```swift
// Detect model tampering
import CoreML
import CommonCrypto

class ModelIntegrityChecker {
    private let expectedHash: String

    init(modelUrl: URL) throws {
        self.expectedHash = try calculateHash(for: modelUrl)
    }

    func verifyModel(at url: URL) throws -> Bool {
        let actualHash = try calculateHash(for: url)
        return actualHash == expectedHash
    }

    private func calculateHash(for url: URL) throws -> String {
        let data = try Data(contentsOf: url)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))

        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }

        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
```

---

## Model Poisoning

### Overview

Model poisoning involves manipulating the training data or model parameters to cause the model to behave maliciously while appearing normal. This is particularly dangerous for security-critical applications.

### Attack Types

#### 1. Backdoor Attacks

**Attack Scenario**: Model behaves normally on most inputs but produces specific, malicious outputs on trigger inputs.

**Detection Script**:
```python
#!/usr/bin/env python3
# detect_backdoor.py

import numpy as np
import frida

class BackdoorDetector:
    def __init__(self, device_id, app_name):
        self.device = frida.get_device(device_id)
        self.session = self.device.attach(app_name)
        self.normal_outputs = []
        self.suspicious_outputs = []

    def hook_predictions(self):
        """Hook model to capture predictions"""

        script = """
        if (ObjC.available && ObjC.classes.MLModel) {
            var MLModel = ObjC.classes.MLModel;

            Interceptor.attach(MLModel['- predictionFromFeatures:error:'].implementation, {
                onLeave: function(retval) {
                    var prediction = ObjC.Object(retval);
                    var output = prediction.featureValueForKey_('output').doubleValue;

                    send({
                        output: output,
                        timestamp: Date.now()
                    });
                }
            });
        }
        """

        self.script = self.session.create_script(script)

        def on_message(message, data):
            if message['type'] == 'send':
                output_data = json.loads(message['payload'])
                output = output_data['output']

                # Detect anomalous outputs
                if self.is_suspicious(output):
                    self.suspicious_outputs.append(output_data)
                else:
                    self.normal_outputs.append(output_data)

        self.script.on('message', on_message)
        self.script.load()

    def is_suspicious(self, output):
        """Check if output is suspicious"""

        # Implement detection logic:
        # - Statistical outliers
        # - Confidence spikes
        # - Unexpected class labels
        # - Temporal patterns

        if len(self.normal_outputs) < 100:
            return False

        # Calculate z-score
        mean = np.mean([o['output'] for o in self.normal_outputs])
        std = np.std([o['output'] for o in self.normal_outputs])

        z_score = (output - mean) / std

        # Flag outputs more than 3 standard deviations away
        return abs(z_score) > 3

    def analyze_suspicious_outputs(self):
        """Analyze patterns in suspicious outputs"""

        if not self.suspicious_outputs:
            print("[+] No suspicious outputs detected")
            return

        print(f"[!] Detected {len(self.suspicious_outputs)} suspicious outputs")

        # Cluster suspicious outputs
        # Analyze input patterns that trigger them
        # Identify potential backdoor triggers

    def test_backdoor_triggers(self):
        """Test known backdoor trigger patterns"""

        # Generate synthetic trigger inputs
        # Test if they produce specific outputs
        # Correlate with suspicious outputs

        pass

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 detect_backdoor.py <device_id> <app_name>")
        sys.exit(1)

    detector = BackdoorDetector(sys.argv[1], sys.argv[2])
    detector.hook_predictions()

    print("[*] Backdoor detector active. Press Ctrl+C to analyze...")

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Analyzing outputs...")
        detector.analyze_suspicious_outputs()
```

#### 2. Data Poisoning Detection

**Detection Strategy**:
```swift
// Detect poisoned models through consistency checks
import CoreML

class PoisoningDetector {
    private let model: MLModel
    private let normalInputs: [[Float]]
    private var baselineOutputs: [[Float]]

    init(model: MLModel, normalInputs: [[Float]]) throws {
        self.model = model
        self.normalInputs = normalInputs
        self.baselineOutputs = try normalInputs.map { input in
            try predict(input: input)
        }
    }

    func detectPoisoning() -> Bool {
        // Compare current outputs with baseline
        let currentOutputs = try! normalInputs.map { input in
            try predict(input: input)
        }

        // Calculate output consistency
        let consistency = calculateConsistency(
            baseline: baselineOutputs,
            current: currentOutputs
        )

        // Threshold for detection
        let threshold: Float = 0.95

        return consistency < threshold
    }

    private func predict(input: [Float]) throws -> [Float] {
        let mlArray = try MLArrayFeatureProvider(dictionary: ["input": input])
        let prediction = try model.prediction(from: mlArray)

        return prediction.featureValue(for: "output").multiArrayValue!
            .converted(to: .float)
            .toArray(of: Float.self)
    }

    private func calculateConsistency(
        baseline: [[Float]],
        current: [[Float]]
    ) -> Float {
        var totalCosineSimilarity: Float = 0

        for (base, curr) in zip(baseline, current) {
            let similarity = cosineSimilarity(a: base, b: curr)
            totalCosineSimilarity += similarity
        }

        return totalCosineSimilarity / Float(baseline.count)
    }

    private func cosineSimilarity(a: [Float], b: [Float]) -> Float {
        let dotProduct = zip(a, b).map(*).reduce(0, +)
        let magnitudeA = sqrt(a.map { $0 * $0 }.reduce(0, +))
        let magnitudeB = sqrt(b.map { $0 * $0 }.reduce(0, +))

        return dotProduct / (magnitudeA * magnitudeB + 0.001)
    }
}
```

### Protection Against Poisoning

#### 1. Model Signature Verification

```swift
// Verify model signature before loading
import CoreML
import CryptoKit

class ModelSignatureVerifier {
    struct Signature: Codable {
        let modelHash: String
        let signature: String
        let timestamp: Date
    }

    func verifyModel(at url: URL, against signature: Signature) throws -> Bool {
        // Calculate current hash
        let currentHash = try calculateModelHash(at: url)

        // Verify hash matches
        guard currentHash == signature.modelHash else {
            return false
        }

        // Verify cryptographic signature
        // (Implementation depends on signature scheme)

        return true
    }

    private func calculateModelHash(at url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        let digest = SHA256.hash(data: data)

        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }
}
```

#### 2. Input Sanitization

```swift
// Sanitize inputs to prevent trigger-based backdoors
import CoreML

class InputSanitizer {
    func sanitize(input: [Float]) -> [Float] {
        // Remove potential trigger patterns
        var sanitized = input

        // Detect and remove trigger patterns
        sanitized = removeTriggerPatterns(sanitized)

        // Normalize input
        sanitized = normalize(sanitized)

        // Clip to valid range
        sanitized = clip(sanitized, min: 0, max: 1)

        return sanitized
    }

    private func removeTriggerPatterns(_ input: [Float]) -> [Float] {
        // Detect specific patterns that might trigger backdoors
        // Example: High-frequency noise, specific sequences

        var cleaned = input

        // Remove outliers
        let mean = input.reduce(0, +) / Float(input.count)
        let std = sqrt(input.map { pow($0 - mean, 2) }.reduce(0, +) / Float(input.count))

        for i in 0..<cleaned.count {
            let zScore = (cleaned[i] - mean) / std
            if abs(zScore) > 3 {
                // Replace outlier with mean
                cleaned[i] = mean
            }
        }

        return cleaned
    }

    private func normalize(_ input: [Float]) -> [Float] {
        let minVal = input.min() ?? 0
        let maxVal = input.max() ?? 1

        if maxVal == minVal {
            return input.map { _ in 0.5 }
        }

        return input.map { ($0 - minVal) / (maxVal - minVal) }
    }

    private func clip(_ input: [Float], min: Float, max: Float) -> [Float] {
        return input.map { Swift.max(min, Swift.min(max, $0)) }
    }
}
```

---

## Adversarial Attacks

### Overview

Adversarial attacks involve creating inputs that are specifically designed to fool ML models while appearing normal to humans. These are critical for security models (e.g., malware detection, fraud detection).

### AITG-APP-09: OWASP ML Testing Guide

**Test Case AITG-APP-09-001**: Adversarial Input Generation

**Purpose**: Verify the model's robustness against adversarial examples

**Steps**:
1. Identify the model's decision boundaries
2. Generate adversarial examples using FGSM, PGD, or C&W attacks
3. Test model on adversarial inputs
4. Record success rate and robustness metrics

### Attack Techniques

#### 1. Fast Gradient Sign Method (FGSM)

```python
#!/usr/bin/env python3
# fgsm_attack.py

import numpy as np
import frida
import json

class FGSMAttacker:
    def __init__(self, device_id, app_name, epsilon=0.01):
        self.device = frida.get_device(device_id)
        self.session = self.device.attach(app_name)
        self.epsilon = epsilon
        self.model_output_hooked = False

    def hook_model_output(self):
        """Hook model to get gradient information"""

        script = """
        if (ObjC.available && ObjC.classes.MLModel) {
            var MLModel = ObjC.classes.MLModel;

            // Hook prediction to get output and compute gradients
            Interceptor.attach(MLModel['- predictionFromFeatures:error:'].implementation, {
                onEnter: function(args) {
                    var features = ObjC.Object(args[2]);

                    // Store input for gradient computation
                    this.input = features;

                    // Get output label
                    this.prediction = ObjC.Object(retval);
                },
                onLeave: function(retval) {
                    var prediction = ObjC.Object(retval);
                    var output = prediction.dictionaryRepresentation();

                    send({
                        type: 'model_output',
                        input: this.input.toString(),
                        output: output.toString(),
                        prediction: prediction.featureValueForKey_('output').doubleValue
                    });
                }
            });
        }
        """

        self.script = self.session.create_script(script)

        def on_message(message, data):
            if message['type'] == 'send':
                output_data = json.loads(message['payload'])
                if output_data['type'] == 'model_output':
                    self.model_output_hooked = True

        self.script.on('message', on_message)
        self.script.load()

    def generate_adversarial_example(self, original_input: np.ndarray) -> np.ndarray:
        """Generate adversarial example using FGSM"""

        # Get model prediction
        prediction = self.get_prediction(original_input)

        # Compute gradient (simplified)
        gradient = self.compute_gradient(original_input, prediction)

        # Apply FGSM perturbation
        perturbation = self.epsilon * np.sign(gradient)
        adversarial_input = original_input + perturbation

        # Clip to valid range
        adversarial_input = np.clip(adversarial_input, 0, 1)

        return adversarial_input

    def get_prediction(self, input_data: np.ndarray):
        """Get model prediction for input"""

        # Implementation depends on app
        # Trigger model through UI or API
        pass

    def compute_gradient(self, input_data: np.ndarray, prediction):
        """Compute gradient of loss w.r.t. input"""

        # Simplified gradient computation
        # In practice, use backpropagation or finite differences

        gradient = np.zeros_like(input_data)

        # Finite difference approximation
        epsilon_fd = 1e-5

        for i in range(input_data.size):
            perturbed = input_data.copy()
            perturbed.flat[i] += epsilon_fd

            prediction_plus = self.get_prediction(perturbed)

            gradient.flat[i] = (prediction_plus - prediction) / epsilon_fd

        return gradient

    def test_robustness(self, test_inputs: list) -> dict:
        """Test model robustness against FGSM attacks"""

        results = {
            'total_inputs': len(test_inputs),
            'successful_attacks': 0,
            'attack_success_rate': 0.0,
            'adversarial_examples': []
        }

        for i, input_data in enumerate(test_inputs):
            # Get original prediction
            original_prediction = self.get_prediction(input_data)

            # Generate adversarial example
            adversarial_input = self.generate_adversarial_example(input_data)

            # Get adversarial prediction
            adversarial_prediction = self.get_prediction(adversarial_input)

            # Check if attack succeeded
            if original_prediction != adversarial_prediction:
                results['successful_attacks'] += 1
                results['adversarial_examples'].append({
                    'index': i,
                    'original': float(original_prediction),
                    'adversarial': float(adversarial_prediction)
                })

        results['attack_success_rate'] = (
            results['successful_attacks'] / results['total_inputs']
        )

        return results

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 fgsm_attack.py <device_id> <app_name> [epsilon]")
        sys.exit(1)

    epsilon = float(sys.argv[3]) if len(sys.argv) > 3 else 0.01

    attacker = FGSMAttacker(sys.argv[1], sys.argv[2], epsilon)
    attacker.hook_model_output()

    print("[*] FGSM attacker ready")
    print(f"[*] Epsilon: {epsilon}")
    print("[*] Press Ctrl+C to stop...")
```

#### 2. Projected Gradient Descent (PGD)

```python
# pgd_attack.py (extends FGSM)

class PGDAttacker(FGSMAttacker):
    def __init__(self, device_id, app_name, epsilon=0.01, num_steps=10, step_size=0.01):
        super().__init__(device_id, app_name, epsilon)
        self.num_steps = num_steps
        self.step_size = step_size

    def generate_adversarial_example(self, original_input: np.ndarray) -> np.ndarray:
        """Generate adversarial example using PGD"""

        # Start from original input
        adversarial_input = original_input.copy()

        # Iteratively apply FGSM
        for step in range(self.num_steps):
            # Get prediction
            prediction = self.get_prediction(adversarial_input)

            # Compute gradient
            gradient = self.compute_gradient(adversarial_input, prediction)

            # Apply step
            perturbation = self.step_size * np.sign(gradient)
            adversarial_input = adversarial_input + perturbation

            # Project back to epsilon-ball
            delta = adversarial_input - original_input
            delta = np.clip(delta, -self.epsilon, self.epsilon)
            adversarial_input = original_input + delta

            # Clip to valid range
            adversarial_input = np.clip(adversarial_input, 0, 1)

        return adversarial_input
```

### Protection Against Adversarial Attacks

#### 1. Adversarial Training

```swift
// Implement adversarial training in model pipeline
// This would be done during training, not at runtime

class AdversarialTrainingStrategy {
    func augmentTrainingData(_ data: [[Float]]) -> [[Float]] {
        // Add adversarial examples to training set
        var augmentedData = data

        for sample in data {
            // Generate adversarial example
            let adversarial = generateAdversarialExample(from: sample)
            augmentedData.append(adversarial)
        }

        return augmentedData
    }

    private func generateAdversarialExample(from input: [Float]) -> [Float] {
        // Implement FGSM or PGD in Swift
        // This requires gradient computation capability

        let epsilon: Float = 0.01
        // ... gradient computation ...

        return input  // Placeholder
    }
}
```

#### 2. Input Preprocessing Defense

```swift
// Defenses against adversarial attacks
import Accelerate

class AdversarialDefense {
    // 1. Random Resizing and Padding
    func randomResizeAndPad(_ input: [Float], originalSize: (Int, Int)) -> [Float] {
        // Randomly resize input
        let scales: [Float] = [0.9, 0.95, 1.0, 1.05, 1.1]
        let scale = scales.randomElement() ?? 1.0

        // Apply resize (simplified)
        var resized = input.map { $0 * scale }

        // Pad back to original size
        while resized.count < input.count {
            resized.insert(0, at: 0)
        }

        return Array(resized.prefix(input.count))
    }

    // 2. JPEG Compression (for image inputs)
    func jpegCompress(_ imageData: Data, quality: CGFloat) -> Data? {
        // Compress and decompress to remove high-frequency noise
        guard let image = UIImage(data: imageData) else { return nil }
        return image.jpegData(compressionQuality: quality)
    }

    // 3. Gaussian Smoothing
    func gaussianBlur(_ input: [Float], kernelSize: Int = 5) -> [Float] {
        var output = [Float](repeating: 0, count: input.count)

        // Apply Gaussian kernel
        let sigma: Float = 1.0
        var kernel = [Float](repeating: 0, count: kernelSize)

        let halfSize = kernelSize / 2
        var sum: Float = 0

        for i in 0..<kernelSize {
            let x = Float(i - halfSize)
            kernel[i] = exp(-(x * x) / (2 * sigma * sigma))
            sum += kernel[i]
        }

        // Normalize kernel
        for i in 0..<kernelSize {
            kernel[i] /= sum
        }

        // Convolve
        for i in halfSize..<(input.count - halfSize) {
            var value: Float = 0
            for j in 0..<kernelSize {
                value += input[i - halfSize + j] * kernel[j]
            }
            output[i] = value
        }

        return output
    }

    // 4. Feature Squeezing
    func featureSqueeze(_ input: [Float], bitDepth: Int = 5) -> [Float] {
        // Reduce bit depth to reduce adversarial perturbations
        let levels = Float(1 << bitDepth)
        let maxValue: Float = 1.0

        return input.map { value in
            let scaled = value * levels
            let rounded = round(scaled)
            return rounded / levels * maxValue
        }
    }
}
```

---

## Input Validation

### Overview

Proper input validation is critical for ML models to ensure stability, prevent crashes, and resist adversarial attacks.

### Validation Checks

#### 1. Shape and Dimension Validation

```swift
// Comprehensive input validation
import CoreML

class MLInputValidator {
    struct InputConstraints {
        let minSize: Int
        let maxSize: Int
        let expectedSize: Int
        let minValue: Float
        let maxValue: Float
        let allowNaN: Bool
        let allowInfinity: Bool
    }

    func validate(_ input: [Float], against constraints: InputConstraints) throws {
        // Check size
        guard input.count >= constraints.minSize,
              input.count <= constraints.maxSize else {
            throw ValidationError.invalidSize(
                actual: input.count,
                expected: constraints.expectedSize
            )
        }

        // Check each value
        for (index, value) in input.enumerated() {
            // Check for NaN
            if !constraints.allowNaN && value.isNaN {
                throw ValidationError.nanValue(at: index)
            }

            // Check for infinity
            if !constraints.allowInfinity && !value.isFinite {
                throw ValidationError.infiniteValue(at: index, value: value)
            }

            // Check range
            if value < constraints.minValue || value > constraints.maxValue {
                throw ValidationError.outOfRange(
                    at: index,
                    value: value,
                    range: (constraints.minValue, constraints.maxValue)
                )
            }
        }
    }

    func sanitize(_ input: [Float], constraints: InputConstraints) -> [Float] {
        var sanitized = input

        // Pad or truncate to expected size
        if sanitized.count < constraints.expectedSize {
            // Pad with zeros
            let padding = [Float](
                repeating: 0,
                count: constraints.expectedSize - sanitized.count
            )
            sanitized.append(contentsOf: padding)
        } else if sanitized.count > constraints.expectedSize {
            // Truncate
            sanitized = Array(sanitized.prefix(constraints.expectedSize))
        }

        // Clip values to valid range
        sanitized = sanitized.map { value in
            var cleaned = value

            // Replace NaN with zero
            if cleaned.isNaN {
                cleaned = 0
            }

            // Replace infinity with max value
            if !cleaned.isFinite {
                cleaned = constraints.maxValue
            }

            // Clip to range
            cleaned = max(constraints.minValue, min(constraints.maxValue, cleaned))

            return cleaned
        }

        return sanitized
    }
}

enum ValidationError: LocalizedError {
    case invalidSize(actual: Int, expected: Int)
    case nanValue(at: Int)
    case infiniteValue(at: Int, value: Float)
    case outOfRange(at: Int, value: Float, range: (Float, Float))

    var errorDescription: String? {
        switch self {
        case .invalidSize(let actual, let expected):
            return "Invalid input size: \(actual) (expected: \(expected))"
        case .nanValue(let index):
            return "NaN value at index \(index)"
        case .infiniteValue(let index, let value):
            return "Infinite value \(value) at index \(index)"
        case .outOfRange(let index, let value, let range):
            return "Value \(value) at index \(index) out of range [\(range.0), \(range.1)]"
        }
    }
}
```

#### 2. Statistical Validation

```swift
// Statistical input validation
import Foundation

class StatisticalValidator {
    func validateDistribution(_ input: [Float], against baseline: [Float]) throws {
        // Compare statistical properties

        let inputStats = calculateStatistics(for: input)
        let baselineStats = calculateStatistics(for: baseline)

        // Check mean difference (within 2 standard deviations)
        let meanDiff = abs(inputStats.mean - baselineStats.mean)
        let meanThreshold = 2 * baselineStats.stdDev

        if meanDiff > meanThreshold {
            throw ValidationError.statisticalAnomaly(
                metric: "mean",
                value: inputStats.mean,
                expected: baselineStats.mean,
                threshold: meanThreshold
            )
        }

        // Check variance ratio
        let varianceRatio = inputStats.variance / baselineStats.variance

        if varianceRatio < 0.5 || varianceRatio > 2.0 {
            throw ValidationError.statisticalAnomaly(
                metric: "variance",
                value: inputStats.variance,
                expected: baselineStats.variance,
                threshold: (0.5, 2.0)
            )
        }
    }

    private func calculateStatistics(for data: [Float]) -> Statistics {
        let n = Float(data.count)
        let mean = data.reduce(0, +) / n

        let variance = data.map { pow($0 - mean, 2) }.reduce(0, +) / n
        let stdDev = sqrt(variance)

        let sortedData = data.sorted()
        let median: Float
        if data.count % 2 == 0 {
            median = (sortedData[data.count / 2 - 1] + sortedData[data.count / 2]) / 2
        } else {
            median = sortedData[data.count / 2]
        }

        return Statistics(
            mean: mean,
            variance: variance,
            stdDev: stdDev,
            median: median
        )
    }
}

struct Statistics {
    let mean: Float
    let variance: Float
    let stdDev: Float
    let median: Float
}
```

---

## Model Protection

### Encryption Strategies

#### 1. AES-256-GCM Model Encryption

```swift
// Secure model encryption
import CryptoKit

class ModelEncryptor {
    struct EncryptedModel {
        let data: Data
        let nonce: Data
        let tag: Data
    }

    static func encryptModel(at url: URL, key: SymmetricKey) throws -> EncryptedModel {
        let modelData = try Data(contentsOf: url)

        // Generate random nonce
        let nonce = AES.GCM.Nonce()

        // Seal with AES-GCM
        let sealedBox = try AES.GCM.seal(modelData, using: key, nonce: nonce)

        return EncryptedModel(
            data: sealedBox.ciphertext,
            nonce: sealedBox.nonce.withUnsafeBytes { Data($0) },
            tag: sealedBox.tag
        )
    }

    static func decryptModel(_ encrypted: EncryptedModel, key: SymmetricKey) throws -> Data {
        // Recreate sealed box
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: encrypted.nonce),
            ciphertext: encrypted.data,
            tag: encrypted.tag
        )

        // Open and decrypt
        return try AES.GCM.open(sealedBox, using: key)
    }
}
```

#### 2. Hybrid Encryption

```swift
// Hybrid encryption for model distribution
import CryptoKit

class HybridModelEncryptor {
    static func encryptModel(
        at url: URL,
        publicKey: SecKey
    ) throws -> (Data, Data) {
        // Generate symmetric key
        let symmetricKey = SymmetricKey(size: .bits256)

        // Encrypt model with symmetric key
        let modelData = try Data(contentsOf: url)
        let sealedBox = try AES.GCM.seal(modelData, using: symmetricKey)

        // Encrypt symmetric key with public key
        let symmetricKeyData = symmetricKey.withUnsafeBytes { Data($0) }

        var error: Unmanaged<CFError>?
        let encryptedKeyData = SecKeyCreateEncryptedData(
            publicKey,
            .eciesEncryptionStandardX963SHA256AESGCM,
            symmetricKeyData as CFData,
            &error
        )

        guard let encryptedKey = encryptedKeyData as Data? else {
            throw error!.takeRetainedValue() as Error
        }

        return (encryptedKey, sealedBox.combined)
    }
}
```

### Integrity Verification

#### 1. Model Hashing and Signing

```swift
// Model integrity verification
import CryptoKit

class ModelIntegrityVerifier {
    struct ModelSignature {
        let sha256Hash: String
        let signature: Data
        let timestamp: Date
    }

    static func generateSignature(
        for modelUrl: URL,
        privateKey: P256.Signing.PrivateKey
    ) throws -> ModelSignature {
        let modelData = try Data(contentsOf: modelUrl)

        // Calculate SHA-256 hash
        let digest = SHA256.hash(data: modelData)
        let sha256Hash = digest.compactMap { String(format: "%02x", $0) }.joined()

        // Sign hash
        let signature = try privateKey.signature(for: digest)

        return ModelSignature(
            sha256Hash: sha256Hash,
            signature: signature.rawRepresentation,
            timestamp: Date()
        )
    }

    static func verifySignature(
        modelUrl: URL,
        signature: ModelSignature,
        publicKey: P256.Signing.PublicKey
    ) throws -> Bool {
        let modelData = try Data(contentsOf: modelUrl)
        let digest = SHA256.hash(data: modelData)

        // Verify signature
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: signature.signature)
        let isValid = publicKey.isValidSignature(sig, for: digest)

        // Verify hash
        let actualHash = digest.compactMap { String(format: "%02x", $0) }.joined()
        let hashMatches = actualHash == signature.sha256Hash

        return isValid && hashMatches
    }
}
```

---

## Frida Instrumentation

### Core ML Monitoring Script

```javascript
// coreml_monitor.js

(function() {
    console.log("[*] Core ML Monitoring Script Loaded");

    // Monitor model loading
    if (ObjC.available && ObjC.classes.MLModel) {
        var MLModel = ObjC.classes.MLModel;

        // Hook model loading
        Interceptor.attach(MLModel['- initWithContentsOfURL:configuration:error:'].implementation, {
            onEnter: function(args) {
                var url = ObjC.Object(args[2]);
                console.log("[!] MLModel loading from: " + url.absoluteString());
                this.modelUrl = url;
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    var model = ObjC.Object(retval);
                    console.log("[+] Model loaded successfully");
                    console.log("    Model description: " + model.modelDescription());
                    console.log("    Metadata: " + model.metadata());
                }
            }
        });

        // Hook predictions
        Interceptor.attach(MLModel['- predictionFromFeatures:error:'].implementation, {
            onEnter: function(args) {
                var features = ObjC.Object(args[2]);
                console.log("[!] Prediction requested");
                console.log("    Input features: " + features.description());

                // Store for output capture
                this.features = features;
            },
            onLeave: function(retval) {
                var prediction = ObjC.Object(retval);
                console.log("[+] Prediction completed");
                console.log("    Output: " + prediction.description());

                // Analyze prediction
                var outputDict = prediction.dictionaryRepresentation();
                console.log("    Output dict: " + outputDict.description());
            }
        });

        // Hook batch predictions
        if (MLModel['- predictionsFromBatch:error:']) {
            Interceptor.attach(MLModel['- predictionsFromBatch:error:'].implementation, {
                onEnter: function(args) {
                    var batch = ObjC.Object(args[2]);
                    console.log("[!] Batch prediction requested");
                    console.log("    Batch size: " + batch.count());
                },
                onLeave: function(retval) {
                    var predictions = ObjC.Object(retval);
                    console.log("[+] Batch prediction completed");
                    console.log("    Predictions: " + predictions.description());
                }
            });
        }
    }

    // Monitor MLFeatureProvider
    if (ObjC.available && ObjC.classes.MLFeatureProvider) {
        var MLFeatureProvider = ObjC.classes.MLFeatureProvider;

        Interceptor.attach(MLFeatureProvider['- featureValueForKey:'].implementation, {
            onEnter: function(args) {
                var key = ObjC.Object(args[2]);
                console.log("[!] Feature requested: " + key);
            },
            onLeave: function(retval) {
                if (retval.toInt32() !== 0) {
                    var value = ObjC.Object(retval);
                    console.log("    Value: " + value.description());
                }
            }
        });
    }

    // Monitor model configuration
    if (ObjC.available && ObjC.classes.MLModelConfiguration) {
        var MLModelConfiguration = ObjC.classes.MLModelConfiguration;

        Interceptor.attach(MLModelConfiguration['- setComputeUnits:'].implementation, {
            onEnter: function(args) {
                var units = args[2];
                console.log("[!] Setting compute units: " + units);
            }
        });
    }

    // Track memory usage
    setInterval(function() {
        if (ObjC.available) {
            var memoryUsage = ObjC.classes.NSProcessInfo.processInfo.physicalMemory() / (1024 * 1024);
            console.log("[*] Memory usage: " + memoryUsage.toFixed(2) + " MB");
        }
    }, 5000);

    console.log("[+] Core ML monitoring hooks installed");
})();
```

---

## On-Device vs Cloud Inference

### Security Comparison

| Aspect | On-Device | Cloud |
|--------|-----------|-------|
| **Data Privacy** | Data stays on device | Data sent to server |
| **Latency** | Low | Network-dependent |
| **Cost** | Device compute | Server compute |
| **Security** | Model exposed locally | Model protected on server |
| **Updates** | App update required | Server-side update |
| **Adversarial Resistance** | Easier to attack | Harder (if secured) |

### Secure Cloud Inference

```swift
// Secure cloud inference implementation
import Foundation
import CryptoKit

class SecureCloudInference {
    struct CloudInferenceRequest: Codable {
        let encryptedInput: Data
        let nonce: Data
        let timestamp: Date
    }

    struct CloudInferenceResponse: Codable {
        let encryptedOutput: Data
        let nonce: Data
        let signature: Data
    }

    private let endpoint: URL
    private let session: URLSession

    init(endpoint: URL) {
        self.endpoint = endpoint
        self.session = URLSession(configuration: .ephemeral)
    }

    func predict(_ input: [Float], key: SymmetricKey) async throws -> [Float] {
        // Validate input
        guard !input.isEmpty else {
            throw InferenceError.invalidInput
        }

        // Encrypt input
        let inputData = try JSONEncoder().encode(input)
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(inputData, using: key, nonce: nonce)

        // Create request
        let request = CloudInferenceRequest(
            encryptedInput: sealedBox.combined,
            nonce: nonce.withUnsafeBytes { Data($0) },
            timestamp: Date()
        )

        // Send to cloud
        let responseData = try await performRequest(request)

        // Decrypt response
        let response = try JSONDecoder().decode(CloudInferenceResponse.self, from: responseData)

        // Verify signature
        guard try verifySignature(response) else {
            throw InferenceError.invalidSignature
        }

        // Decrypt output
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: response.nonce),
            ciphertext: response.encryptedOutput
        )

        let decryptedData = try AES.GCM.open(sealedBox, using: key)
        let output = try JSONDecoder().decode([Float].self, from: decryptedData)

        return output
    }

    private func performRequest(_ request: CloudInferenceRequest) async throws -> Data {
        var urlRequest = URLRequest(url: endpoint)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")

        urlRequest.httpBody = try JSONEncoder().encode(request)

        let (data, response) = try await session.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw InferenceError.networkError
        }

        return data
    }

    private func verifySignature(_ response: CloudInferenceResponse) throws -> Bool {
        // Implement signature verification
        // Use server's public key to verify response signature

        return true
    }
}

enum InferenceError: LocalizedError {
    case invalidInput
    case networkError
    case invalidSignature

    var errorDescription: String? {
        switch self {
        case .invalidInput:
            return "Invalid input provided"
        case .networkError:
            return "Network error occurred"
        case .invalidSignature:
            return "Invalid response signature"
        }
    }
}
```

---

## Testing Methodology

### Comprehensive ML Security Testing

```bash
#!/bin/bash
# ml_security_audit.sh

APP_PATH="$1"
OUTPUT_DIR="$2"

if [ -z "$APP_PATH" ] || [ -z "$OUTPUT_DIR" ]; then
    echo "Usage: $0 <app_path> <output_dir>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[*] Starting ML Security Audit for $APP_PATH"
echo "======================================"

# Phase 1: Static Analysis
echo "[1] Static Analysis"
echo "-------------------"

# Check for Core ML usage
echo "[*] Checking for Core ML framework..."
if strings "$APP_PATH"/* | grep -qi "coreml\|core ml"; then
    echo "[+] Core ML framework detected"
else
    echo "[-] No Core ML usage detected"
    exit 0
fi

# Extract models
echo "[*] Extracting Core ML models..."
MODELS=$(find "$APP_PATH" -name "*.mlmodelc" -type d)

if [ -z "$MODELS" ]; then
    echo "[-] No compiled models found"
else
    echo "[+] Found $(echo "$MODELS" | wc -l | tr -d ' ') model(s)"

    for model in $MODELS; do
        model_name=$(basename "$model")
        echo "  [*] Analyzing: $model_name"

        # Check for encryption
        if [ -f "$model/weights.bin" ]; then
            if file "$model/weights.bin" | grep -q "data"; then
                echo "  [!] WARNING: Unencrypted weights detected"
            fi
        fi

        # Extract metadata
        if [ -f "$model/metadata.json" ]; then
            cp "$model/metadata.json" "$OUTPUT_DIR/${model_name}_metadata.json"
        fi

        # Search for secrets
        strings "$model"/* | grep -iE "api[_-]?key|secret|token|password" | \
            sort -u > "$OUTPUT_DIR/${model_name}_secrets.txt"

        if [ -s "$OUTPUT_DIR/${model_name}_secrets.txt" ]; then
            echo "  [!] WARNING: Potential secrets found in model"
        fi
    done
fi

# Phase 2: Binary Analysis
echo "[2] Binary Analysis"
echo "-------------------"

# Check for encryption APIs
echo "[*] Checking for encryption APIs..."
if strings "$APP_PATH"/* | grep -qi "AES\|CryptoKit\|CommonCrypto"; then
    echo "[+] Encryption APIs found"
else
    echo "[-] No encryption APIs detected"
    echo "  [!] WARNING: Models may be unencrypted"
fi

# Check for input validation
echo "[*] Checking for input validation..."
if strings "$APP_PATH"/* | grep -qi "validate\|sanitize\|check.*input"; then
    echo "[+] Input validation found"
else
    echo "[-] No input validation detected"
    echo "  [!] WARNING: Susceptible to adversarial inputs"
fi

# Phase 3: Dynamic Analysis
echo "[3] Dynamic Analysis"
echo "-------------------"

echo "[*] Dynamic analysis requires device connection"
# NOTE: `coreml_monitor.js` is NOT bundled with this skill (see
#       references/frida-scripts-index.md for the catalog of bundled scripts).
#       You must author it yourself before running this command.
echo "    Run with Frida: frida -U -f com.app.name -l coreml_monitor.js"

# Phase 4: Report Generation
echo ""
echo "[4] Report"
echo "--------"

REPORT="$OUTPUT_DIR/ml_security_report.txt"

cat > "$REPORT" << EOF
ML Security Audit Report
======================

Target: $APP_PATH
Date: $(date)

Static Analysis:
- Core ML Usage: $(strings "$APP_PATH"/* | grep -qi "coreml" && echo "YES" || echo "NO")
- Models Found: $(find "$APP_PATH" -name "*.mlmodelc" | wc -l | tr -d ' ')
- Encryption APIs: $(strings "$APP_PATH"/* | grep -qi "aes\|cryptokit" && echo "YES" || echo "NO")
- Input Validation: $(strings "$APP_PATH"/* | grep -qi "validate\|sanitize" && echo "YES" || echo "NO")

Models:
$(find "$APP_PATH" -name "*.mlmodelc" | while read model; do
    echo "- $(basename "$model")"
    echo "  Size: $(du -sh "$model" | cut -f1)"
    if [ -f "$model/weights.bin" ]; then
        echo "  Weights: Encrypted=$(file "$model/weights.bin" | grep -q "data" && echo "NO" || echo "YES")"
    fi
done)

Recommendations:
EOF

# Add recommendations based on findings
if strings "$APP_PATH"/* | grep -qi "aes\|cryptokit"; then
    echo "- Model encryption detected" >> "$REPORT"
else
    echo "- [HIGH] Implement model encryption to prevent extraction" >> "$REPORT"
fi

if strings "$APP_PATH"/* | grep -qi "validate\|sanitize"; then
    echo "- Input validation detected" >> "$REPORT"
else
    echo "- [MEDIUM] Implement input validation to prevent adversarial attacks" >> "$REPORT"
fi

echo "" >> "$REPORT"
echo "Report saved to: $REPORT"

echo "[+] Audit complete"
```

---

## Vulnerability Examples

### Example 1: Unencrypted Model Extraction

**CVSS 4.0 Vector**: `CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U`

**CVSS Score**: 8.2 (HIGH)

**Description**: Core ML model stored unencrypted in app bundle

**Detection**:
```bash
# Check for unencrypted weights
find Payload/*.app -name "*.mlmodelc" -exec sh -c 'if [ -f "$1/weights.bin" ]; then file "$1/weights.bin"; fi' _ {} \;
# Output: data (unencrypted)
```

**Impact**: IP theft, model reverse engineering, competitive disadvantage

### Example 2: No Input Validation

**CVSS 4.0 Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U`

**CVSS Score**: 6.7 (MEDIUM)

**Description**: Model accepts inputs without validation

**Impact**: Model crashes, adversarial attacks, unreliable predictions

### Example 3: Adversarial Attack Susceptibility

**CVSS 4.0 Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U`

**CVSS Score**: 9.1 (CRITICAL)

**Description**: Model vulnerable to adversarial examples

**Detection**:
```python
# Test with FGSM
attacker = FGSMAttacker("device_id", "com.app.name")
results = attacker.test_robustness(test_inputs)
print(f"Attack success rate: {results['attack_success_rate'] * 100:.1f}%")
```

**Impact**: Bypass security controls, incorrect classifications

---

## Remediation Strategies

### 1. Implement Comprehensive Security

```swift
// Complete secure ML pipeline
import CoreML
import CryptoKit

class SecureMLPipeline {
    private let model: MLModel
    private let encryptionKey: SymmetricKey
    private let inputValidator = MLInputValidator()
    private let adversarialDefense = AdversarialDefense()

    init(modelUrl: URL, key: SymmetricKey) throws {
        self.encryptionKey = key

        // Load encrypted model
        let decryptedUrl = try loadEncryptedModel(at: modelUrl)
        self.model = try MLModel(contentsOf: decryptedUrl)

        // Clean up
        try? FileManager.default.removeItem(at: decryptedUrl)
    }

    func predict(_ input: [Float]) throws -> [Float] {
        // Phase 1: Input validation
        let constraints = MLInputValidator.InputConstraints(
            minSize: 224 * 224 * 3,
            maxSize: 224 * 224 * 3,
            expectedSize: 224 * 224 * 3,
            minValue: 0.0,
            maxValue: 1.0,
            allowNaN: false,
            allowInfinity: false
        )

        try inputValidator.validate(input, against: constraints)

        // Phase 2: Adversarial defense
        var sanitized = input

        // Apply random resize and pad
        sanitized = adversarialDefense.randomResizeAndPad(sanitized, originalSize: (224, 224))

        // Apply feature squeezing
        sanitized = adversarialDefense.featureSqueeze(sanitized, bitDepth: 6)

        // Phase 3: Model prediction
        let mlArray = try MLArrayFeatureProvider(dictionary: ["input": sanitized])
        let prediction = try model.prediction(from: mlArray)

        // Phase 4: Output validation
        let output = try validateOutput(prediction)

        return output
    }

    private func validateOutput(_ prediction: MLFeatureProvider) throws -> [Float] {
        guard let output = prediction.featureValue(for: "output").multiArrayValue else {
            throw MLError.invalidOutput
        }

        let floatArray = output.converted(to: .float).toArray(of: Float.self)

        // Validate output range
        for value in floatArray {
            guard value.isFinite && value >= 0.0 && value <= 1.0 else {
                throw MLError.invalidOutput
            }
        }

        return floatArray
    }

    private func loadEncryptedModel(at url: URL) throws -> URL {
        let encryptedData = try Data(contentsOf: url)

        // Decrypt
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        let decryptedData = try AES.GCM.open(sealedBox, using: encryptionKey)

        // Write to temporary file
        let tempUrl = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
            .appendingPathExtension("mlmodelc")

        try decryptedData.write(to: tempUrl)

        return tempUrl
    }
}

enum MLError: LocalizedError {
    case invalidOutput

    var errorDescription: String? {
        switch self {
        case .invalidOutput:
            return "Invalid model output"
        }
    }
}
```

---

## Testing Checklist

### Model Extraction
- [ ] Check for unencrypted models
- [ ] Test model extraction from bundle
- [ ] Verify model obfuscation
- [ ] Test black-box extraction techniques
- [ ] Check for integrity verification

### Model Poisoning
- [ ] Test for backdoor triggers
- [ ] Verify model signature checking
- [ ] Test consistency over time
- [ ] Check for suspicious outputs
- [ ] Test input sanitization

### Adversarial Attacks
- [ ] Test FGSM robustness
- [ ] Test PGD robustness
- [ ] Test C&W attacks
- [ ] Measure attack success rate
- [ ] Verify defense mechanisms

### Input Validation
- [ ] Test size constraints
- [ ] Test range validation
- [ ] Test NaN/Infinity handling
- [ ] Test statistical validation
- [ ] Verify sanitization

### Cloud Inference
- [ ] Verify input encryption
- [ ] Check certificate pinning
- [ ] Verify output encryption
- [ ] Test signature verification
- [ ] Check for data leakage

---

## OWASP MASTG References

### MASTG Test Cases

- **MASTG-TEST-0038**: Local Data Storage Analysis
  - Analyze stored ML models for security

- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
  - Review ML code for vulnerabilities

- **MASTG-TEST-0083**: Testing Binary Protection
  - Check model protection mechanisms

- **AITG-APP-09**: Machine Learning Security
  - Comprehensive ML security testing

### Related OWASP Projects

- **OWASP Machine Learning Security Top 10**
- **OWASP Adversarial Machine Learning**
- **OWASP Neural Network Security**

---

## Tools and Resources

### Analysis Tools

| Tool | Purpose | Link |
|------|---------|------|
| **Frida** | Runtime instrumentation | https://frida.re |
| **CoreMLTools** | Model conversion and analysis | https://github.com/apple/coremltools |
| **Netron** | Model visualization | https://netron.app |
| **CleverHans** | Adversarial examples | https://github.com/cleverhans-lab/cleverhans |
| **ART (Adversarial Robustness Toolbox)** | Adversarial attacks | https://github.com/Trusted-AI/adversarial-robustness-toolbox |

### Research Papers

- **USENIX 2024**: "Extracting Core ML Models from iOS Apps"
- **Black Hat 2024**: "Adversarial Attacks against On-Device ML"
- **NeurIPS 2023**: "Model Extraction Attacks on Mobile ML"
- **IEEE S&P 2024**: "Defending Against Model Poisoning"

### CVE Examples

- **CVE-2024-27837**: Core ML Model Extraction (Hypothetical)
  - Severity: HIGH (7.5)
  - Impact: Unencrypted model extraction

- **CVE-2024-29881**: ML Model Poisoning (Hypothetical)
  - Severity: HIGH (8.8)
  - Impact: Manipulated model behavior

- **CVE-2024-31045**: Adversarial Attack Bypass (Hypothetical)
  - Severity: CRITICAL (9.1)
  - Impact: Security control bypass

---

## Conclusion

Core ML security requires a multi-layered approach:

1. **Model Protection**: Encrypt, obfuscate, and sign models
2. **Input Validation**: Sanitize and validate all inputs
3. **Adversarial Defense**: Implement robustness techniques
4. **Output Validation**: Verify model outputs
5. **Monitoring**: Use runtime instrumentation to detect attacks

By following the methodologies and best practices in this guide, developers can build secure ML applications that resist extraction, poisoning, and adversarial attacks while maintaining performance and user experience.
