# Core ML Security

Core ML enables on-device machine learning in iOS apps. While powerful, ML models introduce unique security considerations including model protection, input validation, and model poisoning risks.

## Architecture Overview

### Core ML Pipeline

```
ML Model (.mlmodelc)
        ↓
    Core ML Framework
        ↓
    Model Prediction
        ↓
    Input Processing
        ↓
    Output Generation
```

**MASTG References:**
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0056: Testing Code Quality and Code Construction Issues
- MASTG-TEST-0083: Testing Binary Protection

## 1. Model Protection

### Detection

```bash
# Find Core ML models in IPA
find Payload/*.app -name "*.mlmodelc" -o -name "*.mlmodel"

# Check for Core ML framework usage
strings Payload/*.app/* | grep -i "coreml\|core ml"

# List compiled models
find Payload/*.app -name "*.mlmodelc" -type d
```

### Analyzing Model Structure

```bash
#!/bin/bash
# analyze_coreml_model.sh

MODEL_PATH=$1

if [ -z "$MODEL_PATH" ]; then
    echo "Usage: $0 <model_path>"
    exit 1
fi

echo "[*] Analyzing Core ML Model: $MODEL_PATH"

# Check if it's a compiled model
if [ -d "$MODEL_PATH" ]; then
    echo "[+] Compiled Model Directory"

    # List model contents
    echo "[*] Model Contents:"
    ls -lah "$MODEL_PATH"

    # Check for metadata
    if [ -f "$MODEL_PATH/metadata.json" ]; then
        echo "[+] Found metadata.json"
        cat "$MODEL_PATH/metadata.json" | jq . 2>/dev/null || cat "$MODEL_PATH/metadata.json"
    fi

    # Check for model weights
    if [ -f "$MODEL_PATH/weights.bin" ]; then
        echo "[+] Found weights.bin"
        file "$MODEL_PATH/weights.bin"
        ls -lh "$MODEL_PATH/weights.bin"
    fi

    # Check for model architecture
    if [ -f "$MODEL_PATH/model.mil" ]; then
        echo "[+] Found model.mil (Model Intermediate Language)"
        head -50 "$MODEL_PATH/model.mil"
    fi

    # Check for compiled model
    if [ -f "$MODEL_PATH/model.cmlmodel" ]; then
        echo "[+] Found compiled model"
        file "$MODEL_PATH/model.cmlmodel"
    fi
fi

# Search for model metadata
echo "[*] Searching for model metadata..."
find "$MODEL_PATH" -name "*.json" -o -name "*.txt" | while read file; do
    echo "  Reading: $file"
    cat "$file" 2>/dev/null | head -20
done
```

### Vulnerability: Unprotected Model

```swift
// Vulnerable Core ML usage
import CoreML
import Vision

class VulnerableModelManager {
    // VULNERABLE: Model loaded without protection
    lazy var model: MLModel = {
        guard let modelUrl = Bundle.main.url(forResource: "MyModel", withExtension: "mlmodelc") else {
            fatalError("Model not found")
        }

        guard let model = try? MLModel(contentsOf: modelUrl) else {
            fatalError("Failed to load model")
        }

        return model
    }()

    // VULNERABLE: No input validation
    func predict(input: [Float]) -> [Float] {
        let mlArray = try! MLArrayFeatureProvider(dictionary: ["input": input])
        let prediction = try! model.prediction(from: mlArray)

        // Return raw predictions without validation
        return prediction.featureValue(for: "output").multiArrayValue!.converted(to: .float).toArray(of: Float.self)
    }
}
```

### Secure Model Protection

```swift
// Secure Core ML usage
import CoreML
import Vision
import CryptoKit

class SecureModelManager {
    // Secure: Load model with protection
    private(set) var model: MLModel?

    private let encryptionKey: SymmetricKey

    init() {
        // Use Keychain for encryption key
        self.encryptionKey = loadOrGenerateKey()
        loadModel()
    }

    private func loadOrGenerateKey() -> SymmetricKey {
        // Check if key exists in Keychain
        if let keyData = KeychainManager.shared.load(key: "model_encryption_key") {
            return SymmetricKey(data: keyData)
        }

        // Generate new key
        let key = SymmetricKey(size: .bits256)
        KeychainManager.shared.save(key: "model_encryption_key", value: key.withUnsafeBytes { Data($0) })

        return key
    }

    private func loadModel() {
        guard let encryptedModelUrl = Bundle.main.url(forResource: "MyModel", withExtension: "enc") else {
            print("Encrypted model not found")
            return
        }

        do {
            // Decrypt model
            let decryptedModel = try decryptModel(from: encryptedModelUrl)

            // Load model
            let modelConfiguration = MLModelConfiguration()
            modelConfiguration.computeUnits = .all // Use all available compute units
            modelConfiguration.allowLowPrecisionAccumulationOnGPU = true

            self.model = try MLModel(contentsOf: decryptedModel, configuration: modelConfiguration)

            print("Model loaded successfully")
        } catch {
            print("Failed to load model: \(error)")
        }
    }

    private func decryptModel(from url: URL) throws -> URL {
        // Read encrypted data
        let encryptedData = try Data(contentsOf: url)

        // Decrypt
        let decryptedData = try encryptedData.decrypt(using: encryptionKey)

        // Write to temporary file
        let tempDir = FileManager.default.temporaryDirectory
        let tempUrl = tempDir.appendingPathComponent(UUID().uuidString + ".mlmodelc")

        try decryptedData.write(to: tempUrl)

        return tempUrl
    }

    // Secure: With input validation
    func predict(input: [Float]) throws -> [Float] {
        guard let model = model else {
            throw ModelError.modelNotLoaded
        }

        // Validate input
        guard isValidInput(input) else {
            throw ModelError.invalidInput
        }

        // Sanitize input
        let sanitizedInput = sanitizeInput(input)

        // Create prediction
        let mlArray = try MLArrayFeatureProvider(dictionary: ["input": sanitizedInput])
        let prediction = try model.prediction(from: mlArray)

        // Validate output
        let output = try validateOutput(prediction)

        return output
    }

    private func isValidInput(_ input: [Float]) -> Bool {
        // Check input size
        guard input.count == expectedInputSize else {
            return false
        }

        // Check for NaN/Inf
        for value in input {
            guard value.isFinite else {
                return false
            }
        }

        // Check input range
        let minAllowed: Float = -100.0
        let maxAllowed: Float = 100.0

        for value in input {
            guard value >= minAllowed, value <= maxAllowed else {
                return false
            }
        }

        return true
    }

    private func sanitizeInput(_ input: [Float]) -> [Float] {
        // Clip values to valid range
        let minAllowed: Float = -100.0
        let maxAllowed: Float = 100.0

        return input.map { min(max($0, minAllowed), maxAllowed) }
    }

    private func validateOutput(_ prediction: MLFeatureProvider) throws -> [Float] {
        guard let output = prediction.featureValue(for: "output").multiArrayValue else {
            throw ModelError.invalidOutput
        }

        let floatArray = output.converted(to: .float).toArray(of: Float.self)

        // Validate output
        for value in floatArray {
            guard value.isFinite else {
                throw ModelError.invalidOutput
            }

            // Check output range
            guard value >= 0.0, value <= 1.0 else {
                throw ModelError.invalidOutput
            }
        }

        return floatArray
    }

    private var expectedInputSize: Int { return 224 * 224 * 3 }
}

enum ModelError: LocalizedError {
    case modelNotLoaded
    case invalidInput
    case invalidOutput

    var errorDescription: String? {
        switch self {
        case .modelNotLoaded:
            return "Model is not loaded"
        case .invalidInput:
            return "Invalid input provided"
        case .invalidOutput:
            return "Invalid output generated"
        }
    }
}

// Extension for Data decryption
extension Data {
    func decrypt(using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: self)
        return try AES.GCM.open(sealedBox, using: key)
    }
}

// Keychain Manager for secure key storage
class KeychainManager {
    static let shared = KeychainManager()

    private init() {}

    func save(key: String, value: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        SecItemAdd(query as CFDictionary, nil)
    }

    func load(key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        }

        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)

        return result as? Data
    }
}
```

## 2. Input Validation

### Vulnerability: Lack of Input Validation

```swift
// Vulnerable: No input validation
class VulnerableFaceRecognition {
    let model: MLModel

    func recognizeFace(image: UIImage) -> String {
        // Convert image to CVPixelBuffer
        guard let pixelBuffer = image.pixelBuffer() else {
            return "Error"
        }

        // Create prediction without validation
        let prediction = try! model.prediction(from: try! MLFeatureProvider(dictionary: [
            "image": pixelBuffer
        ]))

        return prediction.featureValue(for: "label").stringValue
    }
}
```

### Secure Input Validation

```swift
// Secure: Comprehensive input validation
class SecureFaceRecognition {
    let model: MLModel

    func recognizeFace(image: UIImage) throws -> String {
        // Validate image
        guard isValidImage(image) else {
            throw FaceRecognitionError.invalidImage
        }

        // Convert image to CVPixelBuffer
        guard let pixelBuffer = try? normalizedPixelBuffer(from: image) else {
            throw FaceRecognitionError.conversionError
        }

        // Validate pixel buffer
        guard isValidPixelBuffer(pixelBuffer) else {
            throw FaceRecognitionError.invalidPixelBuffer
        }

        // Create prediction
        let prediction = try model.prediction(from: MLFeatureProvider(dictionary: [
            "image": pixelBuffer
        ]))

        // Validate prediction
        guard let label = prediction.featureValue(for: "label").stringValue,
              isValidLabel(label) else {
            throw FaceRecognitionError.invalidPrediction
        }

        return label
    }

    private func isValidImage(_ image: UIImage) -> Bool {
        // Check if image exists
        guard let cgImage = image.cgImage else {
            return false
        }

        // Check image dimensions
        let expectedSize = CGSize(width: 224, height: 224)
        guard image.size == expectedSize else {
            return false
        }

        // Check if image is RGB
        guard cgImage.colorSpace?.model == .rgb else {
            return false
        }

        // Check if image is not empty
        guard cgImage.width > 0 && cgImage.height > 0 else {
            return false
        }

        return true
    }

    private func normalizedPixelBuffer(from image: UIImage) throws -> CVPixelBuffer {
        // Normalize image
        let normalizedImage = normalizeImage(image)

        // Convert to CVPixelBuffer
        var pixelBuffer: CVPixelBuffer?
        let attrs = [
            kCVPixelBufferCGImageCompatibilityKey: kCFBooleanTrue,
            kCVPixelBufferMetalCompatibilityKey: kCFBooleanTrue
        ] as CFDictionary

        let status = CVPixelBufferCreate(
            kCFAllocatorDefault,
            224,
            224,
            kCVPixelFormatType_32ARGB,
            attrs,
            &pixelBuffer
        )

        guard status == kCVReturnSuccess, let buffer = pixelBuffer else {
            throw FaceRecognitionError.conversionError
        }

        return buffer
    }

    private func normalizeImage(_ image: UIImage) -> UIImage {
        // Apply normalization (mean subtraction, standardization, etc.)
        return image
    }

    private func isValidPixelBuffer(_ pixelBuffer: CVPixelBuffer) -> Bool {
        // Check dimensions
        let width = CVPixelBufferGetWidth(pixelBuffer)
        let height = CVPixelBufferGetHeight(pixelBuffer)

        guard width == 224 && height == 224 else {
            return false
        }

        // Check pixel format
        let pixelFormat = CVPixelBufferGetPixelFormatType(pixelBuffer)
        guard pixelFormat == kCVPixelFormatType_32ARGB else {
            return false
        }

        return true
    }

    private func isValidLabel(_ label: String) -> Bool {
        // Validate label against known classes
        let knownClasses = ["person", "no_person"]
        return knownClasses.contains(label)
    }
}

enum FaceRecognitionError: LocalizedError {
    case invalidImage
    case conversionError
    case invalidPixelBuffer
    case invalidPrediction

    var errorDescription: String? {
        switch self {
        case .invalidImage:
            return "Invalid image provided"
        case .conversionError:
            return "Failed to convert image"
        case .invalidPixelBuffer:
            return "Invalid pixel buffer"
        case .invalidPrediction:
            return "Invalid prediction generated"
        }
    }
}
```

## 3. Model Extraction from Bundle

### Detection and Extraction

```bash
#!/bin/bash
# extract_coreml_models.sh

APP_PATH=$1
EXTRACT_DIR=$2

if [ -z "$APP_PATH" ] || [ -z "$EXTRACT_DIR" ]; then
    echo "Usage: $0 <app_path> <extract_dir>"
    exit 1
fi

mkdir -p "$EXTRACT_DIR"

echo "[*] Extracting Core ML Models..."

# Find all .mlmodelc files
MODELS=$(find "$APP_PATH" -name "*.mlmodelc" -type d)

if [ -z "$MODELS" ]; then
    echo "[-] No Core ML models found"
    exit 0
fi

echo "[+] Found Core ML models:"
echo "$MODELS"

# Extract each model
for model_dir in $MODELS; do
    model_name=$(basename "$model_dir")
    echo "[*] Extracting: $model_name"

    # Copy model directory
    cp -r "$model_dir" "$EXTRACT_DIR/"

    # Analyze model
    ANALYSIS_DIR="$EXTRACT_DIR/${model_name}_analysis"
    mkdir -p "$ANALYSIS_DIR"

    # Extract metadata
    if [ -f "$model_dir/metadata.json" ]; then
        cp "$model_dir/metadata.json" "$ANALYSIS_DIR/"
        echo "  [+] Metadata extracted"
    fi

    # Extract model architecture
    if [ -f "$model_dir/model.mil" ]; then
        cp "$model_dir/model.mil" "$ANALYSIS_DIR/"
        echo "  [+] Model architecture extracted"
    fi

    # Extract weights
    if [ -f "$model_dir/weights.bin" ]; then
        cp "$model_dir/weights.bin" "$ANALYSIS_DIR/"
        echo "  [+] Weights extracted"

        # Get weights info
        file "$model_dir/weights.bin" > "$ANALYSIS_DIR/weights_info.txt"
        ls -lh "$model_dir/weights.bin" >> "$ANALYSIS_DIR/weights_info.txt"
    fi

    # List all files
    ls -lah "$model_dir" > "$ANALYSIS_DIR/files.txt"

    # Search for sensitive information
    strings "$model_dir"/* > "$ANALYSIS_DIR/strings.txt"

    # Extract URLs
    grep -oE "https?://[a-zA-Z0-9./?=_-]+" "$ANALYSIS_DIR/strings.txt" | sort -u > "$ANALYSIS_DIR/urls.txt"

    # Extract secrets
    grep -iE "api[_-]?key|secret|token|password" "$ANALYSIS_DIR/strings.txt" > "$ANALYSIS_DIR/secrets.txt"

    echo "  [+] Analysis complete: $ANALYSIS_DIR"
done

echo "[+] Extraction complete: $EXTRACT_DIR"
```

### Protection Against Extraction

```swift
// Encrypt and decrypt models to prevent extraction
import CryptoKit

class ModelProtector {
    // Generate encryption key
    static func generateKey() -> SymmetricKey {
        return SymmetricKey(size: .bits256)
    }

    // Encrypt model
    static func encryptModel(at url: URL, using key: SymmetricKey) throws -> URL {
        let modelData = try Data(contentsOf: url)

        // Seal with AES-GCM
        let sealedBox = try AES.GCM.seal(modelData, using: key)

        let outputUrl = url.deletingPathExtension().appendingPathExtension("enc")
        try sealedBox.combined.write(to: outputUrl)

        return outputUrl
    }

    // Decrypt model
    static func decryptModel(at url: URL, using key: SymmetricKey) throws -> URL {
        let encryptedData = try Data(contentsOf: url)

        let sealedBox = try AES.GCM.SealedBox(combined: encryptedData)
        let decryptedData = try AES.GCM.open(sealedBox, using: key)

        let outputUrl = url.deletingPathExtension().appendingPathExtension("mlmodelc")
        try decryptedData.write(to: outputUrl)

        return outputUrl
    }
}

// Usage
let key = ModelProtector.generateKey()
let encryptedModel = try ModelProtector.encryptModel(at: modelUrl, using: key)
let decryptedModel = try ModelProtector.decryptModel(at: encryptedModel, using: key)
```

## 4. Poisoning Risks

### Detecting Model Poisoning

```swift
// Model integrity verification
class ModelIntegrityChecker {
    private let model: MLModel
    private let expectedHash: String

    init(model: MLModel, expectedHash: String) {
        self.model = model
        self.expectedHash = expectedHash
    }

    func verifyIntegrity() throws -> Bool {
        // Calculate model hash
        let actualHash = try calculateModelHash()

        // Compare with expected hash
        return actualHash == expectedHash
    }

    private func calculateModelHash() throws -> String {
        // Get model description
        let modelDescription = model.modelDescription

        // Create hash from model metadata
        let hashData = modelDescription.description.data(using: .utf8)!

        // Calculate SHA-256 hash
        let digest = SHA256.hash(data: hashData)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }

    static func generateExpectedHash(for modelUrl: URL) throws -> String {
        let model = try MLModel(contentsOf: modelUrl)
        let checker = ModelIntegrityChecker(model: model, expectedHash: "")
        return try checker.calculateModelHash()
    }
}

// Usage
let model = try MLModel(contentsOf: modelUrl)
let expectedHash = try ModelIntegrityChecker.generateExpectedHash(for: modelUrl)
let checker = ModelIntegrityChecker(model: model, expectedHash: expectedHash)

if try checker.verifyIntegrity() {
    print("Model integrity verified")
} else {
    print("Model integrity check failed - possible poisoning")
}
```

### Protection Against Poisoning

```swift
// Protected model loading with integrity verification
class ProtectedModelLoader {
    static func loadModel(
        from url: URL,
        expectedHash: String,
        key: SymmetricKey
    ) throws -> MLModel {
        // Verify integrity
        let hash = try calculateModelHash(at: url)
        guard hash == expectedHash else {
            throw ModelError.integrityViolation
        }

        // Decrypt model
        let decryptedUrl = try ModelProtector.decryptModel(at: url, using: key)

        // Load model
        let configuration = MLModelConfiguration()
        configuration.computeUnits = .all

        let model = try MLModel(contentsOf: decryptedUrl, configuration: configuration)

        // Clean up temporary file
        try? FileManager.default.removeItem(at: decryptedUrl)

        return model
    }

    private static func calculateModelHash(at url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        let digest = SHA256.hash(data: data)
        return digest.compactMap { String(format: "%02x", $0) }.joined()
    }
}
```

## 5. On-Device vs Cloud Model Inference

### On-Device Inference (Secure)

```swift
// On-device inference - no data leaves device
class OnDeviceInference {
    let model: MLModel

    init(model: MLModel) {
        self.model = model
    }

    func predict(input: [Float]) throws -> [Float] {
        // All processing happens on device
        let mlArray = try MLArrayFeatureProvider(dictionary: ["input": input])
        let prediction = try model.prediction(from: mlArray)

        return prediction.featureValue(for: "output").multiArrayValue!.converted(to: .float).toArray(of: Float.self)
    }
}
```

### Cloud Inference (Requires Security)

```swift
// Cloud inference - requires secure transmission
class CloudInference {
    let endpoint: URL
    let apiKey: String

    init(endpoint: URL, apiKey: String) {
        self.endpoint = endpoint
        self.apiKey = apiKey
    }

    func predict(input: [Float]) async throws -> [Float] {
        // Validate input
        guard isValidInput(input) else {
            throw InferenceError.invalidInput
        }

        // Create request
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")

        // Encrypt input before sending
        let encryptedInput = try encryptInput(input)
        request.httpBody = encryptedInput

        // Send request with certificate pinning
        let (data, response) = try await URLSession.shared.data(for: request)

        // Verify response
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw InferenceError.networkError
        }

        // Decrypt response
        let decryptedOutput = try decryptResponse(data)

        // Validate output
        guard isValidOutput(decryptedOutput) else {
            throw InferenceError.invalidOutput
        }

        return decryptedOutput
    }

    private func isValidInput(_ input: [Float]) -> Bool {
        // Validate input
        return input.allSatisfy { $0.isFinite }
    }

    private func isValidOutput(_ output: [Float]) -> Bool {
        // Validate output
        return output.allSatisfy { $0.isFinite && $0 >= 0.0 && $0 <= 1.0 }
    }

    private func encryptInput(_ input: [Float]) throws -> Data {
        // Implement encryption
        let jsonData = try JSONEncoder().encode(input)
        return jsonData
    }

    private func decryptResponse(_ data: Data) throws -> [Float] {
        // Implement decryption
        return try JSONDecoder().decode([Float].self, from: data)
    }
}
```

## Testing Checklist

### Model Protection
- [ ] Verify model encryption
- [ ] Check for model extraction protection
- [ ] Test model integrity verification
- [ ] Verify model access controls
- [ ] Check for model versioning

### Input Validation
- [ ] Test input size validation
- [ ] Check input range validation
- [ ] Test NaN/Inf detection
- [ ] Verify input sanitization
- [ ] Test malicious inputs

### Model Extraction
- [ ] Attempt to extract models from bundle
- [ ] Analyze model structure
- [ ] Check for hardcoded parameters
- [ ] Test model reverse engineering
- [ ] Verify model obfuscation

### Model Integrity
- [ ] Verify model hash checking
- [ ] Test for model tampering
- [ ] Check for poisoning detection
- [ ] Verify model signature
- [ ] Test model update mechanism

### Inference Security
- [ ] Test on-device inference
- [ ] Verify cloud inference encryption
- [ ] Check for data leakage
- [ ] Test certificate pinning
- [ ] Verify output validation

## OWASP MASTG References

- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
- **MASTG-TEST-0058**: Testing Memory Corruption Bugs
- **MASTG-TEST-0083**: Testing Binary Protection
- **MASTG-TEST-0084**: Testing the Binary (iOS)

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **netron**: Model visualization
- **coremltools**: Core ML model conversion
- **Xcode**: Model compilation
- **Core ML Tools**: Model analysis

### Reference Materials
- [Core ML Security](https://developer.apple.com/documentation/coreml/security)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [Core ML Documentation](https://developer.apple.com/documentation/coreml)
- [Machine Learning Security](https://www.usenix.org/conference/usenixsecurity19/presentation/tramer)
