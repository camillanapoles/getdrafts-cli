# SwiftUI Security Deep Dive

SwiftUI is Apple's modern declarative UI framework for iOS. While it simplifies UI development, it introduces unique security considerations that require specialized testing approaches.

## Architecture Overview

### SwiftUI State Management

```
View
   ↓
@State / @StateObject
   ↓
Binding
   ↓
Environment Values
   ↓
ObservableObject
```

**MASTG References:**
- MASTG-TEST-0038: Local Data Storage Analysis
- MASTG-TEST-0046: Testing for Local Storage
- MASTG-TEST-0056: Testing Code Quality and Code Construction Issues
- MASTG-TEST-0057: Testing Code Quality (iOS)

## 1. @State/@StateObject Exposure

### Vulnerability: Exposed State in Views

```swift
// Vulnerable SwiftUI view
import SwiftUI

struct VulnerableLoginView: View {
    // VULNERABLE: @State exposes sensitive data to debugger
    @State private var username = ""
    @State private var password = ""  // NEVER store password in @State
    @State private var authToken = ""
    @State private var apiKeys: [String] = []

    var body: some View {
        VStack {
            TextField("Username", text: $username)
            SecureField("Password", text: $password)

            Button("Login") {
                login()
            }
        }
    }

    func login() {
        // API call to authenticate
        // ...
    }
}
```

### Detection with Frida

```javascript
// Monitor SwiftUI state changes
if (ObjC.available) {
    try {
        // SwiftUI uses property wrappers internally
        // State is managed through _StateObject

        const StateObject = ObjC.classes._StateObject;

        if (StateObject) {
            console.log("[+] SwiftUI State Detected");

            // Hook state storage
            Interceptor.attach(StateObject['- initProjectedValue'].implementation, {
                onEnter: function(args) {
                    console.log("[+] State object initialized");
                }
            });
        }

        // Monitor @Published properties
        // ObservableObject uses KVO (Key-Value Observing)
        const ObservableObject = ObjC.classes.ObservableObject;

        if (ObservableObject) {
            console.log("[+] ObservableObject detected");

            // Hook KVO notifications
            const didChangeValueForKey = ObjC.classes.NSObject['- didChangeValueForKey:'];
            Interceptor.attach(didChangeValueForKey.implementation, {
                onEnter: function(args) {
                    const key = new ObjC.Object(args[2]).toString();

                    // Check for sensitive keys
                    const sensitive = ['password', 'token', 'api', 'secret', 'credential'];
                    if (sensitive.some(s => key.toLowerCase().includes(s))) {
                        console.log(`[!] Sensitive state changed: ${key}`);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[-] Error monitoring SwiftUI: " + e);
    }
}
```

### Secure State Management

```swift
// Secure SwiftUI view
import SwiftUI
import LocalAuthentication

struct SecureLoginView: View {
    @State private var username = ""
    @State private var password = ""  // Only for UI input, clear after use
    @State private var showLoginError = false
    @State private var errorMessage = ""

    @ObservedObject private var authManager = AuthManager.shared

    var body: some View {
        VStack {
            TextField("Username", text: $username)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()

            SecureField("Password", text: $password)

            Button("Login") {
                login()
            }

            if showLoginError {
                Text(errorMessage)
                    .foregroundColor(.red)
            }
        }
        .onDisappear {
            // Clear sensitive data when view disappears
            clearSensitiveData()
        }
    }

    func login() {
        // Validate input
        guard !username.isEmpty, !password.isEmpty else {
            showError("Please enter username and password")
            return
        }

        // Perform authentication
        authManager.authenticate(username: username, password: password) { result in
            switch result {
            case .success:
                // Authentication successful
                clearSensitiveData()
            case .failure(let error):
                showError(error.localizedDescription)
                clearSensitiveData()
            }
        }
    }

    private func showError(_ message: String) {
        errorMessage = message
        showLoginError = true
    }

    private func clearSensitiveData() {
        // Clear password immediately after use
        password = ""
    }
}

// Secure authentication manager
class AuthManager: ObservableObject {
    static let shared = AuthManager()

    @Published private(set) var isAuthenticated = false
    @Published private(set) var username = ""

    private let keychain = KeychainManager.shared

    private init() {}

    func authenticate(username: String, password: String, completion: @escaping (Result<Void, Error>) -> Void) {
        // Perform secure authentication
        // Use network request with proper TLS
        // Store token securely in Keychain

        // Example: Store auth token
        keychain.save(key: "auth_token", value: "generated_token_here")

        // Never store password
        DispatchQueue.main.async {
            self.username = username
            self.isAuthenticated = true
            completion(.success(()))
        }
    }

    func logout() {
        // Clear sensitive data
        keychain.delete(key: "auth_token")
        username = ""
        isAuthenticated = false
    }
}

// Secure Keychain manager
class KeychainManager {
    static let shared = KeychainManager()

    private init() {}

    func save(key: String, value: String) {
        let data = value.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]

        SecItemAdd(query as CFDictionary, nil)
    }

    func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        SecItemCopyMatching(query as CFDictionary, &result)

        if let data = result as? Data {
            return String(data: data, encoding: .utf8)
        }

        return nil
    }

    func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]

        SecItemDelete(query as CFDictionary)
    }
}
```

## 2. Environment Values

### Vulnerability: Exposed Environment Values

```swift
// Vulnerable usage of environment values
struct VulnerableView: View {
    @Environment(\.horizontalSizeClass) var horizontalSizeClass
    @Environment(\.verticalSizeClass) var verticalSizeClass
    @Environment(\.colorScheme) var colorScheme

    // VULNERABLE: Exposing sensitive environment values
    @Environment(\.managedObjectContext) var viewContext

    var body: some View {
        Text("Size: \(horizontalSizeClass.description)")
            .onAppear {
                // Environment values can be inspected
                print(viewContext.debugDescription)  // Exposes data
            }
    }
}
```

### Secure Environment Value Usage

```swift
// Secure usage of environment values
struct SecureView: View {
    @Environment(\.horizontalSizeClass) var horizontalSizeClass
    @Environment(\.verticalSizeClass) var verticalSizeClass
    @Environment(\.colorScheme) var colorScheme
    @Environment(\.scenePhase) var scenePhase

    // Secure: Don't expose sensitive environment values
    // Use them only for UI logic

    var body: some View {
        VStack {
            Text("Adaptive Layout")

            if horizontalSizeClass == .compact {
                CompactLayout()
            } else {
                RegularLayout()
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            handleScenePhaseChange(newPhase)
        }
    }

    private func handleScenePhaseChange(_ phase: ScenePhase) {
        switch phase {
        case .active:
            // App became active - resume operations
            break
        case .inactive:
            // App became inactive - pause operations
            break
        case .background:
            // App entered background - clear sensitive data
            clearSensitiveData()
        @unknown default:
            break
        }
    }

    private func clearSensitiveData() {
        // Clear sensitive data when app goes to background
        // ...
    }
}
```

## 3. Navigation Security

### Vulnerability: Navigation Parameter Exposure

```swift
// Vulnerable navigation
struct VulnerableContentView: View {
    var body: some View {
        NavigationStack {
            List {
                NavigationLink("View User", value: user.id)  // VULNERABLE: Exposes user ID
                NavigationLink("View Profile", value: user.token)  // VULNERABLE: Exposes token
            }
            .navigationDestination(for: String.self) { id in
                DetailView(id: id)  // No validation
            }
        }
    }
}
```

### Secure Navigation

```swift
// Secure navigation
struct SecureContentView: View {
    @State private var selectedUser: User?
    @State private var path = NavigationPath()

    var body: some View {
        NavigationStack(path: $path) {
            List(users) { user in
                Button {
                    // Validate before navigation
                    if canNavigateToUser(user) {
                        selectedUser = user
                        path.append(user.id)
                    }
                } label: {
                    UserRow(user: user)
                }
            }
            .navigationDestination(for: String.self) { userId in
                if let user = findUser(id: userId) {
                    SecureDetailView(user: user)
                } else {
                    Text("User not found")
                }
            }
        }
    }

    private func canNavigateToUser(_ user: User) -> Bool {
        // Validate navigation
        return user.isAccessible
    }

    private func findUser(id: String) -> User? {
        // Secure lookup with validation
        return users.first { $0.id == id }
    }
}

struct SecureDetailView: View {
    let user: User
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack {
            Text(user.name)

            Button("Close") {
                dismiss()
            }
        }
        .onDisappear {
            // Clear sensitive data
        }
    }
}
```

## 4. Sheet/fullScreenCover Injection

### Vulnerability: Sheet Parameter Injection

```swift
// Vulnerable sheet presentation
struct VulnerableView: View {
    @State private var showSheet = false
    @State private var sheetData: SheetData?

    var body: some View {
        Button("Show Sheet") {
            // VULNERABLE: No validation of sheet data
            sheetData = loadSheetData(from: userSuppliedUrl)
            showSheet = true
        }
        .sheet(isPresented: $showSheet) {
            if let data = sheetData {
                SheetView(data: data)  // No validation
            }
        }
    }

    func loadSheetData(from url: String) -> SheetData? {
        // VULNERABLE: Loads from arbitrary URL
        guard let url = URL(string: url) else { return nil }
        return try? JSONDecoder().decode(SheetData.self, from: Data(contentsOf: url))
    }
}
```

### Secure Sheet Presentation

```swift
// Secure sheet presentation
struct SecureView: View {
    @State private var showSheet = false
    @State private var sheetData: SheetData?

    var body: some View {
        Button("Show Sheet") {
            if let url = validatedSheetUrl {
                loadSheetData(from: url)
            }
        }
        .sheet(isPresented: $showSheet) {
            if let data = sheetData {
                SheetView(data: data)
            }
        }
    }

    private var validatedSheetUrl: URL? {
        // Validate URL before loading
        let allowedHosts = ["api.example.com", "cdn.example.com"]

        guard let urlString = userSuppliedUrl,
              let url = URL(string: urlString),
              let host = url.host,
              allowedHosts.contains(host) else {
            return nil
        }

        return url
    }

    private func loadSheetData(from url: URL) {
        Task {
            do {
                let (data, response) = try await URLSession.shared.data(from: url)

                // Validate response
                guard let httpResponse = response as? HTTPURLResponse,
                      httpResponse.statusCode == 200 else {
                    return
                }

                // Validate data
                let decoder = JSONDecoder()
                decoder.keyDecodingStrategy = .convertFromSnakeCase

                let decodedData = try decoder.decode(SheetData.self, from: data)

                // Additional validation
                guard isValidSheetData(decodedData) else {
                    return
                }

                await MainActor.run {
                    sheetData = decodedData
                    showSheet = true
                }
            } catch {
                print("Error loading sheet data: \(error)")
            }
        }
    }

    private func isValidSheetData(_ data: SheetData) -> Bool {
        // Implement validation logic
        // Check for malicious content, scripts, etc.
        return true
    }
}
```

## 5. ObservableObject Data Leaks

### Vulnerability: Published Sensitive Data

```swift
// Vulnerable ObservableObject
class VulnerableAuthManager: ObservableObject {
    @Published var username = ""
    @Published var password = ""  // VULNERABLE: Published password
    @Published var authToken = ""
    @Published var apiKeys: [String] = []

    @Published var creditCardNumber = ""  // VULNERABLE: Published credit card
    @Published var ssn = ""  // VULNERABLE: Published SSN
}
```

### Secure ObservableObject

```swift
// Secure ObservableObject
class SecureAuthManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var username = ""

    // Private: Not published
    private var authToken: String? {
        didSet {
            isAuthenticated = authToken != nil
        }
    }

    // Never publish sensitive data
    private var password: String?

    private let keychain = KeychainManager.shared

    static let shared = SecureAuthManager()

    private init() {}

    func authenticate(username: String, password: String, completion: @escaping (Result<Void, Error>) -> Void) {
        // Validate inputs
        guard !username.isEmpty, !password.isEmpty else {
            completion(.failure(AuthError.invalidCredentials))
            return
        }

        // Perform authentication
        Task {
            do {
                let token = try await performAuthentication(username: username, password: password)

                await MainActor.run {
                    self.authToken = token
                    self.username = username
                    // Clear password immediately
                    self.password = nil
                    completion(.success(()))
                }
            } catch {
                await MainActor.run {
                    self.password = nil
                    completion(.failure(error))
                }
            }
        }
    }

    private func performAuthentication(username: String, password: String) async throws -> String {
        // Secure authentication implementation
        // Use TLS, certificate pinning, etc.

        // Store token securely
        let token = "generated_token"

        keychain.save(key: "auth_token", value: token)

        return token
    }

    func getAuthToken() -> String? {
        return keychain.load(key: "auth_token")
    }

    func logout() {
        authToken = nil
        username = ""
        isAuthenticated = false

        // Clear Keychain
        keychain.delete(key: "auth_token")
    }
}

enum AuthError: LocalizedError {
    case invalidCredentials
    case networkError
    case unauthorized

    var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "Invalid username or password"
        case .networkError:
            return "Network error occurred"
        case .unauthorized:
            return "Unauthorized access"
        }
    }
}
```

## Testing Checklist

### State Management
- [ ] Review @State usage for sensitive data
- [ ] Check @StateObject for exposed secrets
- [ ] Test state persistence
- [ ] Verify state cleanup on view disappear
- [ ] Check for memory leaks

### Environment Values
- [ ] Identify exposed environment values
- [ ] Validate environment value usage
- [ ] Check for sensitive data in environment
- [ ] Test environment value changes
- [ ] Verify proper cleanup

### Navigation Security
- [ ] Test navigation parameter validation
- [ ] Check for exposed IDs in navigation
- [ ] Verify navigation path sanitization
- [ ] Test deep link handling
- [ ] Check for navigation injection

### Sheet/Modal Security
- [ ] Validate sheet data sources
- [ ] Test sheet parameter injection
- [ ] Check for malicious content in sheets
- [ ] Verify sheet dismissal security
- [ ] Test fullScreenCover security

### ObservableObject Security
- [ ] Review @Published properties
- [ ] Check for sensitive data in published properties
- [ ] Test object lifecycle
- [ ] Verify proper cleanup
- [ ] Check for data leaks

### Data Binding Security
- [ ] Test @Binding for exposed data
- [ ] Verify binding validation
- [ ] Check for injection attacks
- [ ] Test binding updates
- [ ] Verify error handling

## OWASP MASTG References

- **MASTG-TEST-0038**: Local Data Storage Analysis
- **MASTG-TEST-0046**: Testing for Local Storage
- **MASTG-TEST-0056**: Testing Code Quality and Code Construction Issues
- **MASTG-TEST-0057**: Testing Code Quality (iOS)
- **MASTG-TEST-0058**: Testing Memory Corruption Bugs
- **MASTG-TEST-0083**: Testing Binary Protection

## Tools and Resources

### Analysis Tools
- **Frida**: Runtime instrumentation
- **Xcode Instruments**: Memory profiling
- **SwiftLint**: Code analysis
- **Mint**: Swift package manager
- **SwiftFormat**: Code formatting

### Reference Materials
- [SwiftUI Security Best Practices](https://developer.apple.com/documentation/swiftui/security)
- [OWASP MASTG](https://github.com/OWASP/MASTG)
- [SwiftUI Documentation](https://developer.apple.com/documentation/swiftui)
- [SwiftUI by Tutorials](https://www.raywenderlich.com/books/swiftui-by-tutorials)
