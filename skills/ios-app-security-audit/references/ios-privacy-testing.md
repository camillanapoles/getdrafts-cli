# iOS Privacy Testing

iOS privacy testing focuses on verifying privacy manifests, App Tracking Transparency compliance, data collection analysis, and permission usage verification.

**MASTG References:**
- MASTG-TEST-0060: Testing for Privacy Concerns
- MASTG-TEST-0061: Testing for Data Privacy

## 1. Privacy Manifests

### Privacy Manifest Location

```
MyApp.app/
└── PrivacyInfo.xcprivacy
```

### Privacy Manifest Analysis

```bash
#!/bin/bash
# analyze_privacy_manifest.sh

APP_PATH=$1

if [ -z "$APP_PATH" ]; then
    echo "Usage: $0 <app_path>"
    exit 1
fi

PRIVACY_MANIFEST="$APP_PATH/PrivacyInfo.xcprivacy"

if [ ! -f "$PRIVACY_MANIFEST" ]; then
    echo "[-] Privacy manifest not found"
    exit 1
fi

echo "[+] Found Privacy Manifest: $PRIVACY_MANIFEST"

# Convert to XML
plutil -convert xml1 -o "$PRIVACY_MANIFEST.xml" "$PRIVACY_MANIFEST"

# Parse to text
plutil -p "$PRIVACY_MANIFEST" > "$PRIVACY_MANIFEST.parsed.txt"

# Check for required fields
echo "[*] Checking required fields:"

if plutil -p "$PRIVACY_MANIFEST" | grep -q "NSPrivacyTracking"; then
    echo "  [+] NSPrivacyTracking: Present"
    TRACKING=$(plutil -p "$PRIVACY_MANIFEST" | grep "NSPrivacyTracking" | sed 's/.*=\(.*\);/\1/')
    echo "      Value: $TRACKING"
else
    echo "  [-] NSPrivacyTracking: Missing"
fi

if plutil -p "$PRIVACY_MANIFEST" | grep -q "NSPrivacyCollectedDataTypes"; then
    echo "  [+] NSPrivacyCollectedDataTypes: Present"
else
    echo "  [-] NSPrivacyCollectedDataTypes: Missing"
fi

if plutil -p "$PRIVACY_MANIFEST" | grep -q "NSPrivacyAccessedAPITypes"; then
    echo "  [+] NSPrivacyAccessedAPITypes: Present"
else
    echo "  [-] NSPrivacyAccessedAPITypes: Missing"
fi
```

### Privacy Manifest Validation

```xml
<!-- PrivacyInfo.xcprivacy Example -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>NSPrivacyTracking</key>
    <false/>

    <key>NSPrivacyCollectedDataTypes</key>
    <array>
        <dict>
            <key>NSPrivacyCollectedDataType</key>
            <string>NSPrivacyCollectedDataTypeIdentifierForVendors</string>
            <key>NSPrivacyCollectedDataTypeLinked</key>
            <false/>
            <key>NSPrivacyCollectedDataTypeTracking</key>
            <false/>
            <key>NSPrivacyCollectedDataTypePurposes</key>
            <array>
                <string>NSPrivacyCollectedDataTypePurposeAnalytics</string>
            </array>
        </dict>
    </array>

    <key>NSPrivacyAccessedAPITypes</key>
    <array>
        <dict>
            <key>NSPrivacyAccessedAPIType</key>
            <string>NSPrivacyAccessedAPICategoryDiskSpace</string>
            <key>NSPrivacyAccessedAPITypeReasons</key>
            <array>
                <string>CA92.1</string>
            </array>
        </dict>
    </array>
</dict>
</plist>
```

## 2. App Tracking Transparency

### Testing ATT Implementation

```javascript
// Frida script to test ATT
if (ObjC.available) {
    try {
        const ATTrackingManager = ObjC.classes.ATTrackingManager;

        if (ATTrackingManager) {
            console.log("[+] ATTrackingManager detected");

            // Hook trackingAuthorizationStatus
            const trackingAuthorizationStatus = ATTrackingManager['+ trackingAuthorizationStatus'];
            Interceptor.attach(trackingAuthorizationStatus.implementation, {
                onLeave: function(retval) {
                    const status = retval.toInt32();
                    console.log("[+] Tracking authorization status: " + status);

                    const statusNames = [
                        "Not Determined",
                        "Restricted",
                        "Denied",
                        "Authorized"
                    ];

                    if (status >= 0 && status < statusNames.length) {
                        console.log("    " + statusNames[status]);
                    }
                }
            });

            // Hook requestTrackingAuthorization
            const requestTracking = ATTrackingManager['+ requestTrackingAuthorizationWithCompletionHandler:'];
            Interceptor.attach(requestTracking.implementation, {
                onEnter: function(args) {
                    console.log("[+] requestTrackingAuthorization called");
                },
                onLeave: function(retval) {
                    console.log("    Request completed");
                }
            });
        }
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### ATT Compliance Checklist

- [ ] Privacy manifest declares NSPrivacyTracking
- [ ] App Tracking Transparency prompt shown
- [ ] Proper status handling
- [ ] Graceful degradation when denied
- [ ] Clear explanation of tracking purpose

## 3. Data Collection Analysis

### Frida Data Collection Monitor

```javascript
// Monitor data collection
if (ObjC.available) {
    try {
        // Hook UserDefaults
        const NSUserDefaults = ObjC.classes.NSUserDefaults;
        const standardUserDefaults = NSUserDefaults.standardUserDefaults();

        const setObject = standardUserDefaults['- setObject:forKey:'];
        Interceptor.attach(setObject.implementation, {
            onEnter: function(args) {
                const key = new ObjC.Object(args[3]).toString();

                // Check for sensitive data
                const sensitive = ['email', 'phone', 'address', 'name', 'id'];
                if (sensitive.some(s => key.toLowerCase().includes(s))) {
                    console.log("[!] Collected sensitive data: " + key);
                }
            }
        });

        // Hook Keychain
        const SecItemAdd = Module.findGlobalExportByName('SecItemAdd');
        Interceptor.attach(SecItemAdd, {
            onEnter: function(args) {
                const query = new ObjC.Object(args[0]);

                try {
                    const account = query.objectForKey_("kSecAttrAccount");
                    if (account && !account.isNull()) {
                        console.log("[+] Keychain write: " + account.toString());
                    }
                } catch (e) {}
            }
        });

        // Hook URL requests
        const NSURLSession = ObjC.classes.NSURLSession;
        const dataTask = NSURLSession['- dataTaskWithRequest:completionHandler:'];

        Interceptor.attach(dataTask.implementation, {
            onEnter: function(args) {
                const request = new ObjC.Object(args[2]);
                const url = request['- URL']().toString();

                // Check for tracking domains
                const trackingDomains = ['analytics.', 'tracking.', 'ads.'];
                if (trackingDomains.some(d => url.includes(d))) {
                    console.log("[!] Tracking request: " + url);
                }
            }
        });

        console.log("[+] Data collection monitoring installed");
    } catch (e) {
        console.log("[-] Error: " + e);
    }
}
```

### Data Collection Checklist

- [ ] Identify all data collection points
- [ ] Verify necessity of collected data
- [ ] Check for data minimization
- [ ] Verify consent mechanism
- [ ] Review data retention policy

## 4. Permission Usage Verification

### Info.plist Permissions Analysis

```bash
#!/bin/bash
# analyze_permissions.sh

INFO_PLIST=$1

if [ -z "$INFO_PLIST" ]; then
    echo "Usage: $0 <Info.plist>"
    exit 1
fi

echo "[*] Analyzing permissions in: $INFO_PLIST"

# List all permissions
echo "[*] Declared permissions:"

PERMISSIONS=(
    "NSCameraUsageDescription"
    "NSMicrophoneUsageDescription"
    "NSPhotoLibraryUsageDescription"
    "NSLocationWhenInUseUsageDescription"
    "NSLocationAlwaysAndWhenInUseUsageDescription"
    "NSContactsUsageDescription"
    "NSCalendarsUsageDescription"
    "NSRemindersUsageDescription"
    "NSFaceIDUsageDescription"
    "NSBluetoothAlwaysUsageDescription"
    "NSBluetoothPeripheralUsageDescription"
)

for perm in "${PERMISSIONS[@]}"; do
    if plutil -p "$INFO_PLIST" | grep -q "$perm"; then
        DESCRIPTION=$(plutil -p "$INFO_PLIST" | grep "$perm" | sed 's/.*"\(.*\)".*/\1/')
        echo "  [+] $perm"
        echo "      $DESCRIPTION"
    fi
done
```

### Runtime Permission Testing

```swift
// Test permission usage
import Foundation
import AVFoundation
import Photos
import CoreLocation

class PermissionTester {
    static let shared = PermissionTester()

    private init() {}

    func checkPermissions() {
        // Camera
        let cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
        print("Camera: \(cameraStatus.rawValue)")

        // Photo Library
        let photoStatus = PHPhotoLibrary.authorizationStatus()
        print("Photos: \(photoStatus.rawValue)")

        // Location
        let locationManager = CLLocationManager()
        let locationStatus = locationManager.authorizationStatus
        print("Location: \(locationStatus.rawValue)")
    }

    func requestPermissions() {
        // Request camera permission
        AVCaptureDevice.requestAccess(for: .video) { granted in
            print("Camera granted: \(granted)")
        }

        // Request photo library permission
        PHPhotoLibrary.requestAuthorization { status in
            print("Photos status: \(status.rawValue)")
        }
    }
}
```

## Testing Checklist

### Privacy Manifests
- [ ] Verify PrivacyInfo.xcprivacy exists
- [ ] Check NSPrivacyTracking value
- [ ] Verify NSPrivacyCollectedDataTypes
- [ ] Check NSPrivacyAccessedAPITypes
- [ ] Verify reason codes

### App Tracking Transparency
- [ ] Verify ATT implementation
- [ ] Test tracking status
- [ ] Check for prompt display
- [ ] Verify graceful handling
- [ ] Test denial scenario

### Data Collection
- [ ] Identify collection points
- [ ] Verify data minimization
- [ ] Check for consent
- [ ] Verify encryption
- [ ] Review retention policy

### Permissions
- [ ] Verify declared permissions
- [ ] Check descriptions
- [ ] Test permission requests
- [ ] Verify necessity
- [ ] Check for unnecessary permissions

## OWASP MASTG References

- **MASTG-TEST-0060**: Testing for Privacy Concerns
- **MASTG-TEST-0061**: Testing for Data Privacy
