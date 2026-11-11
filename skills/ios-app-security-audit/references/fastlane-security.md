# Fastlane Security Audit

Fastlane is an iOS automation tool that streamlines deployment. However, misconfigured Fastlane can introduce security vulnerabilities including sensitive data exposure, certificate management issues, and environment variable mishandling.

**MASTG References:**
- MASTG-TEST-0002: Identify Development and Security Protections
- MASTG-TEST-0083: Testing Binary Protection

## 1. Lane Exploitation Risk

### Vulnerable Fastfile

```ruby
# Fastfile with security issues

default_platform(:ios)

platform :ios do
  desc "Build and upload to TestFlight"
  lane :beta do
    # VULNERABLE: No input validation
    increment_build_number

    # VULNERABLE: Hardcoded credentials
    match(
      type: "appstore",
      readonly: true,
      git_url: "https://github.com/private/certificates.git",
      git_basic_authorization: Base64.strict_encode64("user:hardcoded_password")
    )

    # VULNERABLE: No code signing verification
    build_app(
      scheme: "MyApp",
      export_method: "app-store",
      export_options: {
        provisioningProfiles: {
          "com.example.app" => "profile.mobileprovision"
        }
      }
    )

    # VULNERABLE: No upload verification
    upload_to_testflight(
      skip_waiting_for_build_processing: true
    )
  end
end
```

### Secure Fastfile

```ruby
# Secure Fastfile

default_platform(:ios)

platform :ios do
  desc "Build and upload to TestFlight"
  lane :beta do
    # Validate environment
    ensure_git_status_clean
    ensure_git_branch(branch: 'main')

    # Use environment variables for credentials
    match(
      type: "appstore",
      readonly: true,
      git_url: ENV['MATCH_GIT_URL'],
      git_basic_authorization: ENV['MATCH_AUTHORIZATION'],
      app_identifier: ENV['APP_IDENTIFIER']
    )

    # Verify code signing
    verify_code_signing

    # Build with verification
    build_app(
      scheme: ENV['APP_SCHEME'],
      export_method: "app-store",
      export_options: {
        provisioningProfiles: {
          ENV['APP_IDENTIFIER'] => ENV['PROVISIONING_PROFILE']
        }
      },
      clean: true
    )

    # Upload with verification
    upload_to_testflight(
      skip_waiting_for_build_processing: false,
      skip_submission: false
    )
  end

  desc "Verify code signing"
  private_lane :verify_code_signing do
    # Verify certificates
    cert(
      development: false,
      output_path: "./certificates"
    )

    # Verify provisioning profiles
    sigh(
      development: false,
      output_path: "./profiles"
    )
  end
end

# Ensure Git status is clean
def ensure_git_status_clean
  status = Action.sh("git status --porcelain", log: false)
  if !status.empty?
    UI.user_error!("Git working directory is not clean. Please commit or stash your changes.")
  end
end

# Ensure on correct branch
def ensure_git_branch(branch:)
  current_branch = Action.sh("git rev-parse --abbrev-ref HEAD", log: false).strip
  if current_branch != branch
    UI.user_error!("Not on #{branch} branch. Current branch: #{current_branch}")
  end
end
```
