# LINE FIDO2 SERVER

![Stars](https://img.shields.io/github/stars/line/line-fido2-server.svg?style=social)
![Repo Size](https://img.shields.io/github/repo-size/line/line-fido2-server)
![License Apache-2.0](https://img.shields.io/github/license/line/line-fido2-server)
![Top Language](https://img.shields.io/github/languages/top/line/line-fido2-server)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-2.7.12-green)
![Java version](https://img.shields.io/badge/Java-11-green)
![Data base](https://img.shields.io/badge/Storage-MySQL%2FH2%2FRedis-blue)
![Last Commit](https://img.shields.io/github/last-commit/line/line-fido2-server)

> **FIDO2(WebAuthn) Server officially certified by FIDO Alliance**

<img src="images/fido2_certificate.jpg" height="500" align="center" alt="FIDO2 Certificate"/>

## Overview

FIDO (Fast IDentity Online) is an open standard for online authentication, aiming to eliminate the vulnerabilities of
passwords. FIDO uses public-key cryptography instead of symmetric credentials like passwords or PINs.

In essence, the user's device generates a key pair, storing the private key securely and sharing the public key with the
server. During both registration and authentication, the server challenges the device, and the device responds with a
digital signature using the private key. The server then verifies this signature with the stored public key. This
challenge-response protocol helps prevent replay attacks.

### What is FIDO2?

FIDO2 is an enhancement of the FIDO standard for web and other platforms, supported by major web browsers and operating
systems. It encompasses two primary operations: Registration and Authentication.

#### Registration

- The user selects a FIDO authenticator that meets the service’s acceptance policy.
- The user unlocks the authenticator via fingerprint, PIN, or another method.
- A public/private key pair is generated; the public key is sent to the service and associated with the user’s account,
  while the private key remains on the device.
- The service challenges the device, which then creates a response using the private key to finish the registration
  process.

#### Authentication

- The service challenges the user to log in with a previously registered device.
- The user unlocks the authenticator using the same method as during registration.
- The device signs the service’s challenge and sends it back to the service.
- The service verifies the signature with the stored public key and grants access.

### Challenge-Response Protocol

Both the registration and authentication processes utilize a challenge-response protocol to prevent replay attacks.
During registration, a challenge is sent from the server to the device and the device responds using its private key.
Similarly, during authentication, another challenge is sent to verify the user's identity. This ensures that each
attempt is unique and secure.

## Screenshots

### Chrome on Mac with Touch ID

<img src="images/chrome_mac_touchid.gif" width="600" align="center" alt="Registration Flow"/>

## Modules

- **rp-server**:
    - RP Server Demo
    - Depends on **common**
- **common**:
    - Message classes that are commonly referenced by both the FIDO2 Server and the RP Server
- **core**:
    - Contains the core domain logic of FIDO
    - If the FIDO2 server being implemented does not interact with an RDB, this module alone should be used
    - Depends on **common**
- **base**:
    - Contains classes that depend on Spring JPA
        - Service Implement classes, Repository interfaces, Entity classes
    - Depends on **core**
- **demo**:
    - FIDO2 server demo application
    - Depends on **base**

## Features

- Supported attestation types:
    - Basic
    - Self
    - Attestation CA (Privacy CA)
    - None
    - Anonymization CA
- Supported attestation formats:
    - Packed
    - TPM
    - Android Key Attestation
    - Android SafetyNet
    - FIDO U2F
    - Apple Anonymous
    - None
- Metadata service integration:
    - FIDO MDSv3

## How to Run

### Manual Run

Start the RP Server and FIDO2 Server:

```bash
# Start RP Server
cd rpserver
./gradlew bootRun

# Start FIDO2 Server
cd fido2-demo/demo
./gradlew bootRun
```

### Docker for demo

If you have Docker configured, you can use docker-compose.

```bash
# Start both RP Server and FIDO2 Server
docker-compose up
```

Once the applications are running, access the test page at:

- http://localhost:8080/

### Local DB

The FIDO2 Server uses H2 as an embedded DB in a local environment, which should be replaced with a standalone DB (like
MySQL) for staging, beta, or production environments. Access the H2 web console at:

- http://localhost:8081/h2-console

### Issues

- If data.sql doesn't work well in an IntelliJ environment,
  try commenting on this part in build.gradle.

```groovy
jar {
    processResources {
        exclude("**/*.sql")
    }
}
```

## API Guides

### Spring REST Docs

To view the API documentation, follow these steps:

1. Execute the following commands:
   ```bash
   cd fido2-demo/demo
   ./gradlew makeRestDocs
   ./gradlew bootRun
    ```
2. Access the API documentation at the following path:

- server: http://localhost:8081/docs/api-guide.html

### Swagger UI

After running the applications, you can view API guide documents at the link below.

- rpserver: http://localhost:8080/swagger-ui.html
- server: http://localhost:8081/swagger-ui.html

## LINE WebAuthn Android and iOS

We are also providing Client SDK for Android/iOS applications. Please see below.

- [Introducing Fido2 Client SDK open source](https://techblog.lycorp.co.jp/ko/introducing-fido2-client-sdk-open-source)
- [LINE Webauthn Demo Kotlin](https://github.com/line/webauthndemo-kotlin)
- [LINE Webauthn Demo Swift](https://github.com/line/webauthndemo-swift)

### checkOrigin Configuration

The `checkOrigin` method validates the origin of requests. It supports both:

- App facet origins for LINE Android/iOS client SDKs (e.g., `android:...`, `ios:...`).
- Web origins for passkeys or browser-based WebAuthn (e.g., `https://example.com`).

How to Configure
Define allowed origins in the `application.yml` file. When web origins (`https://` or `http://`) are listed, they are
treated as an allowlist for web-origin verification (multi-origin supported). If no web origins are configured, the
server falls back to strict equality between the request-provided origin and the `clientDataJSON.origin`.

```yaml
app:
  origins:
    - android:aaa-bbb
    - ios:aaa-bbb
    # Optional: add one or more web origins to enforce an allowlist for web/passkey flows
    - https://example.com
    - https://staging.example.com
```

**Note:** Replace `aaa-bbb` with the appropriate values for your application.

**Important:**

- Facet origins (`android:`, `ios:`) apply to native app flows using LINE’s client SDKs.
    - https://github.com/line/webauthn-swift
    - https://github.com/line/webauthn-kotlin
- Web origins (`https://`, `http://`) apply to browser/passkey flows across platforms (iOS, Android, Windows, macOS).
- If no web origins are configured, verification requires the request origin to exactly match `clientDataJSON.origin`.
- Android native (FIDO2 API/Credential Manager): `clientDataJSON.origin` starts with `android:...` (app facet). See "
  Verify origin" in Android Credential Manager
  docs: https://developer.android.com/identity/sign-in/credential-manager#verify-origin
- iOS native (AuthenticationServices, passkeys): `clientDataJSON.origin` is an `https` web origin (no `ios:` prefix),
  e.g., `https://example.com`. For iOS/macOS passkeys, configure a web-origin allowlist.
- When web origins are configured, the allowlist takes precedence: RP request fields like `VerifyCredential.origin` and
  `RegisterCredential.origin` do not govern the check; the server validates against the configured web-origin allowlist.

## References

`LY Engineering Blogs`

- [FIDO at LINE: A First Step to a World Without Passwords](https://engineering.linecorp.com/en/blog/fido-at-line/)
- [FIDO at LINE: FIDO2 server as an open-source project](https://engineering.linecorp.com/en/blog/fido-at-line-fido2-server-opensource/)
- [Introducing Fido2 Client SDK open source](https://techblog.lycorp.co.jp/ko/introducing-fido2-client-sdk-open-source)

`LY Tech Videos`

- [Open source contribution Starting with LINE FIDO2 Server](https://youtu.be/xKzXi5ic4Do)
- [Strong customer authentication & biometrics using FIDO](https://youtu.be/S1y9wFh7_dc)
- [Cross Platform Mobile Security At LINE](https://youtu.be/4288h-EamTU)
- [Secure LINE login with biometric key replacing password](https://youtu.be/vCAu-y-iwyw)

`Internal`

- [Sequence Diagram](https://github.com/line/line-fido2-server/wiki/Sequence-diagrams)
