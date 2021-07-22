
<img src="images/fido2_certificate.jpg" height="500" align="center" alt=""/>

## Overview

FIDO (Fast IDentity Online) is open standard for online authentication. It is designed for solving the password problems which is stems from a lot of security problems as we are suffering today.

Rather than relying on symmetric credentials (like password or pin, typically which is knowledge based factor), FIDO is based on public key cryptography algorithm which is based on asymmetric credentials.

Simply, the device generates the key pair and stores the private key within the secure area and send corresponding public key (as the name implies it is okay to be public) to the server.

Then, if the authentication is needed, the server sends challenges to the device and the device generates the digital signature with the private key and send it to the server.

Finally, the server can validate the signature with the registered public key.

### What is FIDO2
FIDO2 is an improved standard for use on the web and other platforms as well as mobile. Various web browsers and OS platforms currently support the FIDO2 standard API.

Basically, FIDO2 has following operations - Registration, Authentication.

#### Registration
- User is prompted to choose an available FIDO authenticator that matches the online service’s acceptance policy.
- User unlocks the FIDO authenticator using a fingerprint reader, a button on a second–factor device, securely–entered PIN or other method.
- User’s device creates a new public/private key pair unique for the local device, online service and user’s account.
- Public key is sent to the online service and associated with the user’s account. The private key and any information about the local authentication method (such as biometric measurements or templates) never leave the local device.

#### Authentication
- Online service challenges the user to login with a previously registered device that matches the service’s acceptance policy.
- User unlocks the FIDO authenticator using the same method as at Registration time.
- Device uses the user’s account identifier provided by the service to select the correct key and sign the service’s challenge.
- Client device sends the signed challenge back to the service, which verifies it with the stored public key and logs in the user.

      
## Screenshots
### Chrome on Mac with TouchId
<img src="images/chrome_mac_touchid.gif" height="500" align="center" alt="registration_flow"/>

### Chrome on Mac with Secret Key (2FA)
<img src="images/chrome_mac_secretkey.gif" height="500" align="center" alt="registration_flow"/>

### Chrome on Android with Fingerprint (Reg)
<img src="images/chrome_android_fingerprint_reg.GIF" height="500" align="center" alt="registration_flow"/>

### Chrome on Android with Fingerprint (Auth)
<img src="images/chrome_android_fingerprint_auth.GIF" height="500" align="center" alt="registration_flow"/>

## Modules
- common: fido2 related common models
- rp-server: simple rp server implementation
- server: fido2 server
- spring-boot-stater: Fido2 server wrapped in a spring boot starter

## Features
- Supported browsers (Supported authenticators and interfaces may be different depending on the current browsers implementations)
   - Chrome
   - Opera (inherited from Chrome)
   - Firefox
   - MS Edge (Windows 10 /w 2018 October Update)
   - MS Edge on Chromium
   - Safari
- Supported authenticators (Platforms and externals)
   - Any FIDO2 authenticators and U2F authenticators with None attestation
- Signature algorithms
   - RS1 (RSASSA-PKCS1-v1_5 w/ SHA-1)
   - RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
   - RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)
   - RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)
   - PS256 (RSASSA-PSS w/ SHA-256)
   - PS384 (RSASSA-PSS w/ SHA-384)
   - PS512 (RSASSA-PSS w/ SHA-512)
   - EDDSA (EdDSA)
   - ES256 (ECDSA w/ SHA-256)
   - ES384 (ECDSA w/ SHA-384)
   - ES512 (ECDSA w/ SHA-512)
   - ES256K (ECDSA using P-256K and SHA-256)
- Supported attestation types
   - Basic
   - Self
   - Attestation CA (a.k.a Privacy CA)
   - None
   - Anonymization CA
- Supported attestation formats
   - Packed (FIDO2)
   - Tpm (Windows10 devices)
   - Android key attestation
   - Android safetynet (Any Android devices running 7+)
   - FIDO U2F (Legacy U2F authenticators)
   - Apple Anonymous
   - None
- Metadata service integration
   - FIDO MDSv2
- Supported extensions
   - credProps
   - credProtect

## How to play with
You need to run FIDO2 server and RP Server first.

If you want to integrate your own RP Server, please implement APIs by referring the sample codes. Regarding client sides, you may implement the web app for communicating with RP server.

## Local DB
FIDO2 Server running on local environments uses h2 as an embedded DB. For other environments such as stg, beta or real, this need to be replaced with commercial standalone DB.

In case of local environment, you can use h2 console. Add following path /h2-console to the fido server url to access h2 web console.

e.g., http://localhost:8081/h2-console

## Spring Boot Starter
We also provide our server in the form of spring boot starter.

Check out the spring-boot-starter directory.

## How to run
```bash
# Start RP Server
cd rpserver
./gradlew bootRun

# Start FIDO2 Server or Line-fido2-spring-boot Demo
cd server
./gradlew bootRun

cd spring-boot-starter/line-fido2-spring-boot-demo
./gradlew bootRun
```

## Issues
- If data.sql doesn't work well in an IntelliJ environment,
  try commenting on this part in build.gradle.
```groovy
jar {
  processResources {
    exclude("**/*.sql")
  }
}
```

## Lombok
This project utilizes Lombok to reduce implementing getter/setter/constructors. You need lombok plugin to build with IntelliJ and Eclipse.
See following web pages to get information.

https://projectlombok.org/
