# go-ctap

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctap.svg)](https://pkg.go.dev/github.com/go-ctap/ctap)
[![Go](https://github.com/go-ctap/ctap/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctap/actions/workflows/go.yml)

go-ctap is an idiomatic Go library for interacting with FIDO2 authenticators using CTAP.
It exposes several abstraction levels, from raw CTAPHID transport framing to ergonomic authenticator workflows.

> [!WARNING]
> Work in progress! API may change during `v0.x`!

## Current Status

Library supports almost entire CTAP 2.2 specification, except few extensions which are not yet seen in the wild
(`hmac-secret-mc`, dedicated `largeBlob`, not to be confused with `largeBlobKey` which is supported).

My current priorities are to write better tests and completely replace [sstallion/go-hid](https://github.com/sstallion/go-hid)
with the [go-ctap/hid](https://github.com/go-ctap/hid) `cgo`-free alternative.

## Key Features and Architecture

The library exposes several abstraction levels, allowing you to choose the API that best suits your needs:

1. **Transport Layer (`transport/ctaphid`)**

   Direct access to the raw CTAPHID transport protocol. If you need maximum control, you can communicate with devices
   at the frame level.

2. **Client Layer (`client`)**

   Implements CTAP command messaging atop the transport, letting you call authenticator commands while still managing
   the device handle, channel ID, PIN/UV auth tokens, and command inputs yourself.

3. **Authenticator Layer (`authenticator`)**

   Provides a convenient wrapper over the `client` package, managing the HID device descriptor, channel ID (CID),
   cached authenticator info, and common CTAP flows.

4. **Discovery Helpers (`discover`)**

   A set of helpers for finding and selecting authenticators, including user-presence based selection when
   several authenticators are connected.

5. **Crypto Helpers (`crypto`)**

   Public helpers for CTAP-specific cryptography, including PIN/UV Auth Protocol One and Two, and LargeBlob
   encryption/decryption. The lower-level `crypto/protocolone` and `crypto/protocoltwo` packages are available for
   callers that need direct access to the protocol primitives.

6. **Types (`ctaptypes`, `webauthntypes`)**

   Shared CTAP and WebAuthn data structures used across the lower-level and higher-level APIs.

## Highlights

- Implements major FIDO2 commands: MakeCredential, GetAssertion, ClientPIN (with both PIN/UV methods),
  Reset, CredentialManagement, and more.
- Both low-level access and ergonomic, high-level APIs.
- Modern Go design, making use of language features like iterators.
- `cgo` is currently used only for the macOS HID backend, but CTAP protocol logic is pure Go.

## Feature Matrix

### CTAP 2.2

- [x] MakeCredential
- [x] GetAssertion / GetNextAssertion
- [x] GetInfo
- [x] ClientPIN
  - [x] getPINRetries
  - [x] getKeyAgreement
  - [x] setPIN
  - [x] changePIN
  - [x] getPinToken
  - [x] getPinUvAuthTokenUsingUvWithPermissions
  - [x] getUVRetries
  - [x] getPinUvAuthTokenUsingPinWithPermissions
- [x] Reset
- [x] BioEnrollment
  - [x] enrollBegin
  - [x] enrollCaptureNextSample
  - [x] cancelCurrentEnrollment
  - [x] enumerateEnrollments
  - [x] setFriendlyName
  - [x] removeEnrollment
  - [x] getFingerprintSensorInfo
- [x] CredentialManagement
  - [x] getCredsMetadata
  - [x] enumerateRPsBegin / enumerateRPsGetNextRP
  - [x] enumerateCredentialsBegin / enumerateCredentialsGetNextCredential
  - [x] deleteCredential
  - [x] updateUserInformation
- [x] Selection
- [x] LargeBlobs
  - [x] raw get
  - [x] raw set
  - [x] get serialized large-blob array
  - [x] set serialized large-blob array
- [x] Config
  - [x] enableEnterpriseAttestation
  - [x] toggleAlwaysUv
  - [x] setMinPINLength
- [x] Prototype BioEnrollment
- [x] Prototype CredentialManagement

### Extensions

#### CTAP

- [x] credProtect
- [x] credBlob
- [x] largeBlobKey
- [ ] largeBlob
- [x] minPinLength
- [x] pinComplexityPolicy
- [x] hmac-secret
- [ ] hmac-secret-mc
- [x] thirdPartyPayment

#### WebAuthn

- [x] credProps
- [x] prf
- [ ] largeBlob

### Crypto

- [x] PIN/UV Auth Protocol One
- [x] PIN/UV Auth Protocol Two
- [x] Encrypt/Decrypt using `largeBlobKey` extension

## Build Dependencies

### Linux
For Linux systems, you'll need to install the following packages to build:
- `libudev-dev`: udev device management library
- `libusb-1.0-0-dev`: USB device access library

## Planned Improvements

- [ ] Better tests (using virtual authenticator?)
- [ ] `cgo`-free version for macOS. See [go-hid](https://github.com/go-ctap/hid).
