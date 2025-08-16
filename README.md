# go-ctaphid

[![Go Reference](https://pkg.go.dev/badge/github.com/go-ctap/ctaphid.svg)](https://pkg.go.dev/github.com/go-ctap/ctaphid)
[![Go](https://github.com/go-ctap/ctaphid/actions/workflows/go.yml/badge.svg)](https://github.com/go-ctap/ctaphid/actions/workflows/go.yml)

go-ctaphid is an idiomatic Go library implementing the CTAPHID transport protocol to interact with FIDO2 authenticators,
featuring a clean, modern API with multiple layers of abstraction.

> [!WARNING]
> Work in progress! API may change during `v0.x`!

## Current Status

Library supports almost entire CTAP 2.2 specification, except few extensions which are not yet seen in the wild
(`hmac-secret-mc`, dedicated `largeBlob`, not to be confused with `largeBlobKey` which is supported).

My current priorities are to write better tests and completely replace [sstallion/go-hid](https://github.com/sstallion/go-hid)
with the [own](https://github.com/go-ctap/hid) `cgo`-free alternative.

## Key Features and Architecture

The library exposes several abstraction levels, allowing you to choose the API that best suits your needs:

1. **Transport Layer (`ctaphid`)**

   Direct access to the raw CTAPHID transport protocol. If you need maximum control, you can communicate with devices
   at the frame level.

2. **Protocol Layer (`ctap`)**

   Implements CTAP 2.2 protocol messaging atop the transport, letting you work with high-level commands and
   CBOR-encoded messages.

3. **Device Abstraction (`device`)**

   Provides a convenient wrapper over the `ctap` package, managing device descriptor and abstracting channel (CID)
   management, so you don’t have to handle these low-level details manually.

4. **Scenario Helpers (`sugar`)** _(Mostly TODO now)_

   A growing set of utility functions for common use-cases. These helpers streamline trivial or repetitive
   scenarios, letting you get started quickly without deep protocol knowledge.

## Highlights

- Implements major FIDO2 commands: MakeCredential, GetAssertion, ClientPIN (with both PIN/UV methods),
  Reset, CredentialManagement, and more.
- Both low-level access and ergonomic, high-level APIs.
- Modern Go design, making use of language features like iterators.
- `cgo` is currently used only for macOS version (for HID transport), but FIDO2 protocol logic is pure Go.

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

#### WebAuhn

- [x] credProps
- [x] prf
- [ ] largeBlob

### Crypto

- [x] PIN/UV Auth Protocol One
- [x] PIN/UV Auth Protocol Two
- [x] Encrypt/Decrypt using `LargeBlobsKey` extension

## Build Dependencies

### Linux
For Linux systems, you'll need to install the following packages to build:
- `libudev-dev`: udev device management library
- `libusb-1.0-0-dev`: USB device access library

## Planned Improvements

- [ ] Better tests (using virtual authenticator?)
- [ ] Extended "sugar" helpers for common use-cases.
- [ ] `cgo`-free version for macOS. See [go-hid](https://github.com/go-ctap/hid).
