# go-ctaphid

[![Go Reference](https://pkg.go.dev/badge/github.com/savely-krasovsky/go-ctaphid.svg)](https://pkg.go.dev/github.com/savely-krasovsky/go-ctaphid)

go-ctaphid is an idiomatic Go library implementing the CTAPHID transport protocol to interact with FIDO2 authenticators,
featuring a clean, modern API with multiple layers of abstraction.

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
- `cgo` is currently used for HID transport, but FIDO2 protocol logic is pure Go.

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
- [ ] BioEnrollment
  - [ ] enrollBegin
  - [ ] enrollCaptureNextSample
  - [ ] cancelCurrentEnrollment
  - [ ] enumerateEnrollments
  - [ ] setFriendlyName
  - [ ] removeEnrollment
  - [ ] getFingerprintSensorInfo
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
- [ ] Config
  - [ ] enableEnterpriseAttestation
  - [x] toggleAlwaysUv
  - [x] setMinPINLength
- [ ] Prototype BioEnrollment
- [x] Prototype CredentialManagement

### Extensions

- [x] credProtect
- [x] credBlob
- [x] largeBlobKey
- [ ] largeBlob
- [x] minPinLength
- [x] pinComplexityPolicy
- [x] hmac-secret
- [ ] hmac-secret-mc
- [x] thirdPartyPayment

### Crypto

- [x] PIN/UV Auth Protocol One
- [x] PIN/UV Auth Protocol Two
- [x] Encrypt/Decrypt using `LargeBlobsKey` extension

## Planned Improvements

- [ ] Better tests (using virtual authenticator?)
- [ ] Extended "sugar" helpers for common use-cases.
- [ ] Mobile platform compatibility (Android, iOS) and additional transport support (CTAPNFC, CTAPBLE?).
- [ ] `cgo`-free version.
