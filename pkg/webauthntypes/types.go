package webauthntypes

import "github.com/ldclabs/cose/key"

type (
	// PublicKeyCredentialType defines the valid credential types.
	// https://www.w3.org/TR/webauthn-3/#enumdef-publickeycredentialtype
	PublicKeyCredentialType string
	// AuthenticatorTransport defines hints as to how clients might communicate
	// with a particular authenticator in order to obtain an assertion for a specific credential.
	// https://www.w3.org/TR/webauthn-3/#enumdef-authenticatortransport
	AuthenticatorTransport string
	// AttestationStatementFormatIdentifier is an enum consisting of IANA registered Attestation Statement Format Identifiers.
	// https://www.iana.org/assignments/webauthn/webauthn.xhtml
	AttestationStatementFormatIdentifier string
	// ExtensionIdentifier is an enum consisting of IANA registered Extension Identifiers.
	// https://www.iana.org/assignments/webauthn/webauthn.xhtml
	ExtensionIdentifier string
	// PublicKeyCredentialHint is used by WebAuthn Relying Parties to communicate hints to the user-agent about
	// how a request may be best completed.
	// https://www.w3.org/TR/webauthn-3/#enum-hints
	PublicKeyCredentialHint string
)

const (
	PublicKeyCredentialTypePublicKey PublicKeyCredentialType = "public-key"
)

const (
	AuthenticatorTransportUSB       AuthenticatorTransport = "usb"
	AuthenticatorTransportNFC       AuthenticatorTransport = "nfc"
	AuthenticatorTransportBLE       AuthenticatorTransport = "ble"
	AuthenticatorTransportSmartCard AuthenticatorTransport = "smart-card"
	AuthenticatorTransportHybrid    AuthenticatorTransport = "hybrid"
	AuthenticatorTransportInternal  AuthenticatorTransport = "internal"
)

const (
	AttestationStatementFormatIdentifierPacked           AttestationStatementFormatIdentifier = "packed"
	AttestationStatementFormatIdentifierTPM              AttestationStatementFormatIdentifier = "tpm"
	AttestationStatementFormatIdentifierAndroidKey       AttestationStatementFormatIdentifier = "android-key"
	AttestationStatementFormatIdentifierAndroidSafetyNet AttestationStatementFormatIdentifier = "android-safetynet"
	AttestationStatementFormatIdentifierFIDOU2F          AttestationStatementFormatIdentifier = "fido-u2f"
	AttestationStatementFormatIdentifierApple            AttestationStatementFormatIdentifier = "apple"
	AttestationStatementFormatIdentifierNone             AttestationStatementFormatIdentifier = "none"
)

const (
	ExtensionIdentifierAppID                  ExtensionIdentifier = "appid"
	ExtensionIdentifierTxAuthSimple           ExtensionIdentifier = "txAuthSimple"
	ExtensionIdentifierTxAuthGeneric          ExtensionIdentifier = "txAuthGeneric"
	ExtensionIdentifierAuthnSelection         ExtensionIdentifier = "authnSel"
	ExtensionIdentifierExtensions             ExtensionIdentifier = "exts"
	ExtensionIdentifierUserVerificationIndex  ExtensionIdentifier = "uvi"
	ExtensionIdentifierLocation               ExtensionIdentifier = "loc"
	ExtensionIdentifierUserVerificationMethod ExtensionIdentifier = "uvm"
	ExtensionIdentifierCredentialProtection   ExtensionIdentifier = "credProtect"
	ExtensionIdentifierCredentialBlob         ExtensionIdentifier = "credBlob"
	ExtensionIdentifierLargeBlobKey           ExtensionIdentifier = "largeBlobKey"
	ExtensionIdentifierMinPinLength           ExtensionIdentifier = "minPinLength"
	ExtensionIdentifierPinComplexityPolicy    ExtensionIdentifier = "pinComplexityPolicy"
	ExtensionIdentifierHMACSecret             ExtensionIdentifier = "hmac-secret"
	ExtensionIdentifierHMACSecretMC           ExtensionIdentifier = "hmac-secret-mc"
	ExtensionIdentifierAppIDExclude           ExtensionIdentifier = "appidExclude"
	ExtensionIdentifierCredentialProperties   ExtensionIdentifier = "credProps"
	ExtensionIdentifierLargeBlob              ExtensionIdentifier = "largeBlob"
	ExtensionIdentifierPayment                ExtensionIdentifier = "payment"
)

const (
	PublicKeyCredentialHintSecurityKey  PublicKeyCredentialHint = "security-key"
	PublicKeyCredentialHintClientDevice PublicKeyCredentialHint = "client-device"
	PublicKeyCredentialHintHybrid       PublicKeyCredentialHint = "hybrid"
)

// PublicKeyCredentialRpEntity is used to supply additional Relying Party attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialrpentity
type PublicKeyCredentialRpEntity struct {
	ID   string `cbor:"id"`
	Name string `cbor:"name,omitempty"`
}

// PublicKeyCredentialUserEntity is used to supply additional user account attributes when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialuserentity
type PublicKeyCredentialUserEntity struct {
	ID          []byte `cbor:"id"`
	DisplayName string `cbor:"displayName,omitempty"`
	Name        string `cbor:"name,omitempty"`
	Icon        string `cbor:"icon,omitempty"` // deprecated
}

// PublicKeyCredentialDescriptor identifies a specific public key credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialdescriptor
type PublicKeyCredentialDescriptor struct {
	Type       PublicKeyCredentialType  `cbor:"type"`
	ID         []byte                   `cbor:"id"`
	Transports []AuthenticatorTransport `cbor:"transports,omitempty"`
}

// PublicKeyCredentialParameters is used to supply additional parameters when creating a new credential.
// https://www.w3.org/TR/webauthn-3/#dictdef-publickeycredentialparameters
type PublicKeyCredentialParameters struct {
	Type      PublicKeyCredentialType `cbor:"type"`
	Algorithm key.Alg                 `cbor:"alg"`
}

// PackedAttestationStatementFormat is a WebAuthn optimized attestation statement format.
// https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation
type PackedAttestationStatementFormat struct {
	Algorithm key.Alg  `cbor:"alg"`
	Signature []byte   `cbor:"sig"`
	X509Chain [][]byte `cbor:"x5c"`
}

// FIDOU2FAttestationStatementFormat is attestation statement format is used with FIDO U2F authenticators.
// https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation
type FIDOU2FAttestationStatementFormat struct {
	X509Chain [][]byte `cbor:"x5c"`
	Signature []byte   `cbor:"sig"`
}

// TPMAttestationStatementFormat is generally used by authenticators that use a Trusted Platform Module
// as their cryptographic engine.
// https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
type TPMAttestationStatementFormat struct {
	Version   string   `cbor:"ver"`
	Algorithm key.Alg  `cbor:"alg"`
	X509Chain [][]byte `cbor:"x5c"`
	AIKCert   []byte   `cbor:"aikCert"`
	Signature []byte   `cbor:"sig"`
	CertInfo  []byte   `cbor:"certInfo"` // TPMS_ATTEST structure
	PubArea   []byte   `cbor:"pubArea"`  // TPMT_PUBLIC structure
}
