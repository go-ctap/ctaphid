package ctaptypes

type AuthenticatorMakeCredentialRequest struct {
	ClientDataHash               []byte                                 `cbor:"1,keyasint"`
	RP                           PublicKeyCredentialRpEntity            `cbor:"2,keyasint"`
	User                         PublicKeyCredentialUserEntity          `cbor:"3,keyasint"`
	PubKeyCredParams             []PublicKeyCredentialParameters        `cbor:"4,keyasint"`
	ExcludeList                  []PublicKeyCredentialDescriptor        `cbor:"5,keyasint,omitempty"`
	Extensions                   map[ExtensionIdentifier]any            `cbor:"6,keyasint,omitempty"`
	Options                      map[Option]bool                        `cbor:"7,keyasint,omitempty"`
	PinUvAuthParam               []byte                                 `cbor:"8,keyasint,omitempty"`
	PinUvAuthProtocol            PinUvAuthProtocol                      `cbor:"9,keyasint,omitempty"`
	EnterpriseAttestation        uint                                   `cbor:"10,keyasint,omitempty"`
	AttestationFormatsPreference []AttestationStatementFormatIdentifier `cbor:"11,keyasint,omitempty"`
}

type AuthenticatorMakeCredentialResponse struct {
	Format                   AttestationStatementFormatIdentifier `cbor:"1,keyasint"`
	AuthData                 *AuthData                            `cbor:"-"`
	AuthDataRaw              []byte                               `cbor:"2,keyasint"`
	AttestationStatement     map[string]any                       `cbor:"3,keyasint,omitempty"`
	EnterpriseAttestation    bool                                 `cbor:"4,keyasint,omitempty"`
	LargeBlobKey             []byte                               `cbor:"5,keyasint,omitempty"`
	UnsignedExtensionOutputs map[ExtensionIdentifier]any          `cbor:"6,keyasint,omitempty"`
}
