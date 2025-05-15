package ctaptypes

type AuthenticatorGetAssertionRequest struct {
	RPID              string                          `cbor:"1,keyasint"`
	ClientDataHash    []byte                          `cbor:"2,keyasint"`
	AllowList         []PublicKeyCredentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        map[ExtensionIdentifier]any     `cbor:"4,keyasint,omitempty"`
	Options           map[Option]bool                 `cbor:"5,keyasint,omitempty"`
	PinUvAuthParam    []byte                          `cbor:"6,keyasint,omitempty"`
	PinUvAuthProtocol PinUvAuthProtocol               `cbor:"7,keyasint,omitempty"`
}

type AuthenticatorGetAssertionResponse struct {
	Credential               PublicKeyCredentialDescriptor  `cbor:"1,keyasint"`
	AuthDataRaw              []byte                         `cbor:"2,keyasint"`
	Signature                []byte                         `cbor:"3,keyasint"`
	User                     *PublicKeyCredentialUserEntity `cbor:"4,keyasint,omitempty"`
	NumberOfCredentials      uint                           `cbor:"5,keyasint,omitempty"`
	UserSelected             bool                           `cbor:"6,keyasint,omitempty"`
	LargeBlobKey             []byte                         `cbor:"7,keyasint,omitempty"`
	UnsignedExtensionOutputs map[ExtensionIdentifier]any    `cbor:"8,keyasint,omitempty"`
}

func (r *AuthenticatorGetAssertionResponse) AuthData() (*AuthData, error) {
	return ParseAuthData(r.AuthDataRaw)
}
