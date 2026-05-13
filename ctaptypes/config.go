package ctaptypes

type AuthenticatorConfigRequest struct {
	SubCommand        ConfigSubCommand  `cbor:"1,keyasint"`
	SubCommandParams  any               `cbor:"2,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"3,keyasint,omitempty"`
	PinUvAuthParam    []byte            `cbor:"4,keyasint,omitempty"`
}

type SetMinPINLengthConfigSubCommandParams struct {
	NewMinPINLength     uint     `cbor:"1,keyasint,omitempty"`
	MinPinLengthRPIDs   []string `cbor:"2,keyasint,omitempty"`
	ForceChangePin      bool     `cbor:"3,keyasint,omitempty"`
	PinComplexityPolicy bool     `cbor:"4,keyasint,omitempty"`
}
