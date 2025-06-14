package webauthntypes

type CreateAuthenticationExtensionsClientInputs struct {
	*CreateCredentialBlobInputs
	*CreateCredentialPropertiesInputs
	*CreateCredentialProtectionInputs
	*CreateHMACSecretInputs
	*CreateHMACSecretMCInputs
	*LargeBlobInputs
	*CreateMinPinLengthInputs
	*CreatePinComplexityPolicyInputs
	*PaymentInputs
	*PRFInputs
}

type CreateAuthenticationExtensionsClientOutputs struct {
	*CreateCredentialBlobOutputs
	*CreateCredentialPropertiesOutputs
	*CreateHMACSecretOutputs
	*CreateHMACSecretMCOutputs
	*LargeBlobOutputs
	*PRFOutputs
}

type GetAuthenticationExtensionsClientInputs struct {
	*GetCredentialBlobInputs
	*GetHMACSecretInputs
	*LargeBlobInputs
	*PRFInputs
}

type GetAuthenticationExtensionsClientOutputs struct {
	*GetCredentialBlobOutputs
	*GetHMACSecretOutputs
	*LargeBlobOutputs
	*PRFOutputs
}
