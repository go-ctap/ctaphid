package winhello

type currentVersion struct {
	rpEntityInformation                uint32
	userEntityInformation              uint32
	clientData                         uint32
	coseCredentialParameter            uint32
	credential                         uint32
	credentialEx                       uint32
	credentialDetails                  uint32
	getCredentialsOptions              uint32
	authenticatorMakeCredentialOptions uint32
	authenticatorGetAssertionOptions   uint32
	commonAttestation                  uint32
	credentialAttestation              uint32
	assertion                          uint32
}

func availableVersions(ver uint32) *currentVersion {
	baseline := &currentVersion{
		rpEntityInformation:     1,
		userEntityInformation:   1,
		clientData:              1,
		coseCredentialParameter: 1,
		credential:              1,
		credentialEx:            1,
		getCredentialsOptions:   1,
		commonAttestation:       1,

		authenticatorMakeCredentialOptions: 3,
		authenticatorGetAssertionOptions:   4,
		credentialAttestation:              3,
		assertion:                          1,
	}

	diff := []func(*currentVersion){
		func(v *currentVersion) {}, // 2
		func(v *currentVersion) {
			v.authenticatorMakeCredentialOptions++
			v.authenticatorGetAssertionOptions++
			v.credentialAttestation++
			v.assertion++
		}, // 3
		func(v *currentVersion) {
			v.authenticatorMakeCredentialOptions++
			v.authenticatorGetAssertionOptions++
			v.assertion++
			v.credentialDetails++
		}, // 4
		func(v *currentVersion) {
			v.credentialDetails++
		}, // 5
		func(v *currentVersion) {
			v.authenticatorMakeCredentialOptions++
			v.credentialAttestation++
			v.assertion++
		}, // 6
		func(v *currentVersion) {
			v.authenticatorMakeCredentialOptions++
			v.authenticatorGetAssertionOptions++
			v.credentialAttestation++
			v.assertion++
		}, // 7
		func(v *currentVersion) {
			v.authenticatorMakeCredentialOptions++
			v.credentialDetails++
			v.credentialAttestation++
			v.authenticatorGetAssertionOptions++
		}, // 8
	}

	for i, d := range diff {
		if i+1 == int(ver) {
			break
		}
		d(baseline)
	}

	return baseline
}
