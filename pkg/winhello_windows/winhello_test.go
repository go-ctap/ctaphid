package winhello_windows

import (
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/goforj/godump"
	"github.com/ldclabs/cose/iana"
	hiddenwindow "github.com/savely-krasovsky/go-ctaphid/pkg/hiddenwindow_windows"
	"github.com/savely-krasovsky/go-ctaphid/pkg/webauthntypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var (
	hWnd windows.HWND
)

func TestMain(m *testing.M) {
	wnd, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "WebAuthn Tests")
	if err != nil {
		panic(err)
	}
	defer wnd.Close()

	hWnd = wnd.WindowHandle()
	m.Run()
}

func TestAuthenticatorMakePlatformCredential(t *testing.T) {
	credAttestation, err := MakeCredential(
		hWnd,
		[]byte("{}"),
		webauthntypes.PublicKeyCredentialRpEntity{
			ID:   "example.org",
			Name: "Example RP",
		},
		webauthntypes.PublicKeyCredentialUserEntity{
			ID:          []byte("john"),
			Name:        "John Doe",
			DisplayName: "John Doe",
		},
		[]webauthntypes.PublicKeyCredentialParameters{
			{
				Type:      webauthntypes.PublicKeyCredentialTypePublicKey,
				Algorithm: iana.AlgorithmES256,
			},
		},
		nil,
		&webauthntypes.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthntypes.CreateCredentialPropertiesInputs{
				CredentialProperties: true,
			},
		},
		&AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment:         WinHelloAuthenticatorAttachmentPlatform,
			AttestationConveyancePreference: WinHelloAttestationConveyancePreferenceDirect,
			RequireResidentKey:              true,
		},
	)
	require.NoError(t, err)

	// credProps
	assert.True(t, credAttestation.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)

	godump.Dump(credAttestation)
}

func TestGetPlatformAssertion(t *testing.T) {
	assertion, err := GetAssertion(
		hWnd,
		"example.org",
		[]byte("{}"),
		nil,
		nil,
		&AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     WinHelloAuthenticatorAttachmentPlatform,
			UserVerificationRequirement: WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []webauthntypes.PublicKeyCredentialHint{
				webauthntypes.PublicKeyCredentialHintClientDevice,
				webauthntypes.PublicKeyCredentialHintSecurityKey,
				webauthntypes.PublicKeyCredentialHintHybrid,
			},
		},
	)
	require.NoError(t, err)

	godump.Dump(assertion)
}

func TestPlatformCredentialList(t *testing.T) {
	list, err := PlatformCredentialList("", false)
	require.NoError(t, err)
	require.NotEmpty(t, list)

	for _, cred := range list {
		godump.Dump(cred)
	}
}

func TestDeletePlatformCredential(t *testing.T) {
	list, err := PlatformCredentialList("example.org", false)
	require.NoError(t, err)
	require.Len(t, list, 1)

	for _, cred := range list {
		err = DeletePlatformCredential(cred.CredentialID)
		require.NoError(t, err)
	}
}

func TestIsUserVerifyingPlatformAuthenticatorAvailable(t *testing.T) {
	available, err := IsUserVerifyingPlatformAuthenticatorAvailable()
	require.NoError(t, err)

	assert.True(t, available)
}

// TestAuthenticatorMakeCrossPlatformCredential creates a non-residential credential to save space on authenticator.
func TestAuthenticatorMakeCrossPlatformCredential(t *testing.T) {
	credAttestation, err := MakeCredential(
		hWnd,
		[]byte("{}"),
		webauthntypes.PublicKeyCredentialRpEntity{
			ID:   "example.org",
			Name: "Example RP",
		},
		webauthntypes.PublicKeyCredentialUserEntity{
			ID:          []byte("john"),
			Name:        "John Doe",
			DisplayName: "John Doe",
		},
		[]webauthntypes.PublicKeyCredentialParameters{
			{
				Type:      webauthntypes.PublicKeyCredentialTypePublicKey,
				Algorithm: iana.AlgorithmES256,
			},
		},
		nil,
		&webauthntypes.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthntypes.CreateCredentialPropertiesInputs{
				CredentialProperties: true,
			},
		},
		&AuthenticatorMakeCredentialOptions{
			AuthenticatorAttachment:         WinHelloAuthenticatorAttachmentCrossPlatform,
			AttestationConveyancePreference: WinHelloAttestationConveyancePreferenceDirect,
		},
	)
	require.NoError(t, err)

	// credProps
	assert.False(t, credAttestation.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)

	godump.Dump(credAttestation)
}

// TestAuthenticatorGetCrossPlatformAssertion uses previously created credential ID to test deterministic PRF output.
// Value was compared with various
func TestAuthenticatorGetCrossPlatformAssertion(t *testing.T) {
	credIDStr := "ruDDeY_rT2Jv25HOJCY5LhTUXlX1DrIaAYVTXrumUtU5qNvr9uo77UekHDMiu1TEIRgw20ptOx841RsVZl--iofFQXkc0vIZ0-gpXZtw5g138QI0a1d4WBQbF7F1PbpC"
	credID, _ := base64.URLEncoding.DecodeString(credIDStr)

	assertion, err := GetAssertion(
		hWnd,
		"example.org",
		[]byte("{}"),
		[]webauthntypes.PublicKeyCredentialDescriptor{
			{
				ID:   credID,
				Type: webauthntypes.PublicKeyCredentialTypePublicKey,
			},
		},
		&webauthntypes.GetAuthenticationExtensionsClientInputs{
			PRFInputs: &webauthntypes.PRFInputs{
				PRF: webauthntypes.AuthenticationExtensionsPRFInputs{
					EvalByCredential: map[string]webauthntypes.AuthenticationExtensionsPRFValues{
						credIDStr: {
							First: []byte("first"),
						},
					},
				},
			},
		},
		&AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     WinHelloAuthenticatorAttachmentCrossPlatform,
			UserVerificationRequirement: WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []webauthntypes.PublicKeyCredentialHint{
				webauthntypes.PublicKeyCredentialHintClientDevice,
				webauthntypes.PublicKeyCredentialHintSecurityKey,
				webauthntypes.PublicKeyCredentialHintHybrid,
			},
		},
	)
	require.NoError(t, err)

	// prf
	assert.True(t, assertion.ExtensionOutputs.PRFOutputs.PRF.Enabled)
	assert.Equal(
		t,
		[]byte{
			0x1d, 0x6, 0x7d, 0xaf, 0x7e, 0xec, 0xc2, 0x17,
			0x1b, 0x24, 0x4d, 0xc8, 0x52, 0x1, 0x18, 0x1f,
			0x92, 0xc, 0xe0, 0xcc, 0xcd, 0xa5, 0x6b, 0x9e,
			0x12, 0xfc, 0x6d, 0xab, 0xaf, 0x6, 0x10, 0x5c,
		},
		assertion.ExtensionOutputs.PRFOutputs.PRF.Results.First,
	)

	godump.Dump(assertion)
}
