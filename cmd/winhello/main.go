//go:build windows

package main

import (
	"encoding/base64"
	"log/slog"

	"github.com/go-ctap/ctaphid/pkg/hiddenwindow"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/go-ctap/ctaphid/pkg/winhello"
	"github.com/goforj/godump"
)

func main() {
	wnd, err := hiddenwindow.New(slog.New(slog.DiscardHandler), "WinHello Example")
	if err != nil {
		panic(err)
	}
	defer wnd.Close()

	credIDStr := "ruDDeY_rT2Jv25HOJCY5LhTUXlX1DrIaAYVTXrumUtU5qNvr9uo77UekHDMiu1TEIRgw20ptOx841RsVZl--iofFQXkc0vIZ0-gpXZtw5g138QI0a1d4WBQbF7F1PbpC"
	credID, _ := base64.URLEncoding.DecodeString(credIDStr)

	assertion, err := winhello.GetAssertion(
		wnd.WindowHandle(),
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
		&winhello.AuthenticatorGetAssertionOptions{
			AuthenticatorAttachment:     winhello.WinHelloAuthenticatorAttachmentCrossPlatform,
			UserVerificationRequirement: winhello.WinHelloUserVerificationRequirementDiscouraged,
			CredentialHints: []webauthntypes.PublicKeyCredentialHint{
				webauthntypes.PublicKeyCredentialHintSecurityKey,
			},
		},
	)
	if err != nil {
		panic(err)
	}

	godump.Dump(assertion)
}
