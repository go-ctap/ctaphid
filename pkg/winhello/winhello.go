//go:build windows

//go:generate powershell -Command "go tool cgo -godefs types_webauthn.go | Set-Content -Path ztypes_webauthn.go -Encoding UTF8"
package winhello

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"unsafe"

	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"golang.org/x/sys/windows"
)

var (
	modWebAuthn                                               = windows.NewLazyDLL("webauthn.dll")
	procWebAuthNAuthenticatorGetAssertion                     = modWebAuthn.NewProc("WebAuthNAuthenticatorGetAssertion")
	procWebAuthNAuthenticatorMakeCredential                   = modWebAuthn.NewProc("WebAuthNAuthenticatorMakeCredential")
	procWebAuthNCancelCurrentOperation                        = modWebAuthn.NewProc("WebAuthNCancelCurrentOperation")
	procWebAuthNDeletePlatformCredential                      = modWebAuthn.NewProc("WebAuthNDeletePlatformCredential")
	procWebAuthNFreeAssertion                                 = modWebAuthn.NewProc("WebAuthNFreeAssertion")
	procWebAuthNFreeCredentialAttestation                     = modWebAuthn.NewProc("WebAuthNFreeCredentialAttestation")
	procWebAuthNFreePlatformCredentialList                    = modWebAuthn.NewProc("WebAuthNFreePlatformCredentialList")
	procWebAuthNGetApiVersionNumber                           = modWebAuthn.NewProc("WebAuthNGetApiVersionNumber")
	procWebAuthNGetCancellationId                             = modWebAuthn.NewProc("WebAuthNGetCancellationId")
	procWebAuthNGetErrorName                                  = modWebAuthn.NewProc("WebAuthNGetErrorName")
	procWebAuthNGetPlatformCredentialList                     = modWebAuthn.NewProc("WebAuthNGetPlatformCredentialList")
	procWebAuthNGetW3CExceptionDOMError                       = modWebAuthn.NewProc("WebAuthNGetW3CExceptionDOMError")
	procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable = modWebAuthn.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	currVer                                                   = availableVersions(APIVersionNumber())
)

type WebAuthnCredentialDetails struct {
	CredentialID []byte
	RP           webauthntypes.PublicKeyCredentialRpEntity
	User         webauthntypes.PublicKeyCredentialUserEntity
	Removable    bool
	BackedUp     bool
}

func GetAssertion(
	hWnd windows.HWND,
	rpID string,
	clientData []byte,
	allowList []webauthntypes.PublicKeyCredentialDescriptor,
	extInputs *webauthntypes.GetAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorGetAssertionOptions,
) (*WinHelloGetAssertionResponse, error) {
	if winHelloOpts == nil {
		winHelloOpts = &AuthenticatorGetAssertionOptions{}
	}

	opts := &_WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS{
		DwVersion:                     currVer.authenticatorGetAssertionOptions,
		DwTimeoutMilliseconds:         uint32(winHelloOpts.Timeout.Milliseconds()),
		CredentialList:                _WEBAUTHN_CREDENTIALS{}, // basically deprecated, baseline supports pAllowCredentialList
		DwAuthenticatorAttachment:     uint32(winHelloOpts.AuthenticatorAttachment),
		DwUserVerificationRequirement: uint32(winHelloOpts.UserVerificationRequirement),
		DwFlags:                       0, // user only in version 8 for PRF Global Eval
		DwCredLargeBlobOperation:      uint32(winHelloOpts.CredentialLargeBlobOperation),
		CbCredLargeBlob:               uint32(len(winHelloOpts.CredentialLargeBlob)),
		PbCredLargeBlob:               unsafe.SliceData(winHelloOpts.CredentialLargeBlob),
		BBrowserInPrivateMode:         boolToInt32(winHelloOpts.BrowserInPrivateMode),
		BAutoFill:                     boolToInt32(winHelloOpts.AutoFill),
		CbJsonExt:                     uint32(len(winHelloOpts.JsonExt)),
		PbJsonExt:                     unsafe.SliceData(winHelloOpts.JsonExt),
	}

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(allowList))
	for i, ex := range allowList {
		dwTransports := uint32(0)
		for _, tr := range ex.Transports {
			switch tr {
			case webauthntypes.AuthenticatorTransportUSB:
				dwTransports |= uint32(WinHelloCTAPTransportUSB)
			case webauthntypes.AuthenticatorTransportNFC:
				dwTransports |= uint32(WinHelloCTAPTransportNFC)
			case webauthntypes.AuthenticatorTransportBLE:
				dwTransports |= uint32(WinHelloCTAPTransportBLE)
			case webauthntypes.AuthenticatorTransportSmartCard:
			case webauthntypes.AuthenticatorTransportHybrid:
				dwTransports |= uint32(WinHelloCTAPTransportHybrid)
			case webauthntypes.AuthenticatorTransportInternal:
				dwTransports |= uint32(WinHelloCTAPTransportInternal)
			}
		}

		credExList[i] = &_WEBAUTHN_CREDENTIAL_EX{
			DwVersion:          currVer.credentialEx,
			CbId:               uint32(len(ex.ID)),
			PbId:               unsafe.SliceData(ex.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(ex.Type)),
			DwTransports:       dwTransports,
		}
	}
	if len(credExList) > 0 {
		opts.PAllowCredentialList = &_WEBAUTHN_CREDENTIAL_LIST{
			CCredentials:  uint32(len(credExList)),
			PpCredentials: unsafe.SliceData(credExList),
		}
	}

	if winHelloOpts.CancellationID != nil {
		opts.PCancellationId = &_GUID{
			Data1: winHelloOpts.CancellationID.Data1,
			Data2: winHelloOpts.CancellationID.Data2,
			Data3: winHelloOpts.CancellationID.Data3,
			Data4: winHelloOpts.CancellationID.Data4,
		}
	}

	if winHelloOpts.U2FAppID != "" {
		opts.PwszU2fAppId = windows.StringToUTF16Ptr(winHelloOpts.U2FAppID)
		t := boolToInt32(true)
		opts.PbU2fAppId = &t
	}

	if winHelloOpts.CredentialHints != nil {
		credHints := make([]*uint16, len(winHelloOpts.CredentialHints))
		for i, hint := range winHelloOpts.CredentialHints {
			credHints[i] = windows.StringToUTF16Ptr(string(hint))
		}

		opts.CCredentialHints = uint32(len(credHints))
		opts.PpwszCredentialHints = unsafe.SliceData(credHints)
	}

	if extInputs != nil {
		exts := make([]_WEBAUTHN_EXTENSION, 0)

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := boolToInt32(extInputs.GetCredentialBlobInputs.GetCredBlob)
			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// check that only hmac-secret or prf was supplied
		if extInputs.GetHMACSecretInputs != nil && extInputs.PRFInputs != nil {
			return nil, errors.New("you cannot use hmac-secret and prf extensions at the same time")
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil && extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1 != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)
			opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1)),
				PbFirst:  unsafe.SliceData(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1),
				CbSecond: uint32(len(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2)),
				PbSecond: unsafe.SliceData(extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)

			if extInputs.PRFInputs.PRF.Eval != nil {
				opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
					CbFirst:  uint32(len(extInputs.PRFInputs.PRF.Eval.First)),
					PbFirst:  unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.First),
					CbSecond: uint32(len(extInputs.PRFInputs.PRF.Eval.Second)),
					PbSecond: unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.Second),
				}
			}

			var credWithHMACSecretSaltList []_WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
			for credIDStr, values := range extInputs.PRFInputs.PRF.EvalByCredential {
				credID, err := base64.URLEncoding.DecodeString(credIDStr)
				if err != nil {
					return nil, fmt.Errorf("failed to decode credential ID: %w", err)
				}

				credWithHMACSecretSaltList = append(credWithHMACSecretSaltList, _WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT{
					CbCredID: uint32(len(credID)),
					PbCredID: unsafe.SliceData(credID),
					PHmacSecretSalt: &_WEBAUTHN_HMAC_SECRET_SALT{
						CbFirst:  uint32(len(values.First)),
						PbFirst:  unsafe.SliceData(values.First),
						CbSecond: uint32(len(values.Second)),
						PbSecond: unsafe.SliceData(values.Second),
					},
				})
			}

			opts.PHmacSecretSaltValues.CCredWithHmacSecretSaltList = uint32(len(credWithHMACSecretSaltList))
			opts.PHmacSecretSaltValues.PCredWithHmacSecretSaltList = unsafe.SliceData(credWithHMACSecretSaltList)
		}

		opts.Extensions = _WEBAUTHN_EXTENSIONS{
			CExtensions: uint32(len(exts)),
			PExtensions: unsafe.SliceData(exts),
		}
	}

	assertionPtr := new(_WEBAUTHN_ASSERTION)

	r1, _, _ := procWebAuthNAuthenticatorGetAssertion.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(rpID))),
		uintptr(unsafe.Pointer(&_WEBAUTHN_CLIENT_DATA{
			DwVersion:        currVer.clientData,
			CbClientDataJSON: uint32(len(clientData)),
			PbClientDataJSON: unsafe.SliceData(clientData),
			PwszHashAlgId:    windows.StringToUTF16Ptr("SHA-256"),
		})),
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&assertionPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer func() {
		_, _, err := procWebAuthNFreeAssertion.Call(uintptr(unsafe.Pointer(assertionPtr)))
		if err != nil && !errors.Is(err, windows.NTE_OP_OK) {
			slog.Debug("Assertion free failed!", "err", err)
		}
	}()

	resp, err := assertionPtr.ToGetAssertionResponse()
	if err != nil {
		return nil, err
	}

	resp.ExtensionOutputs = new(webauthntypes.GetAuthenticationExtensionsClientOutputs)
	if resp.AuthData.Extensions != nil {
		// hmac-secret
		if extInputs != nil && extInputs.GetHMACSecretInputs != nil && resp.AuthData.Extensions.GetHMACSecretOutput != nil {
			resp.ExtensionOutputs.GetHMACSecretOutputs = &webauthntypes.GetHMACSecretOutputs{
				HMACGetSecret: webauthntypes.HMACGetSecretOutput{
					Output1: resp.hmacSecret.First,
					Output2: resp.hmacSecret.Second,
				},
			}
		}

		// credBlob
		if resp.AuthData.Extensions.GetCredBlobOutput != nil {
			resp.ExtensionOutputs.GetCredentialBlobOutputs = &webauthntypes.GetCredentialBlobOutputs{
				GetCredBlob: resp.AuthData.Extensions.GetCredBlobOutput.CredBlob,
			}
		}

		// prf
		if extInputs != nil && extInputs.PRFInputs != nil && resp.AuthData.Extensions.GetHMACSecretOutput != nil {
			resp.ExtensionOutputs.PRFOutputs = &webauthntypes.PRFOutputs{
				PRF: webauthntypes.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthntypes.AuthenticationExtensionsPRFValues{
						First:  resp.hmacSecret.First,
						Second: resp.hmacSecret.Second,
					},
				},
			}
		}
	}

	return resp, nil
}

func MakeCredential(
	hWnd windows.HWND,
	clientData []byte,
	rp webauthntypes.PublicKeyCredentialRpEntity,
	user webauthntypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
	excludeList []webauthntypes.PublicKeyCredentialDescriptor,
	extInputs *webauthntypes.CreateAuthenticationExtensionsClientInputs,
	winHelloOpts *AuthenticatorMakeCredentialOptions,
) (*WinHelloMakeCredentialResponse, error) {
	coseCredentialParams := make([]_WEBAUTHN_COSE_CREDENTIAL_PARAMETER, len(pubKeyCredParams))
	for i, param := range pubKeyCredParams {
		coseCredentialParams[i] = _WEBAUTHN_COSE_CREDENTIAL_PARAMETER{
			DwVersion:          currVer.coseCredentialParameter,
			PwszCredentialType: windows.StringToUTF16Ptr(string(param.Type)),
			LAlg:               int32(param.Algorithm),
		}
	}

	if winHelloOpts == nil {
		winHelloOpts = &AuthenticatorMakeCredentialOptions{}
	}

	opts := &_WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS{
		DwVersion:                         currVer.authenticatorMakeCredentialOptions,
		DwTimeoutMilliseconds:             uint32(winHelloOpts.Timeout.Milliseconds()),
		CredentialList:                    _WEBAUTHN_CREDENTIALS{}, // basically deprecated, baseline supports pExcludeCredentialList
		DwAuthenticatorAttachment:         uint32(winHelloOpts.AuthenticatorAttachment),
		BRequireResidentKey:               boolToInt32(winHelloOpts.RequireResidentKey),
		DwUserVerificationRequirement:     uint32(winHelloOpts.UserVerificationRequirement),
		DwAttestationConveyancePreference: uint32(winHelloOpts.AttestationConveyancePreference),
		DwFlags:                           0, // user only in version 8 for PRF Global Eval
		DwEnterpriseAttestation:           uint32(winHelloOpts.EnterpriseAttestation),
		DwLargeBlobSupport:                uint32(winHelloOpts.LargeBlobSupport),
		BPreferResidentKey:                boolToInt32(winHelloOpts.PreferResidentKey),
		BBrowserInPrivateMode:             boolToInt32(winHelloOpts.BrowserInPrivateMode),
		CbJsonExt:                         uint32(len(winHelloOpts.JsonExt)),
		PbJsonExt:                         unsafe.SliceData(winHelloOpts.JsonExt),
		BThirdPartyPayment:                boolToInt32(winHelloOpts.ThirdPartyPayment),
	}

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(excludeList))
	for i, ex := range excludeList {
		dwTransports := uint32(0)
		for _, tr := range ex.Transports {
			switch tr {
			case webauthntypes.AuthenticatorTransportUSB:
				dwTransports |= uint32(WinHelloCTAPTransportUSB)
			case webauthntypes.AuthenticatorTransportNFC:
				dwTransports |= uint32(WinHelloCTAPTransportNFC)
			case webauthntypes.AuthenticatorTransportBLE:
				dwTransports |= uint32(WinHelloCTAPTransportBLE)
			case webauthntypes.AuthenticatorTransportSmartCard:
			case webauthntypes.AuthenticatorTransportHybrid:
				dwTransports |= uint32(WinHelloCTAPTransportHybrid)
			case webauthntypes.AuthenticatorTransportInternal:
				dwTransports |= uint32(WinHelloCTAPTransportInternal)
			}
		}

		credExList[i] = &_WEBAUTHN_CREDENTIAL_EX{
			DwVersion:          currVer.credentialEx,
			CbId:               uint32(len(ex.ID)),
			PbId:               unsafe.SliceData(ex.ID),
			PwszCredentialType: windows.StringToUTF16Ptr(string(ex.Type)),
			DwTransports:       dwTransports,
		}
	}
	if len(credExList) > 0 {
		opts.PExcludeCredentialList = &_WEBAUTHN_CREDENTIAL_LIST{
			CCredentials:  uint32(len(credExList)),
			PpCredentials: unsafe.SliceData(credExList),
		}
	}

	if winHelloOpts.CancellationID != nil {
		opts.PCancellationId = &_GUID{
			Data1: winHelloOpts.CancellationID.Data1,
			Data2: winHelloOpts.CancellationID.Data2,
			Data3: winHelloOpts.CancellationID.Data3,
			Data4: winHelloOpts.CancellationID.Data4,
		}
	}

	if winHelloOpts.CredentialHints != nil {
		credHints := make([]*uint16, len(winHelloOpts.CredentialHints))
		for i, hint := range winHelloOpts.CredentialHints {
			credHints[i] = windows.StringToUTF16Ptr(string(hint))
		}

		opts.CCredentialHints = uint32(len(credHints))
		opts.PpwszCredentialHints = unsafe.SliceData(credHints)
	}

	if extInputs != nil {
		exts := make([]_WEBAUTHN_EXTENSION, 0)

		// hmac-secret
		if extInputs.CreateHMACSecretInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierHMACSecret)),
			}

			hmacSecret := boolToInt32(extInputs.CreateHMACSecretInputs.HMACCreateSecret)
			ext.CbExtension = uint32(unsafe.Sizeof(hmacSecret))
			ext.PvExtension = (*byte)(unsafe.Pointer(&hmacSecret))
			exts = append(exts, ext)
		}

		// hmac-secret-mc
		if extInputs.CreateHMACSecretMCInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.PRFInputs.PRF.Eval.First)),
				PbFirst:  unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.First),
				CbSecond: uint32(len(extInputs.PRFInputs.PRF.Eval.Second)),
				PbSecond: unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.Second),
			}
			opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
		}

		// prf
		if extInputs.PRFInputs != nil {
			opts.BEnablePrf = boolToInt32(true)
			opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
				CbFirst:  uint32(len(extInputs.PRFInputs.PRF.Eval.First)),
				PbFirst:  unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.First),
				CbSecond: uint32(len(extInputs.PRFInputs.PRF.Eval.Second)),
				PbSecond: unsafe.SliceData(extInputs.PRFInputs.PRF.Eval.Second),
			}
		}

		// credProtect
		if extInputs.CreateCredentialProtectionInputs != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierCredentialProtection)),
			}

			credProtectValue := WinHelloUserVerificationAny
			switch extInputs.CreateCredentialProtectionInputs.CredentialProtectionPolicy {
			case webauthntypes.CredentialProtectionPolicyUserVerificationOptional:
				credProtectValue = WinHelloUserVerificationOptional
			case webauthntypes.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
				credProtectValue = WinHelloUserVerificationOptionalWithCredentialIDList
			case webauthntypes.CredentialProtectionPolicyUserVerificationRequired:
				credProtectValue = WinHelloUserVerificationRequired
			}

			credProtect := _WEBAUTHN_CRED_PROTECT_EXTENSION_IN{
				DwCredProtect:       uint32(credProtectValue),
				BRequireCredProtect: boolToInt32(extInputs.CreateCredentialProtectionInputs.EnforceCredentialProtectionPolicy),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credProtect))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credProtect))
			exts = append(exts, ext)
		}

		// credBlob
		if extInputs.CreateCredentialBlobInputs != nil && extInputs.CreateCredentialBlobInputs.CredBlob != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierCredentialBlob)),
			}

			credBlob := _WEBAUTHN_CRED_BLOB_EXTENSION{
				CbCredBlob: uint32(len(extInputs.CreateCredentialBlobInputs.CredBlob)),
				PbCredBlob: unsafe.SliceData(extInputs.CreateCredentialBlobInputs.CredBlob),
			}

			ext.CbExtension = uint32(unsafe.Sizeof(credBlob))
			ext.PvExtension = (*byte)(unsafe.Pointer(&credBlob))
			exts = append(exts, ext)
		}

		// minPinLength
		if extInputs.CreateMinPinLengthInputs != nil {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(webauthntypes.ExtensionIdentifierMinPinLength)),
			}

			minPinLength := boolToInt32(extInputs.CreateMinPinLengthInputs.MinPinLength)
			ext.CbExtension = uint32(unsafe.Sizeof(minPinLength))
			ext.PvExtension = (*byte)(unsafe.Pointer(&minPinLength))
			exts = append(exts, ext)
		}

		opts.Extensions = _WEBAUTHN_EXTENSIONS{
			CExtensions: uint32(len(exts)),
			PExtensions: unsafe.SliceData(exts),
		}
	}

	credAttestationPtr := new(_WEBAUTHN_CREDENTIAL_ATTESTATION)

	r1, _, _ := procWebAuthNAuthenticatorMakeCredential.Call(
		uintptr(hWnd),
		uintptr(unsafe.Pointer(&_WEBAUTHN_RP_ENTITY_INFORMATION{
			DwVersion: currVer.rpEntityInformation,
			PwszId:    windows.StringToUTF16Ptr(rp.ID),
			PwszName:  windows.StringToUTF16Ptr(rp.Name),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_USER_ENTITY_INFORMATION{
			DwVersion:       currVer.userEntityInformation,
			CbId:            uint32(len(user.ID)),
			PbId:            unsafe.SliceData(user.ID),
			PwszName:        windows.StringToUTF16Ptr(user.Name),
			PwszDisplayName: windows.StringToUTF16Ptr(user.DisplayName),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_COSE_CREDENTIAL_PARAMETERS{
			CCredentialParameters: uint32(len(coseCredentialParams)),
			PCredentialParameters: unsafe.SliceData(coseCredentialParams),
		})),
		uintptr(unsafe.Pointer(&_WEBAUTHN_CLIENT_DATA{
			DwVersion:        currVer.clientData,
			CbClientDataJSON: uint32(len(clientData)),
			PbClientDataJSON: unsafe.SliceData(clientData),
			PwszHashAlgId:    windows.StringToUTF16Ptr("SHA-256"),
		})),
		uintptr(unsafe.Pointer(opts)),
		uintptr(unsafe.Pointer(&credAttestationPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	defer func() {
		_, _, err := procWebAuthNFreeCredentialAttestation.Call(uintptr(unsafe.Pointer(credAttestationPtr)))
		if err != nil && !errors.Is(err, windows.NTE_OP_OK) {
			slog.Debug("Credential Attestation free failed!", "err", err)
		}
	}()

	resp, err := credAttestationPtr.ToMakeCredentialResponse()
	if err != nil {
		return nil, err
	}

	resp.ExtensionOutputs = new(webauthntypes.CreateAuthenticationExtensionsClientOutputs)

	if extInputs != nil && extInputs.CreateCredentialPropertiesInputs != nil {
		resp.ExtensionOutputs.CreateCredentialPropertiesOutputs = &webauthntypes.CreateCredentialPropertiesOutputs{
			CredentialProperties: webauthntypes.CredentialPropertiesOutput{
				ResidentKey: resp.ResidentKey,
			},
		}
	}

	if resp.AuthData.Extensions != nil {
		if resp.AuthData.Extensions.CreateCredBlobOutput != nil {
			resp.ExtensionOutputs.CreateCredentialBlobOutputs = &webauthntypes.CreateCredentialBlobOutputs{
				CredBlob: resp.AuthData.Extensions.CredBlob,
			}
		}

		if resp.AuthData.Extensions.CreateHMACSecretOutput != nil {
			resp.ExtensionOutputs.CreateHMACSecretOutputs = &webauthntypes.CreateHMACSecretOutputs{
				HMACCreateSecret: resp.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret,
			}
		}
	}

	return resp, nil
}

func CancelCurrentOperation() (*windows.GUID, error) {
	var cancellationIDPtr windows.GUID

	r1, _, _ := procWebAuthNCancelCurrentOperation.Call(
		uintptr(unsafe.Pointer(&cancellationIDPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	return &cancellationIDPtr, nil
}

func DeletePlatformCredential(credentialID []byte) error {
	r1, _, _ := procWebAuthNDeletePlatformCredential.Call(
		uintptr(len(credentialID)),
		uintptr(unsafe.Pointer(&credentialID[0])),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return windows.Errno(hr)
	}

	return nil
}

func APIVersionNumber() uint32 {
	r1, _, _ := procWebAuthNGetApiVersionNumber.Call()
	return uint32(r1)
}

func CancellationID() (*windows.GUID, error) {
	var cancellationIDPtr windows.GUID

	r1, _, _ := procWebAuthNGetCancellationId.Call(
		uintptr(unsafe.Pointer(&cancellationIDPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	return &cancellationIDPtr, nil
}

func ErrorName(hr windows.Handle) string {
	r1, _, _ := procWebAuthNGetErrorName.Call(uintptr(hr))
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(r1)))
}

func PlatformCredentialList(rpID string, browserInPrivateMode bool) ([]*WebAuthnCredentialDetails, error) {
	var rpIDPtr *uint16
	if rpID != "" {
		rpIDPtr = windows.StringToUTF16Ptr(rpID)
	}

	credDetailsListPtr := new(_WEBAUTHN_CREDENTIAL_DETAILS_LIST)

	r1, _, _ := procWebAuthNGetPlatformCredentialList.Call(
		uintptr(unsafe.Pointer(&_WEBAUTHN_GET_CREDENTIALS_OPTIONS{
			DwVersion:             currVer.getCredentialsOptions,
			PwszRpId:              rpIDPtr,
			BBrowserInPrivateMode: boolToInt32(browserInPrivateMode),
		})),
		uintptr(unsafe.Pointer(&credDetailsListPtr)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return nil, windows.Errno(hr)
	}

	credListDetails := slices.Clone(unsafe.Slice(credDetailsListPtr.PpCredentialDetails, credDetailsListPtr.CCredentialDetails))

	list := make([]*WebAuthnCredentialDetails, len(credListDetails))
	for i, cred := range credListDetails {
		credID := bytes.Clone(unsafe.Slice(cred.PbCredentialID, cred.CbCredentialID))

		list[i] = &WebAuthnCredentialDetails{
			CredentialID: credID,
			RP: webauthntypes.PublicKeyCredentialRpEntity{
				ID:   windows.UTF16PtrToString(cred.PRpInformation.PwszId),
				Name: windows.UTF16PtrToString(cred.PRpInformation.PwszName),
			},
			User: webauthntypes.PublicKeyCredentialUserEntity{
				ID:          bytes.Clone(unsafe.Slice(cred.PUserInformation.PbId, cred.PUserInformation.CbId)),
				DisplayName: windows.UTF16PtrToString(cred.PUserInformation.PwszDisplayName),
				Name:        windows.UTF16PtrToString(cred.PUserInformation.PwszName),
			},
			Removable: int32ToBool(cred.BRemovable),
			BackedUp:  int32ToBool(cred.BBackedUp),
		}
	}

	if _, _, err := procWebAuthNFreePlatformCredentialList.Call(
		uintptr(unsafe.Pointer(credDetailsListPtr)),
	); !errors.Is(err, windows.NTE_OP_OK) {
		return nil, err
	}

	return list, nil
}

func W3CExceptionDOMError() (windows.Handle, error) {
	var ret windows.Handle

	r1, _, _ := procWebAuthNGetW3CExceptionDOMError.Call(
		uintptr(unsafe.Pointer(&ret)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return 0, windows.Errno(hr)
	}

	return ret, nil
}

func IsUserVerifyingPlatformAuthenticatorAvailable() (bool, error) {
	var isAvailable bool

	r1, _, _ := procWebAuthNIsUserVerifyingPlatformAuthenticatorAvailable.Call(
		uintptr(unsafe.Pointer(&isAvailable)),
	)
	if hr := windows.Handle(r1); hr != windows.S_OK {
		return false, windows.Errno(hr)
	}

	return isAvailable, nil
}
