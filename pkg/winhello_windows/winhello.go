//go:generate powershell -Command "go tool cgo -godefs types_webauthn.go | Set-Content -Path ztypes_webauthn.go -Encoding UTF8"
package winhello_windows

import "C"
import (
	"encoding/base64"
	"errors"
	"unsafe"

	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
	"github.com/savely-krasovsky/go-ctaphid/pkg/webauthntypes"
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

	apiVersionNumber = WebAuthNGetApiVersionNumber()
	currVer          = availableVersions(apiVersionNumber)
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
	winHelloOpts *AuthenticatorGetAssertionOptions,
) (*ctaptypes.AuthenticatorGetAssertionResponse, *WinHelloGetAssertionResponse, error) {
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

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(winHelloOpts.AllowCredentialList))
	for i, ex := range winHelloOpts.AllowCredentialList {
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

	// TODO
	if winHelloOpts.Extensions != nil {
		/*var exts []_WEBAUTHN_EXTENSION
		for name, value := range winHelloOpts.Extensions {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(name)),
				CbExtension:             uint32(unsafe.Sizeof(value)),
				PvExtension:             (*byte)(unsafe.Pointer(&value)),
			}

			exts = append(exts, ext)
		}

		opts.Extensions.CExtensions = uint32(len(exts))
		opts.Extensions.PExtensions = unsafe.SliceData(exts)*/
	}

	if winHelloOpts.HMACSecretSaltValues != nil {
		opts.PHmacSecretSaltValues = new(_WEBAUTHN_HMAC_SECRET_SALT_VALUES)
		opts.PHmacSecretSaltValues.PGlobalHmacSalt = &_WEBAUTHN_HMAC_SECRET_SALT{
			CbFirst:  uint32(len(winHelloOpts.HMACSecretSaltValues.Eval.First)),
			PbFirst:  unsafe.SliceData(winHelloOpts.HMACSecretSaltValues.Eval.First),
			CbSecond: uint32(len(winHelloOpts.HMACSecretSaltValues.Eval.Second)),
			PbSecond: unsafe.SliceData(winHelloOpts.HMACSecretSaltValues.Eval.Second),
		}

		var credWithHMACSecretSaltList []_WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
		for credIDStr, values := range winHelloOpts.HMACSecretSaltValues.EvalByCredential {
			credID, err := base64.URLEncoding.DecodeString(credIDStr)
			if err != nil {
				return nil, nil, err
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
		//opts.DwFlags |= WinHelloAuthenticatorHMACSecretValuesFlag
	}

	assertionPtr := new(_WEBAUTHN_ASSERTION)

	r1, _, err := procWebAuthNAuthenticatorGetAssertion.Call(
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
	if !errors.Is(err, windows.NTE_OP_OK) {
		return nil, nil, err
	}
	if windows.Handle(r1) != windows.S_OK {
		return nil, nil, windows.Errno(r1)
	}

	return assertionPtr.ToGetAssertionResponse()
}

func MakeCredential(
	hWnd windows.HWND,
	clientData []byte,
	rp webauthntypes.PublicKeyCredentialRpEntity,
	user webauthntypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
	winHelloOpts *AuthenticatorMakeCredentialOptions,
) (*ctaptypes.AuthenticatorMakeCredentialResponse, *WinHelloMakeCredentialResponse, error) {
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
		DwUserVerificationRequirement:     uint32(winHelloOpts.UserVerificationRequirement),
		DwAttestationConveyancePreference: uint32(winHelloOpts.AttestationConveyancePreference),
		DwFlags:                           0, // user only in version 8 for PRF Global Eval
		DwEnterpriseAttestation:           uint32(winHelloOpts.EnterpriseAttestation),
		DwLargeBlobSupport:                uint32(winHelloOpts.LargeBlobSupport),
		BPreferResidentKey:                boolToInt32(winHelloOpts.PreferResidentKey),
		BBrowserInPrivateMode:             boolToInt32(winHelloOpts.BrowserInPrivateMode),
		BEnablePrf:                        boolToInt32(winHelloOpts.EnablePRF),
		CbJsonExt:                         uint32(len(winHelloOpts.JsonExt)),
		PbJsonExt:                         unsafe.SliceData(winHelloOpts.JsonExt),
		BThirdPartyPayment:                boolToInt32(winHelloOpts.ThirdPartyPayment),
	}

	credExList := make([]*_WEBAUTHN_CREDENTIAL_EX, len(winHelloOpts.ExcludeCredentialList))
	for i, ex := range winHelloOpts.ExcludeCredentialList {
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

	if winHelloOpts.PPRFGlobalEval != nil {
		opts.PPRFGlobalEval = &_WEBAUTHN_HMAC_SECRET_SALT{
			CbFirst:  uint32(len(winHelloOpts.PPRFGlobalEval.First)),
			PbFirst:  unsafe.SliceData(winHelloOpts.PPRFGlobalEval.First),
			CbSecond: uint32(len(winHelloOpts.PPRFGlobalEval.Second)),
			PbSecond: unsafe.SliceData(winHelloOpts.PPRFGlobalEval.Second),
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

	if winHelloOpts.Extensions != nil {
		var exts []_WEBAUTHN_EXTENSION
		for name, value := range winHelloOpts.Extensions {
			ext := _WEBAUTHN_EXTENSION{
				PwszExtensionIdentifier: windows.StringToUTF16Ptr(string(name)),
			}

			switch name {
			case webauthntypes.ExtensionIdentifierHMACSecret:
				v, ok := value.(bool)
				if !ok {
					continue
				}

				hmacSecret := boolToInt32(v)
				ext.CbExtension = uint32(unsafe.Sizeof(hmacSecret))
				ext.PvExtension = (*byte)(unsafe.Pointer(&hmacSecret))
			case webauthntypes.ExtensionIdentifierCredentialProtection:
				/*v, ok := value.(*ctaptypes.CredProtectInput)
				if !ok {
					continue
				}

				credProtect := _WEBAUTHN_CRED_PROTECT_EXTENSION_IN{
					BRequireCredProtect: boolToInt32(v.EnforceCredentialProtectionPolicy),
				}
				switch v.CredentialProtectionPolicy {
				case device.CredentialProtectionPolicyUserVerificationOptional:
					credProtect.DwCredProtect = uint32(WinHelloUserVerificationOptional)
				case device.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
					credProtect.DwCredProtect = uint32(WinHelloUserVerificationOptionalWithCredentialIDList)
				case device.CredentialProtectionPolicyUserVerificationRequired:
					credProtect.DwCredProtect = uint32(WinHelloUserVerificationRequired)
				}

				ext.CbExtension = uint32(unsafe.Sizeof(v))
				ext.PvExtension = (*byte)(unsafe.Pointer(&credProtect))
				// TODO: implement those extensions*/
			case webauthntypes.ExtensionIdentifierCredentialBlob:
				panic("not implemented")
			case webauthntypes.ExtensionIdentifierMinPinLength:
				panic("not implemented")
			case webauthntypes.ExtensionIdentifierLargeBlob:
				panic("not implemented")
			default:
				continue
			}

			exts = append(exts, ext)
		}

		opts.Extensions.CExtensions = uint32(len(exts))
		opts.Extensions.PExtensions = unsafe.SliceData(exts)
	}

	credAttestationPtr := new(_WEBAUTHN_CREDENTIAL_ATTESTATION)

	r1, _, err := procWebAuthNAuthenticatorMakeCredential.Call(
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
	if !errors.Is(err, windows.NTE_OP_OK) {
		return nil, nil, err
	}
	if windows.Handle(r1) != windows.S_OK {
		return nil, nil, windows.Errno(r1)
	}

	return credAttestationPtr.ToMakeCredentialResponse()
}

func PlatformCredentialList(rpID string, browserInPrivateMode bool) ([]*WebAuthnCredentialDetails, error) {
	var rpIDPtr *uint16
	if rpID != "" {
		rpIDPtr = windows.StringToUTF16Ptr(rpID)
	}

	credDetailsListPtr := new(_WEBAUTHN_CREDENTIAL_DETAILS_LIST)

	r1, _, err := procWebAuthNGetPlatformCredentialList.Call(
		uintptr(unsafe.Pointer(&_WEBAUTHN_GET_CREDENTIALS_OPTIONS{
			DwVersion:             currVer.getCredentialsOptions,
			PwszRpId:              rpIDPtr,
			BBrowserInPrivateMode: boolToInt32(browserInPrivateMode),
		})),
		uintptr(unsafe.Pointer(&credDetailsListPtr)),
	)
	if !errors.Is(err, windows.NOERROR) {
		return nil, err
	}
	if windows.Handle(r1) != windows.S_OK {
		return nil, windows.Errno(r1)
	}

	credListDetails := unsafe.Slice(credDetailsListPtr.PpCredentialDetails, credDetailsListPtr.CCredentialDetails)

	list := make([]*WebAuthnCredentialDetails, len(credListDetails))
	for i, cred := range credListDetails {
		credID := unsafe.Slice(cred.PbCredentialID, cred.CbCredentialID)

		list[i] = &WebAuthnCredentialDetails{
			CredentialID: credID,
			RP: webauthntypes.PublicKeyCredentialRpEntity{
				ID:   windows.UTF16PtrToString(cred.PRpInformation.PwszId),
				Name: windows.UTF16PtrToString(cred.PRpInformation.PwszName),
			},
			User: webauthntypes.PublicKeyCredentialUserEntity{
				ID:          unsafe.Slice(cred.PUserInformation.PbId, cred.PUserInformation.CbId),
				DisplayName: windows.UTF16PtrToString(cred.PUserInformation.PwszDisplayName),
				Name:        windows.UTF16PtrToString(cred.PUserInformation.PwszName),
			},
			Removable: int32ToBool(cred.BRemovable),
			BackedUp:  int32ToBool(cred.BBackedUp),
		}
	}

	if _, _, err := procWebAuthNFreePlatformCredentialList.Call(
		uintptr(unsafe.Pointer(credDetailsListPtr)),
	); !errors.Is(err, windows.NOERROR) {
		return nil, err
	}

	return list, nil
}

func WebAuthNGetApiVersionNumber() uint32 {
	r1, _, _ := procWebAuthNGetApiVersionNumber.Call()
	return uint32(r1)
}

func WebAuthNGetErrorName(hr windows.Handle) string {
	r1, _, _ := procWebAuthNGetErrorName.Call(uintptr(hr))
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(r1)))
}
