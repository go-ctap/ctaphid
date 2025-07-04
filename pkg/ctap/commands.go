package ctap

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"slices"

	"github.com/go-ctap/ctaphid/pkg/crypto"
	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/options"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
)

type Client struct {
	logger  *slog.Logger
	encMode cbor.EncMode
}

func NewClient(opts ...options.Option) *Client {
	oo := options.NewOptions(opts...)

	return &Client{
		logger:  oo.Logger,
		encMode: oo.EncMode,
	}
}

func (cl *Client) MakeCredential(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	clientData []byte,
	rp webauthntypes.PublicKeyCredentialRpEntity,
	user webauthntypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
	excludeList []webauthntypes.PublicKeyCredentialDescriptor,
	extensions *ctaptypes.CreateExtensionInputs,
	options map[ctaptypes.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []webauthntypes.AttestationStatementFormatIdentifier,
) (*ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	hasher := sha256.New()
	hasher.Write(clientData)
	clientDataHash := hasher.Sum(nil)

	req := &ctaptypes.AuthenticatorMakeCredentialRequest{
		ClientDataHash:               clientDataHash,
		RP:                           rp,
		User:                         user,
		PubKeyCredParams:             pubKeyCredParams,
		ExcludeList:                  excludeList,
		Extensions:                   extensions,
		Options:                      options,
		EnterpriseAttestation:        enterpriseAttestation,
		AttestationFormatsPreference: attestationFormatsPreference,
	}

	if pinUvAuthToken != nil {
		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			clientDataHash,
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal MakeCredential CBOR request: %w", err)
	}
	cl.logger.Debug("MakeCredential CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorMakeCredential)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("MakeCredential CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}
	resp.AuthData, err = ctaptypes.ParseMakeCredentialAuthData(resp.AuthDataRaw)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) GetAssertion(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []webauthntypes.PublicKeyCredentialDescriptor,
	extensions *ctaptypes.GetExtensionInputs,
	options map[ctaptypes.Option]bool,
) iter.Seq2[*ctaptypes.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {
		hasher := sha256.New()
		hasher.Write(clientData)
		clientDataHash := hasher.Sum(nil)

		req := &ctaptypes.AuthenticatorGetAssertionRequest{
			RPID:           rpID,
			ClientDataHash: clientDataHash,
			AllowList:      allowList,
			Extensions:     extensions,
			Options:        options,
		}

		if pinUvAuthToken != nil {
			pinUvAuthParamBegin := crypto.Authenticate(
				pinUvAuthProtocol,
				pinUvAuthToken,
				clientDataHash,
			)

			req.PinUvAuthParam = pinUvAuthParamBegin
			req.PinUvAuthProtocol = pinUvAuthProtocol
		}

		bBegin, err := cl.encMode.Marshal(req)
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("GetAssertion CBOR request", "hex", hex.EncodeToString(bBegin))

		respRawBegin, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorGetAssertion)}, bBegin))
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("GetAssertion CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin *ctaptypes.AuthenticatorGetAssertionResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}
		respBegin.AuthData, err = ctaptypes.ParseGetAssertionAuthData(respBegin.AuthDataRaw)
		if err != nil {
			yield(nil, err)
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.NumberOfCredentials; i++ {
			respRaw, err := ctaphid.CBOR(device, cid, []byte{byte(ctaptypes.AuthenticatorGetNextAssertion)})
			if err != nil {
				yield(nil, err)
				return
			}
			cl.logger.Debug("GetNextAssertion CBOR response", "hex", hex.EncodeToString(respRaw.Data))

			var resp *ctaptypes.AuthenticatorGetAssertionResponse
			if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
				yield(nil, err)
				return
			}
			resp.AuthData, err = ctaptypes.ParseGetAssertionAuthData(resp.AuthDataRaw)
			if err != nil {
				yield(nil, err)
				return
			}

			if !yield(resp, nil) {
				return
			}
		}
	}
}

func (cl *Client) GetInfo(device io.ReadWriter, cid ctaphid.ChannelID) (*ctaptypes.AuthenticatorGetInfoResponse, error) {
	respRaw, err := ctaphid.CBOR(device, cid, []byte{byte(ctaptypes.AuthenticatorGetInfo)})
	if err != nil {
		return nil, err
	}

	var resp *ctaptypes.AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) GetPINRetries(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
) (uint, bool, error) {
	req := &ctaptypes.AuthenticatorClientPINRequest{
		// While this parameter is unnecessary, SoloKeys Solo 2 requires it for some reason.
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        ctaptypes.ClientPINSubCommandGetPINRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, false, err
	}
	cl.logger.Debug("getPINRetries CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, false, err
	}
	cl.logger.Debug("getPINRetries CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, false, err
	}

	return resp.PinRetries, resp.PowerCycleState, nil
}

func (cl *Client) GetKeyAgreement(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
) (key.Key, error) {
	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        ctaptypes.ClientPINSubCommandGetKeyAgreement,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal keyAgreement CBOR request: %w", err)
	}
	cl.logger.Debug("getKeyAgreement CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, fmt.Errorf("keyAgreement CBOR request failed: %w", err)
	}
	cl.logger.Debug("getKeyAgreement CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal keyAgreement CBOR response: %w", err)
	}

	return resp.KeyAgreement, nil
}

func (cl *Client) SetPIN(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
) error {
	protocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	// Pad pin with zero bytes until
	pinBytes := []byte(pin)
	for i := 0; i < 64-len(pin); i++ {
		pinBytes = append(pinBytes, 0)
	}

	ciphertext, err := protocol.Encrypt(sharedSecret, pinBytes)
	if err != nil {
		return err
	}

	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Number,
		SubCommand:        ctaptypes.ClientPINSubCommandSetPIN,
		KeyAgreement:      platformCoseKey,
		NewPinEnc:         ciphertext,
		PinUvAuthParam: crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			ciphertext,
		),
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("setPIN CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return err
	}
	cl.logger.Debug("setPIN CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ChangePIN(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	keyAgreement key.Key,
	currentPin string,
	newPin string,
) error {
	protocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	// Hash PIN and return the first 16 bytes of hash
	hasher := sha256.New()
	hasher.Write([]byte(currentPin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return err
	}

	newPinBytes := []byte(newPin)
	for i := 0; i < 64-len([]byte(newPin)); i++ {
		newPinBytes = append(newPinBytes, 0)
	}

	newPinEnc, err := protocol.Encrypt(sharedSecret, newPinBytes)
	if err != nil {
		return err
	}

	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Number,
		SubCommand:        ctaptypes.ClientPINSubCommandChangePIN,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		NewPinEnc:         newPinEnc,
		PinUvAuthParam: crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			slices.Concat(newPinEnc, pinHashEnc),
		),
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("changePIN CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return err
	}
	cl.logger.Debug("changePIN CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return err
	}

	return nil
}

// GetPinToken allows getting a PinUvAuthToken (superseded by GetPinUvAuthTokenUsingUvWithPermissions or
// GetPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only).
func (cl *Client) GetPinToken(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
) ([]byte, error) {
	protocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Number,
		SubCommand:        ctaptypes.ClientPINSubCommandGetPinToken,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinToken CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinToken CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// GetPinUvAuthTokenUsingUvWithPermissions allows getting a PinUvAuthToken with specific permissions using User Verification.
func (cl *Client) GetPinUvAuthTokenUsingUvWithPermissions(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	keyAgreement key.Key,
	permissions ctaptypes.Permission,
	rpID string,
) ([]byte, error) {
	protocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Number,
		SubCommand:        ctaptypes.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement:      platformCoseKey,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingUvWithPermissions CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingUvWithPermissions CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

func (cl *Client) GetUVRetries(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
) (uint, error) {
	req := &ctaptypes.AuthenticatorClientPINRequest{
		SubCommand: ctaptypes.ClientPINSubCommandGetUVRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, err
	}
	cl.logger.Debug("getUVRetries CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, err
	}
	cl.logger.Debug("getUVRetries CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, err
	}

	return resp.UvRetries, nil
}

// GetPinUvAuthTokenUsingPinWithPermissions allows getting a PinUvAuthToken with specific permissions using PIN.
func (cl *Client) GetPinUvAuthTokenUsingPinWithPermissions(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
	permissions ctaptypes.Permission,
	rpID string,
) ([]byte, error) {
	protocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := protocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := protocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &ctaptypes.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: protocol.Number,
		SubCommand:        ctaptypes.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingPinWithPermissions CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{byte(ctaptypes.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingPinWithPermissions CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := protocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

func Reset(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
) error {
	_, err := ctaphid.CBOR(device, cid, []byte{byte(ctaptypes.AuthenticatorReset)})
	if err != nil {
		return err
	}

	return nil
}

func (cl *Client) GetBioModality(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{GetModality: true}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getBioModality CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getBioModality CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) GetFingerprintSensorInfo(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandGetFingerprintSensorInfo,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getFingerprintSensorInfo CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getFingerprintSensorInfo CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) BeginEnroll(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.BioEnrollmentSubCommandParams{
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return nil, err
	}
	if timeoutMilliseconds == 0 {
		bSubCommandParams = nil
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandEnrollBegin)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandEnrollBegin,
		SubCommandParams: ctaptypes.BioEnrollmentSubCommandParams{
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enrollBegin CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enrollBegin CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) EnrollCaptureNextSample(device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.BioEnrollmentSubCommandParams{
		TemplateID:          templateID,
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return nil, err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandEnrollCaptureNextSample)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandEnrollCaptureNextSample,
		SubCommandParams: ctaptypes.BioEnrollmentSubCommandParams{
			TemplateID:          templateID,
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enrollCaptureNextSample CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enrollCaptureNextSample CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) CancelCurrentEnrollment(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
) error {
	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandCancelCurrentEnrollment,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("cancelCurrentEnrollment CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) EnumerateEnrollments(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandEnumerateEnrollments)},
	)

	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:          ctaptypes.BioModalityFingerprint,
		SubCommand:        ctaptypes.BioEnrollmentSubCommandEnumerateEnrollments,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enumerateEnrollments CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("enumerateEnrollments CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) SetFriendlyName(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	friendlyName string,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.BioEnrollmentSubCommandParams{
		TemplateID:           templateID,
		TemplateFriendlyName: friendlyName,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandSetFriendlyName)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandSetFriendlyName,
		SubCommandParams: ctaptypes.BioEnrollmentSubCommandParams{
			TemplateID:           templateID,
			TemplateFriendlyName: friendlyName,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("setFriendlyName CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) RemoveEnrollment(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.BioEnrollmentSubCommandParams{
		TemplateID: templateID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandRemoveEnrollment)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorBioEnrollmentRequest{
		Modality:   ctaptypes.BioModalityFingerprint,
		SubCommand: ctaptypes.BioEnrollmentSubCommandRemoveEnrollment,
		SubCommandParams: ctaptypes.BioEnrollmentSubCommandParams{
			TemplateID: templateID,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("removeEnrollment CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorBioEnrollment
	if preview {
		command = ctaptypes.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) GetCredsMetadata(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (*ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(ctaptypes.CredentialManagementSubCommandGetCredsMetadata)},
	)

	req := &ctaptypes.AuthenticatorCredentialManagementRequest{
		SubCommand:        ctaptypes.CredentialManagementSubCommandGetCredsMetadata,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getCredsMetadata CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorCredentialManagement
	if preview {
		command = ctaptypes.PrototypeAuthenticatorCredentialManagement
	}

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getCredsMetadata CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *ctaptypes.AuthenticatorCredentialManagementResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (cl *Client) EnumerateRPs(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) iter.Seq2[*ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			[]byte{byte(ctaptypes.CredentialManagementSubCommandEnumerateRPsBegin)},
		)

		reqBegin := &ctaptypes.AuthenticatorCredentialManagementRequest{
			SubCommand:        ctaptypes.CredentialManagementSubCommandEnumerateRPsBegin,
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("enumerateRPsBegin CBOR request", "hex", hex.EncodeToString(bBegin))

		command := ctaptypes.AuthenticatorCredentialManagement
		if preview {
			command = ctaptypes.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := ctaphid.CBOR(
			device,
			cid,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("enumerateRPsBegin CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin *ctaptypes.AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}

		if respBegin.TotalRPs == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalRPs; i++ {
			reqNext := &ctaptypes.AuthenticatorCredentialManagementRequest{
				SubCommand: ctaptypes.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(nil, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR request", "hex", hex.EncodeToString(bNext))

			respRawNext, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{0x0A}, bNext))
			if err != nil {
				yield(nil, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR response", "hex", hex.EncodeToString(respRawNext.Data))

			var respNext *ctaptypes.AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(nil, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (cl *Client) EnumerateCredentials(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpIDHash []byte,
) iter.Seq2[*ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.CredentialManagementSubCommandParams{RPIDHash: rpIDHash})
		if err != nil {
			yield(nil, err)
			return
		}

		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				[]byte{byte(ctaptypes.CredentialManagementSubCommandEnumerateCredentialsBegin)},
				bSubCommandParams,
			),
		)

		reqBegin := &ctaptypes.AuthenticatorCredentialManagementRequest{
			SubCommand:        ctaptypes.CredentialManagementSubCommandEnumerateCredentialsBegin,
			SubCommandParams:  ctaptypes.CredentialManagementSubCommandParams{RPIDHash: rpIDHash},
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("enumerateCredentialsBegin CBOR request", "hex", hex.EncodeToString(bBegin))

		command := ctaptypes.AuthenticatorCredentialManagement
		if preview {
			command = ctaptypes.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := ctaphid.CBOR(
			device,
			cid,
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(nil, err)
			return
		}
		cl.logger.Debug("enumerateCredentialsBegin CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin *ctaptypes.AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(nil, err)
			return
		}

		if respBegin.TotalCredentials == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalCredentials; i++ {
			reqNext := &ctaptypes.AuthenticatorCredentialManagementRequest{
				SubCommand: ctaptypes.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(nil, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR request", "hex", hex.EncodeToString(bNext))

			respRawNext, err := ctaphid.CBOR(device, cid, slices.Concat([]byte{0x0A}, bNext))
			if err != nil {
				yield(nil, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR response", "hex", hex.EncodeToString(respRawNext.Data))

			var respNext *ctaptypes.AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(nil, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (cl *Client) DeleteCredential(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID webauthntypes.PublicKeyCredentialDescriptor,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.CredentialManagementSubCommandDeleteCredential)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorCredentialManagementRequest{
		SubCommand:        ctaptypes.CredentialManagementSubCommandDeleteCredential,
		SubCommandParams:  ctaptypes.CredentialManagementSubCommandParams{CredentialID: credentialID},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("deleteCredential CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorCredentialManagement
	if preview {
		command = ctaptypes.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) UpdateUserInformation(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	preview bool,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID webauthntypes.PublicKeyCredentialDescriptor,
	user webauthntypes.PublicKeyCredentialUserEntity,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(ctaptypes.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
		User:         user,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(ctaptypes.CredentialManagementSubCommandUpdateUserInformation)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorCredentialManagementRequest{
		SubCommand: ctaptypes.CredentialManagementSubCommandUpdateUserInformation,
		SubCommandParams: ctaptypes.CredentialManagementSubCommandParams{
			CredentialID: credentialID,
			User:         user,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("updateUserInformation CBOR request", "hex", hex.EncodeToString(b))

	command := ctaptypes.AuthenticatorCredentialManagement
	if preview {
		command = ctaptypes.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(command)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) LargeBlobs(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	get uint,
	set []byte,
	offset uint,
	length uint,
) (*ctaptypes.AuthenticatorLargeBlobsResponse, error) {
	req := &ctaptypes.AuthenticatorLargeBlobsRequest{
		Get:    get,
		Set:    set,
		Offset: offset,
		Length: length,
	}

	if pinUvAuthToken != nil {
		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		offsetBin := make([]byte, 4)
		binary.LittleEndian.PutUint32(offsetBin, uint32(offset))

		hasher := sha256.New()
		hasher.Reset()
		hasher.Write(set)
		hash := hasher.Sum(nil)

		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0c, 0x00},
				offsetBin,
				hash,
			),
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("largeBlobs set CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(ctaptypes.AuthenticatorLargeBlobs)}, b),
	)
	if err != nil {
		return nil, err
	}

	if get > 0 {
		var resp *ctaptypes.AuthenticatorLargeBlobsResponse
		if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
			return nil, err
		}

		return resp, nil
	}

	return nil, nil
}

func (cl *Client) EnableEnterpriseAttestation(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ctaptypes.ConfigSubCommandEnableEnterpriseAttestation)},
		),
	)

	req := &ctaptypes.AuthenticatorConfigRequest{
		SubCommand:        ctaptypes.ConfigSubCommandEnableEnterpriseAttestation,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("enableEnterpriseAttestation CBOR request", "hex", hex.EncodeToString(b))

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(ctaptypes.AuthenticatorConfig)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ToggleAlwaysUV(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ctaptypes.ConfigSubCommandToggleAlwaysUv)},
		),
	)

	req := &ctaptypes.AuthenticatorConfigRequest{
		SubCommand:        ctaptypes.ConfigSubCommandToggleAlwaysUv,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("toggleAlwaysUv CBOR request", "hex", hex.EncodeToString(b))

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(ctaptypes.AuthenticatorConfig)}, b),
	); err != nil {
		return err
	}

	return nil
}

func (cl *Client) SetMinPINLength(
	device io.ReadWriter,
	cid ctaphid.ChannelID,
	pinUvAuthProtocol ctaptypes.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	subCommandParams := &ctaptypes.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:     newMinPINLength,
		MinPinLengthRPIDs:   minPinLengthRPIDs,
		ForceChangePin:      forceChangePin,
		PinComplexityPolicy: pinComplexityPolicy,
	}
	bSubCommandParams, err := cl.encMode.Marshal(subCommandParams)
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(ctaptypes.ConfigSubCommandSetMinPINLength)},
			bSubCommandParams,
		),
	)

	req := &ctaptypes.AuthenticatorConfigRequest{
		SubCommand:        ctaptypes.ConfigSubCommandSetMinPINLength,
		SubCommandParams:  subCommandParams,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("SetMinPINLength CBOR request", "hex", hex.EncodeToString(b))

	if _, err := ctaphid.CBOR(
		device,
		cid,
		slices.Concat([]byte{byte(ctaptypes.AuthenticatorConfig)}, b),
	); err != nil {
		return err
	}

	return nil
}

// Selection blocks execution until the user will confirm his presence or operation will be canceled.
func (cl *Client) Selection(device io.ReadWriter, cid ctaphid.ChannelID) error {
	_, err := ctaphid.CBOR(device, cid, []byte{byte(ctaptypes.AuthenticatorSelection)})
	if err != nil {
		var ctapError *ctaphid.CTAPError
		if !errors.As(err, &ctapError) || ctapError.StatusCode != ctaphid.CTAP2_ERR_KEEPALIVE_CANCEL {
			return err
		}
	}

	return nil
}
