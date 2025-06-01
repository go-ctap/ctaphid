package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/ldclabs/cose/key"
	"github.com/samber/lo"
	"github.com/savely-krasovsky/go-ctaphid/pkg/crypto"
	"github.com/savely-krasovsky/go-ctaphid/pkg/ctap"
	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaphid"
	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"

	"github.com/sstallion/go-hid"
)

// Device represents a physical or virtual hardware device supporting CTAP communication protocols.
type Device struct {
	Path       string
	device     *hid.Device
	cid        [4]byte
	info       *ctaptypes.AuthenticatorGetInfoResponse
	ctapClient *ctap.Client
	encMode    cbor.EncMode
}

// New creates a new Device instance from a given HID path.
// It also initializes a new underlying CTAP2 client with the provided options.
func New(path string, opts ...ctap.ClientOption) (*Device, error) {
	dev, err := hid.OpenPath(path)
	if err != nil {
		return nil, err
	}

	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	d := &Device{
		Path:    path,
		device:  dev,
		encMode: encMode,
	}

	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	msg, err := ctaphid.Init(dev, ctaphid.BROADCAST_CID, nonce)
	if err != nil {
		return nil, err
	}
	d.cid = msg.CID

	// Init CTAP2 client
	d.ctapClient = ctap.NewClient(opts...)

	info, err := d.ctapClient.GetInfo(d.device, d.cid)
	if err != nil {
		return nil, err
	}
	d.info = info

	return d, nil
}

// Close closes the underlying HID device.
func (d *Device) Close() error {
	return d.device.Close()
}

// Ping sends a ping message to the device and verifies the response matches the sent data.
// Returns an error on failure.
func (d *Device) Ping(ping []byte) error {
	pong, err := ctaphid.Ping(d.device, d.cid, ping)
	if err != nil {
		return err
	}

	if !bytes.Equal(ping, pong.Bytes) {
		return ErrPingPongMismatch
	}

	return nil
}

// Wink sends a blink command to the device to visually signal its presence to the user.
// It uses the CTAPHID_WINK command which is optional and could be unsupported by some devices.
func (d *Device) Wink() error {
	return ctaphid.Wink(d.device, d.cid)
}

// Lock places an exclusive lock for one channel to communicate with the device.
// As long as the lock is active, any other channel trying to send a message will fail.
// Send 0 seconds to unlock the channel.
func (d *Device) Lock(seconds uint) error {
	return ctaphid.Lock(d.device, d.cid, uint8(seconds))
}

// MakeCredential initiates the process of creating a new credential on a device with specified parameters and options.
func (d *Device) MakeCredential(
	pinUvAuthToken []byte,
	clientDataHash []byte,
	rp ctaptypes.PublicKeyCredentialRpEntity,
	user ctaptypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []ctaptypes.PublicKeyCredentialParameters,
	excludeList []ctaptypes.PublicKeyCredentialDescriptor,
	extensions map[ctaptypes.ExtensionIdentifier]any,
	options map[ctaptypes.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []ctaptypes.AttestationStatementFormatIdentifier,
) (*ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	notRequired, ok := d.info.Options[ctaptypes.OptionMakeCredentialUvNotRequired]
	if (!ok || !notRequired) && pinUvAuthToken == nil {
		return nil, ErrPinUvAuthTokenRequired
	}

	return d.ctapClient.MakeCredential(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		clientDataHash,
		rp,
		user,
		pubKeyCredParams,
		excludeList,
		extensions,
		options,
		enterpriseAttestation,
		attestationFormatsPreference,
	)
}

// GetAssertion provides a generator function to iterate over assertions stored on the device
// for the specified Relying Party, clientDataHash, and allowed list (in case of non-discoverable credentials).
// It yields results via a callback function.
func (d *Device) GetAssertion(
	pinUvAuthToken []byte,
	rpID string,
	clientDataHash []byte,
	allowList []ctaptypes.PublicKeyCredentialDescriptor,
	extensions map[ctaptypes.ExtensionIdentifier]any,
	options map[ctaptypes.Option]bool,
) func(yield func(*ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {
	return func(yield func(*ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {
		var (
			protocol     *crypto.PinUvAuthProtocol
			sharedSecret []byte
		)

		hmacGetSecretInput, ok := extensions[ctaptypes.ExtensionIdentifierHMACSecret]
		if ok {
			input, ok := hmacGetSecretInput.(*HMACSecretInput)
			if !ok {
				yield(nil, newErrorMessage(ErrBadType, "*device.HMACSecretInput was expected"))
				return
			}
			salt := slices.Concat(input.Salt1, input.Salt2)

			var err error
			protocol, err = crypto.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
			if err != nil {
				yield(nil, err)
				return
			}

			var platformCoseKey key.Key
			platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(nil, err)
				return
			}

			saltEnc, err := protocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(nil, err)
				return
			}

			saltAuth := crypto.Authenticate(
				d.info.PinUvAuthProtocols[0],
				sharedSecret,
				saltEnc,
			)

			extensions[ctaptypes.ExtensionIdentifierHMACSecret] = ctaptypes.AuthenticatorGetAssertionHMACSecretInput{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
			}
		}

		for assertion, err := range d.ctapClient.GetAssertion(
			d.device,
			d.cid,
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			rpID,
			clientDataHash,
			allowList,
			extensions,
			options,
		) {
			if err != nil {
				yield(assertion, err)
				return
			}

			// Yield assertions without extension data
			if !assertion.AuthData.ExtensionDataIncluded() {
				yield(assertion, err)
				return
			}

			// Yield assertions without hmac-secret extension payload
			encryptedSalt, ok := assertion.AuthData.Extensions[ctaptypes.ExtensionIdentifierHMACSecret]
			if !ok {
				yield(assertion, err)
				return
			}

			b, ok := encryptedSalt.([]byte)
			if !ok {
				yield(nil, newErrorMessage(ErrBadType, "[]byte was expected"))
				return
			}

			salt, err := protocol.Decrypt(sharedSecret, b)
			if err != nil {
				yield(nil, err)
				return
			}

			switch len(salt) {
			case 32:
				assertion.AuthData.Extensions[ctaptypes.ExtensionIdentifierHMACSecret] = &HMACSecretOutput{
					Output1: salt,
				}
			case 64:
				assertion.AuthData.Extensions[ctaptypes.ExtensionIdentifierHMACSecret] = &HMACSecretOutput{
					Output1: salt[:32],
					Output2: salt[32:],
				}
			default:
				yield(nil, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes"))
				return
			}

			if !yield(assertion, err) {
				return
			}
		}
	}
}

// GetInfo returns the struct containing metadata and capabilities of the device.
func (d *Device) GetInfo() *ctaptypes.AuthenticatorGetInfoResponse {
	return d.info
}

// GetPINRetries retrieves the number of PIN retries remaining for the device, and if it requires a power cycle
// (after reaching the limit, you can reset remaining tries by re-connecting the token).
func (d *Device) GetPINRetries() (uint, bool, error) {
	clientPin, ok := d.info.Options[ctaptypes.OptionClientPIN]
	if !ok {
		return 0, false, newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return 0, false, newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	return d.ctapClient.GetPINRetries(d.device, d.cid, d.info.PinUvAuthProtocols[0])
}

// SetPIN sets a new PIN on the device if the clientPin option is supported and no PIN exists.
// Returns an error if the device does not support clientPin or if it was already set with PIN.
func (d *Device) SetPIN(pin string) error {
	clientPin, ok := d.info.Options[ctaptypes.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if clientPin {
		return newErrorMessage(ErrPinAlreadySet, "pin already set, use changePin instead")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
	if err != nil {
		return err
	}

	return d.ctapClient.SetPIN(d.device, d.cid, d.info.PinUvAuthProtocols[0], keyAgreement, pin)
}

// ChangePIN updates the device's PIN by using the provided current PIN and new PIN.
// Returns an error if the device does not support clientPin or if the PIN change process fails.
func (d *Device) ChangePIN(currentPin, newPin string) error {
	clientPin, ok := d.info.Options[ctaptypes.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
	if err != nil {
		return err
	}

	return d.ctapClient.ChangePIN(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		currentPin,
		newPin,
	)
}

// GetPinUvAuthTokenUsingPIN obtains a pinUvAuthToken using a given PIN, permission, and in some cases optional
// Relying Party ID. Returns a token as a byte slice or an error if the operation fails.
// Checks device capabilities and permissions before proceeding.
func (d *Device) GetPinUvAuthTokenUsingPIN(
	pin string,
	permission ctaptypes.Permission,
	rpID string,
) ([]byte, error) {
	noMcGaPermission, ok := d.info.Options[ctaptypes.OptionNoMcGaPermissionsWithClientPin]
	if ok && noMcGaPermission && (permission&ctaptypes.PermissionMakeCredential != 0 || permission&ctaptypes.PermissionGetAssertion != 0) {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN with MakeCredential or GetAssertion permissions if device has noMcGaPermissionsWithClientPin option",
		)
	}

	clientPIN, ok := d.info.Options[ctaptypes.OptionClientPIN]
	if !ok {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN if device hasn't clientPin option",
		)
	}
	if !clientPIN {
		return nil, newErrorMessage(
			ErrPinNotSet,
			"please set PIN first",
		)
	}

	uvBioEnroll, ok := d.info.Options[ctaptypes.OptionUvBioEnroll]
	if (!ok || !uvBioEnroll) && permission&ctaptypes.PermissionBioEnrollment != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be BioEnrollment permission if device doesn't support uvBioEnroll option",
		)
	}

	authnrCfg, ok := d.info.Options[ctaptypes.OptionAuthenticatorConfig]
	if (!ok || !authnrCfg) && permission&ctaptypes.PermissionAuthenticatorConfiguration != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be AuthenticatorConfiguration permission if device doesn't support uv option")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
	if err != nil {
		return nil, err
	}

	token, ok := d.info.Options[ctaptypes.OptionPinUvAuthToken]
	if !ok || !token {
		return d.ctapClient.GetPinToken(
			d.device,
			d.cid,
			d.info.PinUvAuthProtocols[0],
			keyAgreement,
			pin,
		)
	}

	return d.ctapClient.GetPinUvAuthTokenUsingPinWithPermissions(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		pin,
		permission,
		rpID,
	)
}

// GetPinUvAuthTokenUsingUV obtains a pinUvAuthToken by performing user verification (UV) on a compatible device.
// Returns an error if the device does not support pinUvAuthToken or user verification features.
// Requires the permission type and optionally Relying Party ID (rpID) in some cases to execute successfully.
func (d *Device) GetPinUvAuthTokenUsingUV(permission ctaptypes.Permission, rpID string) ([]byte, error) {
	token, ok := d.info.Options[ctaptypes.OptionPinUvAuthToken]
	if !ok || !token {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support pinUvAuthToken")
	}

	uv, ok := d.info.Options[ctaptypes.OptionUserVerification]
	if !ok {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return nil, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
	if err != nil {
		return nil, err
	}

	return d.ctapClient.GetPinUvAuthTokenUsingUvWithPermissions(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		keyAgreement,
		permission,
		rpID,
	)
}

// GetUVRetries retrieves the number of remaining user verification retries from the device.
// Returns an error if the device does not support user verification.
func (d *Device) GetUVRetries() (uint, error) {
	uv, ok := d.info.Options[ctaptypes.OptionUserVerification]
	if !ok {
		return 0, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return 0, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	return d.ctapClient.GetUVRetries(d.device, d.cid)
}

// Reset performs a factory reset on the device, clearing all stored user data and resetting it to its default state.
// Some devices require doing reset within 10 seconds after you connected the token.
func (d *Device) Reset() error {
	return ctap.Reset(d.device, d.cid)
}

// GetCredsMetadata retrieves credential management metadata if the device supports it.
// Mainly ExistingResidentCredentialsCount and MaxPossibleRemainingResidentCredentialsCount.
func (d *Device) GetCredsMetadata(pinUvAuthToken []byte) (*ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	credMgmt, ok := d.info.Options[ctaptypes.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctaptypes.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.GetCredsMetadata(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// EnumerateRPs provides a generator function to iterate over Relying Parties stored on the device.
// It utilizes the Credential Management extension and yields results via a callback function.
// If the device does not support credential management, an error is yielded.
func (d *Device) EnumerateRPs(pinUvAuthToken []byte) func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		credMgmt, ok := d.info.Options[ctaptypes.OptionCredentialManagement]
		if d.info.Versions.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[ctaptypes.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
		}

		for rp, err := range d.ctapClient.EnumerateRPs(
			d.device,
			d.cid,
			d.info.Versions.IsPreviewOnly(),
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// EnumerateCredentials provides a generator function to iterate over Credentials stored on the device
// for the specified Relying Party. It utilizes the Credential Management extension and yields results
// via a callback function. If the device does not support credential management, an error is yielded.
func (d *Device) EnumerateCredentials(pinUvAuthToken []byte, rpIDHash []byte) func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		credMgmt, ok := d.info.Options[ctaptypes.OptionCredentialManagement]
		if d.info.Versions.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[ctaptypes.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(nil, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
		}

		for rp, err := range d.ctapClient.EnumerateCredentials(
			d.device,
			d.cid,
			d.info.Versions.IsPreviewOnly(),
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			rpIDHash,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// DeleteCredential removes a specified credential from the device using the given authentication token.
// It returns an error if credential management is not supported or the operation fails.
func (d *Device) DeleteCredential(
	pinUvAuthToken []byte,
	credentialID ctaptypes.PublicKeyCredentialDescriptor,
) error {
	credMgmt, ok := d.info.Options[ctaptypes.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctaptypes.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.DeleteCredential(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		credentialID,
	)
}

// UpdateUserInformation updates information of an existing user credential on the device.
// Requires the device to support credential management features.
// Returns an error if the operation is not supported or fails.
func (d *Device) UpdateUserInformation(
	pinUvAuthToken []byte,
	credentialID ctaptypes.PublicKeyCredentialDescriptor,
	user ctaptypes.PublicKeyCredentialUserEntity,
) error {
	credMgmt, ok := d.info.Options[ctaptypes.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[ctaptypes.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	return d.ctapClient.UpdateUserInformation(
		d.device,
		d.cid,
		false, //d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		credentialID,
		user,
	)
}

// GetLargeBlobs retrieves a list of large blobs from the device that supports the large blobs option.
// Returns an error if the device does not support large blobs or if there is an issue with the retrieval process.
// Ensures integrity by validating computed and actual hashes of the retrieved data.
func (d *Device) GetLargeBlobs() ([]*ctaptypes.LargeBlob, error) {
	largeBlobs, ok := d.info.Options[ctaptypes.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	maxFragmentLength := d.info.MaxMsgSize - 64

	resp, err := d.ctapClient.LargeBlobs(
		d.device,
		d.cid,
		0,
		nil,
		maxFragmentLength,
		nil,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}

	config := resp.Config
	offset := maxFragmentLength

	// Continue to read
	for uint(len(config)) == maxFragmentLength {
		respNext, err := d.ctapClient.LargeBlobs(
			d.device,
			d.cid,
			0,
			nil,
			maxFragmentLength,
			nil,
			offset,
			0,
		)
		if err != nil {
			return nil, err
		}

		config = slices.Concat(config, respNext.Config)
		offset += uint(len(respNext.Config))
	}

	bLargeBlobs := config[:len(config)-16]
	hash := config[len(config)-16:]

	hasher := sha256.New()
	hasher.Write(bLargeBlobs)
	if !slices.Equal(hash, hasher.Sum(nil)[:16]) {
		return nil, newErrorMessage(ErrLargeBlobsIntegrityCheck, "for some reason calculated and actual hashes mismatch")
	}

	var blobs []*ctaptypes.LargeBlob
	if err := cbor.Unmarshal(bLargeBlobs, &blobs); err != nil {
		return nil, err
	}

	return blobs, nil
}

// SetLargeBlobs stores large blobs on the device, ensuring compatibility with its supported capabilities and limits.
// It validates device support, fragments the blob data if needed, and sends it in chunks to the device.
// Returns an error if the device does not support large blobs, the data exceeds size limits, or if any other failure occurs.
func (d *Device) SetLargeBlobs(pinUvAuthToken []byte, blobs []*ctaptypes.LargeBlob) error {
	largeBlobs, ok := d.info.Options[ctaptypes.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	set, err := d.encMode.Marshal(blobs)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write(set)
	hash := hasher.Sum(nil)

	set = slices.Concat(set, hash[:16])

	if uint(len(set)) > d.info.MaxSerializedLargeBlobArray {
		return newErrorMessage(
			ErrLargeBlobsTooBig,
			fmt.Sprintf(
				"this device max serialized large blob size is %db while you are trying to save %db",
				d.info.MaxSerializedLargeBlobArray,
				len(set),
			),
		)
	}

	maxFragmentLength := d.info.MaxMsgSize - 64
	offset := uint(0)
	length := uint(len(set))

	setChunks := lo.Chunk(set, int(maxFragmentLength))
	for i, chunk := range setChunks {
		if i > 0 {
			length = 0
		}

		if _, err := d.ctapClient.LargeBlobs(
			d.device,
			d.cid,
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			0,
			chunk,
			offset,
			length,
		); err != nil {
			return err
		}

		offset += uint(len(chunk))
	}

	return nil
}

// ToggleAlwaysUV toggles the always UV (User Verification) setting on the device if supported, using the provided token.
func (d *Device) ToggleAlwaysUV(pinUvAuthToken []byte) error {
	if authnrCfg, ok := d.info.Options[ctaptypes.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}

	if _, ok := d.info.Options[ctaptypes.OptionAlwaysUv]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support alwaysUv")
	}

	return d.ctapClient.ToggleAlwaysUV(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

func (d *Device) SetMinPINLength(
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	if authnrCfg, ok := d.info.Options[ctaptypes.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}

	return d.ctapClient.SetMinPINLength(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		newMinPINLength,
		minPinLengthRPIDs,
		forceChangePin,
		pinComplexityPolicy,
	)
}

// Selection is a higher-level version of ctap.Selection, which cancels the
// command if the context is canceled.
func (d *Device) Selection(ctx context.Context) error {
	errc := make(chan error, 1)

	go func() {
		if err := d.ctapClient.Selection(d.device, d.cid); err != nil {
			errc <- err
		}
		errc <- nil
	}()

	select {
	case <-ctx.Done():
		if err := ctaphid.Cancel(d.device, d.cid); err != nil {
			return errors.Join(err, <-errc)
		}
		return <-errc
	case err := <-errc:
		return err
	}
}
