package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/ldclabs/cose/key"
	"github.com/samber/lo"

	"github.com/go-ctap/ctaphid/pkg/crypto"
	"github.com/go-ctap/ctaphid/pkg/ctap"
	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/options"
)

// Device represents a physical or virtual hardware device supporting CTAP communication protocols.
type Device struct {
	Path       string
	device     io.ReadWriteCloser
	cid        [4]byte
	info       *ctaptypes.AuthenticatorGetInfoResponse
	ctapClient *ctap.Client
	encMode    cbor.EncMode
	mu         sync.Mutex // global mutex to serialize requests to the device
}

type CtxKey = string

const (
	CtxKeyUseNamedPipe CtxKey = "useNamedPipe"
)

// New creates a new Device instance from a given HID path.
// It also initializes a new underlying CTAP2 client with the provided options.
func New(path string, opts ...options.Option) (*Device, error) {
	oo := options.NewOptions(opts...)

	ctx := context.WithValue(oo.Context, CtxKeyUseNamedPipe, oo.UseNamedPipe)
	dev, err := OpenPath(ctx, path)
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = dev.Close()
		}
	}()

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

	cleanup = false
	return d, nil
}

// Close closes the underlying HID device.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.device.Close(); err != nil {
		return err
	}

	return hidExit()
}

// Ping sends a ping message to the device and verifies the response matches the sent data.
// Returns an error on failure.
func (d *Device) Ping(ping []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

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
// It uses the CTAPHID_WINK command, which is optional and could be unsupported by some devices.
func (d *Device) Wink() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return ctaphid.Wink(d.device, d.cid)
}

// Lock places an exclusive lock for one channel to communicate with the device.
// As long as the lock is active, any other channel trying to send a message will fail.
// Send 0 seconds to unlock the channel.
func (d *Device) Lock(seconds uint) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return ctaphid.Lock(d.device, d.cid, uint8(seconds))
}

// MakeCredential initiates the process of creating a new credential on a device with specified parameters and options.
func (d *Device) MakeCredential(
	pinUvAuthToken []byte,
	clientData []byte,
	rp webauthntypes.PublicKeyCredentialRpEntity,
	user webauthntypes.PublicKeyCredentialUserEntity,
	pubKeyCredParams []webauthntypes.PublicKeyCredentialParameters,
	excludeList []webauthntypes.PublicKeyCredentialDescriptor,
	extInputs *webauthntypes.CreateAuthenticationExtensionsClientInputs,
	options map[ctaptypes.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []webauthntypes.AttestationStatementFormatIdentifier,
) (*ctaptypes.AuthenticatorMakeCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	notRequired, ok := d.info.Options[ctaptypes.OptionMakeCredentialUvNotRequired]
	if (!ok || !notRequired) && pinUvAuthToken == nil {
		return nil, ErrPinUvAuthTokenRequired
	}

	var (
		protocol     *crypto.PinUvAuthProtocol
		sharedSecret []byte
	)

	extensions := new(ctaptypes.CreateExtensionInputs)
	if extInputs == nil {
		extInputs = &webauthntypes.CreateAuthenticationExtensionsClientInputs{}
	}

	if extInputs.LargeBlobInputs != nil {
		return nil, newErrorMessage(SyntaxError, "largeBlob extension is not supported yet")
	}

	if extInputs.CreateHMACSecretMCInputs != nil && extInputs.PRFInputs != nil {
		return nil, newErrorMessage(SyntaxError, "you cannot use hmac-secret and prf extensions at the same time")
	}

	// hmac-secret
	if extInputs.CreateHMACSecretInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierHMACSecret) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret extension")
		}

		extensions.CreateHMACSecretInput = &ctaptypes.CreateHMACSecretInput{
			HMACSecret: extInputs.HMACCreateSecret,
		}
	}

	// hmac-secret-mc
	if extInputs.CreateHMACSecretMCInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierHMACSecretMC) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret-mc extension")
		}

		salt := slices.Concat(
			extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt1,
			extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt2,
		)

		var err error
		protocol, err = crypto.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
		if err != nil {
			return nil, err
		}

		saltEnc, err := protocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return nil, err
		}

		saltAuth := crypto.Authenticate(
			d.info.PinUvAuthProtocols[0],
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &ctaptypes.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &ctaptypes.CreateHMACSecretMCInput{
			HMACSecret: ctaptypes.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
			},
		}
	}

	// prf
	if extInputs.PRFInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierHMACSecretMC) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support prf extension during registration")
		}

		if extInputs.PRF.EvalByCredential != nil {
			return nil, newErrorMessage(ErrNotSupported, "evalByCredential is not supported during registration")
		}

		if extInputs.PRF.Eval == nil {
			return nil, newErrorMessage(SyntaxError, "eval is empty")
		}

		hasher := sha256.New()
		hasher.Write([]byte("WebAuthn PRF"))
		hasher.Write([]byte{0x00})
		hasher.Write(extInputs.PRF.Eval.First)
		salt := hasher.Sum(nil)

		if extInputs.PRF.Eval.Second != nil {
			hasher.Reset()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(extInputs.PRF.Eval.Second)
			salt = slices.Concat(salt, hasher.Sum(nil))
		}

		var err error
		protocol, err = crypto.NewPinUvAuthProtocol(d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		keyAgreement, err := d.ctapClient.GetKeyAgreement(d.device, d.cid, d.info.PinUvAuthProtocols[0])
		if err != nil {
			return nil, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = protocol.Encapsulate(keyAgreement)
		if err != nil {
			return nil, err
		}

		saltEnc, err := protocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return nil, err
		}

		saltAuth := crypto.Authenticate(
			d.info.PinUvAuthProtocols[0],
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &ctaptypes.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &ctaptypes.CreateHMACSecretMCInput{
			HMACSecret: ctaptypes.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
			},
		}
	}

	// credProtection
	if extInputs.CreateCredentialProtectionInputs != nil {
		var credProtect int

		switch extInputs.CredentialProtectionPolicy {
		case webauthntypes.CredentialProtectionPolicyUserVerificationOptional:
			credProtect = 0x01
		case webauthntypes.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
			credProtect = 0x02
		case webauthntypes.CredentialProtectionPolicyUserVerificationRequired:
			credProtect = 0x03
		default:
			return nil, newErrorMessage(ErrNotSupported, "invalid credential protection policy")
		}

		if extInputs.EnforceCredentialProtectionPolicy &&
			extInputs.CredentialProtectionPolicy != webauthntypes.CredentialProtectionPolicyUserVerificationOptional &&
			!slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierCredentialProtection) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support credProtect extension")
		}

		extensions.CreateCredProtectInput = &ctaptypes.CreateCredProtectInput{
			CredProtect: credProtect,
		}
	}

	// credBlob
	if extInputs.CreateCredentialBlobInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierCredentialBlob) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support credBlob extension")
		}

		if uint(len(extInputs.CredBlob)) > d.info.MaxCredBlobLength {
			return nil, newErrorMessage(
				ErrNotSupported,
				fmt.Sprintf("credBlob length must be less than %d bytes", d.info.MaxCredBlobLength),
			)
		}

		extensions.CreateCredBlobInput = &ctaptypes.CreateCredBlobInput{
			CredBlob: extInputs.CredBlob,
		}
	}

	// minPinLength
	if extInputs.CreateMinPinLengthInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierMinPinLength) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support minPinLength extension")
		}

		extensions.CreateMinPinLengthInput = &ctaptypes.CreateMinPinLengthInput{
			MinPinLength: extInputs.MinPinLength,
		}
	}
	if extInputs.CreatePinComplexityPolicyInputs != nil {
		if !slices.Contains(d.info.Extensions, webauthntypes.ExtensionIdentifierPinComplexityPolicy) {
			return nil, newErrorMessage(ErrNotSupported, "device doesn't support pinComplexityPolicy extension")
		}

		extensions.CreatePinComplexityPolicyInput = &ctaptypes.CreatePinComplexityPolicyInput{
			PinComplexityPolicy: extInputs.PinComplexityPolicy,
		}
	}

	resp, err := d.ctapClient.MakeCredential(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		clientData,
		rp,
		user,
		pubKeyCredParams,
		excludeList,
		extensions,
		options,
		enterpriseAttestation,
		attestationFormatsPreference,
	)
	if err != nil {
		return nil, err
	}

	extOutputs := new(webauthntypes.CreateAuthenticationExtensionsClientOutputs)
	resp.ExtensionOutputs = extOutputs

	if extInputs.CreateCredentialProtectionInputs != nil && extInputs.CredentialProperties {
		extOutputs.CreateCredentialPropertiesOutputs = &webauthntypes.CreateCredentialPropertiesOutputs{
			CredentialProperties: webauthntypes.CredentialPropertiesOutput{
				ResidentKey: options[ctaptypes.OptionResidentKeys],
			},
		}
	}

	if !resp.AuthData.Flags.ExtensionDataIncluded() {
		return resp, nil
	}

	// credBlob
	if resp.AuthData.Extensions.CreateCredBlobOutput != nil {
		extOutputs.CreateCredentialBlobOutputs = &webauthntypes.CreateCredentialBlobOutputs{
			CredBlob: resp.AuthData.Extensions.CreateCredBlobOutput.CredBlob,
		}
	}

	// hmac-secret
	if resp.AuthData.Extensions.CreateHMACSecretOutput != nil {
		extOutputs.CreateHMACSecretOutputs = &webauthntypes.CreateHMACSecretOutputs{
			HMACCreateSecret: resp.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret,
		}
	}

	// hmac-secret-mc (it needs tests, thought I cannot find any devices that support it yet)
	if resp.AuthData.Extensions.CreateHMACSecretMCOutput != nil {
		salt, err := protocol.Decrypt(sharedSecret, resp.AuthData.Extensions.CreateHMACSecretMCOutput.HMACSecret)
		if err != nil {
			return nil, err
		}

		switch len(salt) {
		case 32:
			extOutputs.PRFOutputs = &webauthntypes.PRFOutputs{
				PRF: webauthntypes.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthntypes.AuthenticationExtensionsPRFValues{
						First: salt[:32],
					},
				},
			}
		case 64:
			extOutputs.PRFOutputs = &webauthntypes.PRFOutputs{
				PRF: webauthntypes.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthntypes.AuthenticationExtensionsPRFValues{
						First:  salt[:32],
						Second: salt[32:],
					},
				},
			}
		default:
			return nil, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes")
		}
	}

	return resp, nil
}

// GetAssertion provides a generator function to iterate over assertions stored on the device
// for the specified Relying Party, clientDataHash, and allowed list (in case of non-discoverable credentials).
// It yields results via a callback function.
func (d *Device) GetAssertion(
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []webauthntypes.PublicKeyCredentialDescriptor,
	extInputs *webauthntypes.GetAuthenticationExtensionsClientInputs,
	options map[ctaptypes.Option]bool,
) iter.Seq2[*ctaptypes.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorGetAssertionResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		var (
			protocol     *crypto.PinUvAuthProtocol
			sharedSecret []byte
		)

		extensions := new(ctaptypes.GetExtensionInputs)
		if extInputs == nil {
			extInputs = &webauthntypes.GetAuthenticationExtensionsClientInputs{}
		}

		if extInputs.LargeBlobInputs != nil {
			yield(nil, newErrorMessage(SyntaxError, "largeBlob extension is not supported yet"))
			return
		}

		if extInputs.PRFInputs != nil && extInputs.GetHMACSecretInputs != nil {
			yield(nil, newErrorMessage(SyntaxError, "you cannot use hmac-secret and prf extensions at the same time"))
			return
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil {
			salt := slices.Concat(
				extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1,
				extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2,
			)

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

			extensions.GetHMACSecretInput = &ctaptypes.GetHMACSecretInput{
				HMACSecret: ctaptypes.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
				},
			}
		}

		// prf
		if extInputs.PRFInputs != nil {
			if extInputs.PRF.EvalByCredential != nil && (allowList == nil || len(allowList) == 0) {
				yield(nil, newErrorMessage(ErrNotSupported, "evalByCredential works only in conjunction with allowList"))
				return
			}

			var ev *webauthntypes.AuthenticationExtensionsPRFValues
			var ids [][]byte
			for idStr := range extInputs.PRF.EvalByCredential {
				id, err := base64.URLEncoding.DecodeString(idStr)
				if err != nil {
					yield(nil, newErrorMessage(SyntaxError, "invalid credential id"))
					return
				}

				ids = append(ids, id)
			}

			for _, id := range ids {
				desc, found := lo.Find(allowList, func(descriptor webauthntypes.PublicKeyCredentialDescriptor) bool {
					if slices.Equal(descriptor.ID, id) {
						return true
					}
					return false
				})
				if found {
					v, ok := extInputs.PRF.EvalByCredential[base64.URLEncoding.EncodeToString(desc.ID)]
					if ok {
						ev = &v
					}
				}
			}

			if ev == nil && extInputs.PRF.Eval != nil {
				ev = extInputs.PRF.Eval
			}

			hasher := sha256.New()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(ev.First)
			salt := hasher.Sum(nil)

			if ev.Second != nil {
				hasher.Reset()
				hasher.Write([]byte("WebAuthn PRF"))
				hasher.Write([]byte{0x00})
				hasher.Write(ev.Second)
				salt = slices.Concat(salt, hasher.Sum(nil))
			}

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

			extensions.GetHMACSecretInput = &ctaptypes.GetHMACSecretInput{
				HMACSecret: ctaptypes.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: d.info.PinUvAuthProtocols[0],
				},
			}
		}

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil {
			extensions.GetCredBlobInput = &ctaptypes.GetCredBlobInput{
				CredBlob: extInputs.GetCredBlob,
			}
		}

		for assertion, err := range d.ctapClient.GetAssertion(
			d.device,
			d.cid,
			d.info.PinUvAuthProtocols[0],
			pinUvAuthToken,
			rpID,
			clientData,
			allowList,
			extensions,
			options,
		) {
			if err != nil {
				yield(nil, err)
				return
			}

			assertion.ExtensionOutputs = new(webauthntypes.GetAuthenticationExtensionsClientOutputs)

			// Yield assertions without extension data
			if !assertion.AuthData.Flags.ExtensionDataIncluded() {
				yield(assertion, nil)
				return
			}

			// credBlob
			if assertion.AuthData.Extensions.GetCredBlobOutput != nil {
				assertion.ExtensionOutputs.GetCredentialBlobOutputs = &webauthntypes.GetCredentialBlobOutputs{
					GetCredBlob: assertion.AuthData.Extensions.GetCredBlobOutput.CredBlob,
				}
			}

			// hmac-secret or prf
			if assertion.AuthData.Extensions.GetHMACSecretOutput != nil {
				salt, err := protocol.Decrypt(sharedSecret, assertion.AuthData.Extensions.HMACSecret)
				if err != nil {
					yield(nil, err)
					return
				}

				switch len(salt) {
				case 32:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthntypes.GetHMACSecretOutputs{
							HMACGetSecret: webauthntypes.HMACGetSecretOutput{
								Output1: salt[:32],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthntypes.PRFOutputs{
							PRF: webauthntypes.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthntypes.AuthenticationExtensionsPRFValues{
									First: salt[:32],
								},
							},
						}
					}
				case 64:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthntypes.GetHMACSecretOutputs{
							HMACGetSecret: webauthntypes.HMACGetSecretOutput{
								Output1: salt[:32],
								Output2: salt[32:],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthntypes.PRFOutputs{
							PRF: webauthntypes.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthntypes.AuthenticationExtensionsPRFValues{
									First:  salt[:32],
									Second: salt[32:],
								},
							},
						}
					}
				default:
					yield(nil, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes"))
					return
				}
			}

			if !yield(assertion, nil) {
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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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

	if _, ok := d.info.Options[ctaptypes.OptionBioEnroll]; !ok && permission&ctaptypes.PermissionBioEnrollment != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be BioEnrollment permission if device doesn't support bioEnroll option",
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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

	return ctap.Reset(d.device, d.cid)
}

// GetBioModality returns bio modality of authenticator.
// Currently, only fingerprint modality is defined in the FIDO 2.2 specification.
func (d *Device) GetBioModality() (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetBioModality(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
	)
}

// GetFingerprintSensorInfo returns three properties:
//
//		FingerprintKind: For touch type fingerprints, its value is 1. For swipe type fingerprints, its value is 2.
//		MaxCaptureSamplesRequiredForEnroll: Indicates the maximum good samples required for enrollment.
//	 	MaxTemplateFriendlyName: Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
func (d *Device) GetFingerprintSensorInfo() (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetFingerprintSensorInfo(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
	)
}

// BeginEnroll begins a fingerprint enrollment process and returns TemplateID, LastEnrollSampleStatus,
// and RemainingSamples properties. Use those properties to continue to capture the next samples or cancel it.
func (d *Device) BeginEnroll(
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.BeginEnroll(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		timeoutMilliseconds,
	)
}

// EnrollCaptureNextSample continues capturing samples from an already started enrollment process.
func (d *Device) EnrollCaptureNextSample(
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.EnrollCaptureNextSample(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
		timeoutMilliseconds,
	)
}

// CancelCurrentEnrollment cancels a current enrollment process.
func (d *Device) CancelCurrentEnrollment() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.CancelCurrentEnrollment(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
	)
}

// EnumerateEnrollments enumerates enrollments by returning TemplateInfos property with an array of TemplateInfo
// for all the enrollments available on the authenticator.
func (d *Device) EnumerateEnrollments(pinUvAuthToken []byte) (*ctaptypes.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.EnumerateEnrollments(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// SetFriendlyName allows renaming/setting of a friendly fingerprint name.
func (d *Device) SetFriendlyName(pinUvAuthToken []byte, templateID []byte, friendlyName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.SetFriendlyName(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
		friendlyName,
	)
}

// RemoveEnrollment removes existing enrollment.
func (d *Device) RemoveEnrollment(pinUvAuthToken []byte, templateID []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[ctaptypes.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[ctaptypes.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.RemoveEnrollment(
		d.device,
		d.cid,
		d.info.Versions.IsPreviewOnly(),
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
		templateID,
	)
}

// GetCredsMetadata retrieves credential management metadata if the device supports it.
// Mainly ExistingResidentCredentialsCount and MaxPossibleRemainingResidentCredentialsCount.
func (d *Device) GetCredsMetadata(pinUvAuthToken []byte) (*ctaptypes.AuthenticatorCredentialManagementResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

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
func (d *Device) EnumerateRPs(pinUvAuthToken []byte) iter.Seq2[*ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

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
func (d *Device) EnumerateCredentials(pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[*ctaptypes.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(*ctaptypes.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

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
	credentialID webauthntypes.PublicKeyCredentialDescriptor,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

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
	credentialID webauthntypes.PublicKeyCredentialDescriptor,
	user webauthntypes.PublicKeyCredentialUserEntity,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	if len(config) < 16 {
		return nil, newErrorMessage(ErrLargeBlobsIntegrityCheck, "invalid large blobs response length")
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
	d.mu.Lock()
	defer d.mu.Unlock()

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

// EnableEnterpriseAttestation enables enterprise attestation on the device if supported, using the provided token.
func (d *Device) EnableEnterpriseAttestation(pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[ctaptypes.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}
	if _, ok := d.info.Options[ctaptypes.OptionEnterpriseAttestation]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support ep")
	}

	return d.ctapClient.EnableEnterpriseAttestation(
		d.device,
		d.cid,
		d.info.PinUvAuthProtocols[0],
		pinUvAuthToken,
	)
}

// ToggleAlwaysUV toggles the always UV (User Verification) setting on the device if supported, using the provided token.
func (d *Device) ToggleAlwaysUV(pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

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
	d.mu.Lock()
	defer d.mu.Unlock()

	errc := make(chan error, 1)

	go func() {
		errc <- d.ctapClient.Selection(d.device, d.cid)
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
