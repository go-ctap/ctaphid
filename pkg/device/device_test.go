package device

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/ctap"
	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}

type scriptedDevice struct {
	reads  *bytes.Reader
	writes bytes.Buffer
}

func newScriptedDevice(t *testing.T, responses ...[]byte) *scriptedDevice {
	t.Helper()

	var reads bytes.Buffer
	for _, response := range responses {
		msg, err := ctaphid.NewMessage(testCID, ctaphid.CTAPHID_CBOR, append([]byte{byte(ctaphid.CTAP2_OK)}, response...))
		require.NoError(t, err)

		var withReportIDs bytes.Buffer
		_, err = msg.WriteTo(&withReportIDs)
		require.NoError(t, err)
		reads.Write(stripReportIDs(withReportIDs.Bytes()))
	}

	return &scriptedDevice{reads: bytes.NewReader(reads.Bytes())}
}

func (d *scriptedDevice) Read(p []byte) (int, error) {
	return d.reads.Read(p)
}

func (d *scriptedDevice) Write(p []byte) (int, error) {
	return d.writes.Write(p)
}

func (d *scriptedDevice) Close() error {
	return nil
}

func stripReportIDs(packets []byte) []byte {
	const reportPacketSize = 65
	const packetSize = 64

	stripped := make([]byte, 0, len(packets)/reportPacketSize*packetSize)
	for len(packets) >= reportPacketSize {
		stripped = append(stripped, packets[1:reportPacketSize]...)
		packets = packets[reportPacketSize:]
	}

	return stripped
}

func newTestDevice(fake *scriptedDevice, info *ctaptypes.AuthenticatorGetInfoResponse) *Device {
	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	d := &Device{
		device:     fake,
		cid:        testCID,
		info:       info,
		ctapClient: ctap.NewClient(),
		encMode:    encMode,
	}
	if len(info.PinUvAuthProtocols) > 0 {
		d.pinUvAuthProtocol = info.PinUvAuthProtocols[0]
	}

	return d
}

func encodeCBOR(t *testing.T, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func minimalAuthData() []byte {
	return make([]byte, 37)
}

func firstCTAPPayload(t *testing.T, fake *scriptedDevice) (ctaptypes.Command, []byte) {
	t.Helper()

	written := fake.writes.Bytes()
	require.GreaterOrEqual(t, len(written), 8)
	require.Equal(t, byte(0), written[0])
	require.Equal(t, testCID[:], written[1:5])
	length := int(binary.BigEndian.Uint16(written[6:8]))
	payload := make([]byte, 0, length)
	firstPacketDataLen := min(length, 57)
	payload = append(payload, written[8:8+firstPacketDataLen]...)
	remaining := length - firstPacketDataLen
	offset := 65
	for remaining > 0 {
		require.GreaterOrEqual(t, len(written), offset+65)
		dataLen := min(remaining, 59)
		payload = append(payload, written[offset+6:offset+6+dataLen]...)
		remaining -= dataLen
		offset += 65
	}
	require.NotEmpty(t, payload)

	return ctaptypes.Command(payload[0]), payload[1:]
}

func TestGetAssertionContinuesAfterAssertionWithoutExtensionData(t *testing.T) {
	first := encodeCBOR(t, &ctaptypes.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: 2,
	})
	second := encodeCBOR(t, &ctaptypes.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{2},
	})
	fake := newScriptedDevice(t, first, second)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{})

	var assertions []*ctaptypes.AuthenticatorGetAssertionResponse
	for assertion, err := range d.GetAssertion(nil, "example.com", []byte("client-data"), nil, nil, nil) {
		require.NoError(t, err)
		assertions = append(assertions, assertion)
	}

	require.Len(t, assertions, 2)
	assert.Equal(t, []byte{1}, assertions[0].Signature)
	assert.Equal(t, []byte{2}, assertions[1].Signature)
}

func TestLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []*ctaptypes.LargeBlob{})
	sum := sha256.Sum256(encodedBlobs)
	response := encodeCBOR(t, &ctaptypes.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, sum[:16]...),
	})
	fake := newScriptedDevice(t, response)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)

	command, requestCBOR := firstCTAPPayload(t, fake)
	require.Equal(t, ctaptypes.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	assert.Equal(t, uint64(960), request[uint64(1)])
}

func TestLargeBlobsTreatsCorruptConfigAsInitialEmptyArray(t *testing.T) {
	encodedBlobs := encodeCBOR(t, []*ctaptypes.LargeBlob{{Ciphertext: []byte{0xaa}}})
	response := encodeCBOR(t, &ctaptypes.AuthenticatorLargeBlobsResponse{
		Config: append(encodedBlobs, bytes.Repeat([]byte{0x00}, 16)...),
	})
	fake := newScriptedDevice(t, response)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionLargeBlobs: true,
		},
	})

	blobs, err := d.GetLargeBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSetLargeBlobsUsesDefaultMaxMsgSizeWhenMissing(t *testing.T) {
	fake := newScriptedDevice(t, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols:          []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionLargeBlobs: true,
		},
	})
	blob := &ctaptypes.LargeBlob{
		Ciphertext: bytes.Repeat([]byte{0xaa}, 1000),
		Nonce:      []byte("nonce"),
	}

	err := d.SetLargeBlobs(make([]byte, 32), []*ctaptypes.LargeBlob{blob})
	require.NoError(t, err)

	command, requestCBOR := firstCTAPPayload(t, fake)
	require.Equal(t, ctaptypes.AuthenticatorLargeBlobs, command)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))
	set, ok := request[uint64(2)].([]byte)
	require.True(t, ok)
	assert.Len(t, set, 960)
	assert.Equal(t, uint64(0), request[uint64(3)])
}

func TestCredentialManagementUnsupportedIteratorsReturnBeforeCommand(t *testing.T) {
	t.Run("enumerate RPs", func(t *testing.T) {
		fake := newScriptedDevice(t)
		d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{Options: map[ctaptypes.Option]bool{}})

		var count int
		for rp, err := range d.EnumerateRPs(nil) {
			count++
			assert.Nil(t, rp)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assert.Empty(t, fake.writes.Bytes())
	})

	t.Run("enumerate credentials", func(t *testing.T) {
		fake := newScriptedDevice(t)
		d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{Options: map[ctaptypes.Option]bool{}})

		var count int
		for cred, err := range d.EnumerateCredentials(nil, make([]byte, 32)) {
			count++
			assert.Nil(t, cred)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrNotSupported))
		}

		assert.Equal(t, 1, count)
		assert.Empty(t, fake.writes.Bytes())
	})
}

func TestUpdateUserInformationUsesPreviewCommandForPreviewOnlyDevice(t *testing.T) {
	fake := newScriptedDevice(t, nil)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Versions:           ctaptypes.Versions{ctaptypes.FIDO_2_0, ctaptypes.FIDO_2_1_PRE},
		PinUvAuthProtocols: []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionCredentialManagementPreview: true,
		},
	})

	err := d.UpdateUserInformation(
		make([]byte, 32),
		webauthntypes.PublicKeyCredentialDescriptor{ID: []byte("credential-id")},
		webauthntypes.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
	)
	require.NoError(t, err)

	command, _ := firstCTAPPayload(t, fake)
	assert.Equal(t, ctaptypes.PrototypeAuthenticatorCredentialManagement, command)
}

func TestMakeCredentialCredPropsOutputDependsOnCredPropsInput(t *testing.T) {
	response := encodeCBOR(t, &ctaptypes.AuthenticatorMakeCredentialResponse{
		Format:      webauthntypes.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	})
	fake := newScriptedDevice(t, response)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionMakeCredentialUvNotRequired: true,
		},
	})

	resp, err := d.MakeCredential(
		nil,
		[]byte("client-data"),
		webauthntypes.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		webauthntypes.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]webauthntypes.PublicKeyCredentialParameters{{
			Type:      webauthntypes.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		&webauthntypes.CreateAuthenticationExtensionsClientInputs{
			CreateCredentialPropertiesInputs: &webauthntypes.CreateCredentialPropertiesInputs{CredentialProperties: true},
		},
		map[ctaptypes.Option]bool{ctaptypes.OptionResidentKeys: true},
		0,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs)
	assert.True(t, resp.ExtensionOutputs.CreateCredentialPropertiesOutputs.CredentialProperties.ResidentKey)
}

func TestMissingPinUvAuthProtocolsReturnsError(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Options: map[ctaptypes.Option]bool{ctaptypes.OptionClientPIN: false},
	})

	err := d.SetPIN("1234")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotSupported))
	assert.Empty(t, fake.writes.Bytes())
}

func TestGetPinUvAuthTokenUsingPINValidatesPINBeforeCommand(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
		Options:            map[ctaptypes.Option]bool{ctaptypes.OptionClientPIN: true},
	})

	_, err := d.GetPinUvAuthTokenUsingPIN("123\x00", ctaptypes.PermissionCredentialManagement, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0x00")
	assert.Empty(t, fake.writes.Bytes())
}

func TestSetPINValidatesPINBeforeCommand(t *testing.T) {
	t.Run("rejects too short PIN", func(t *testing.T) {
		fake := newScriptedDevice(t)
		d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
			Options:            map[ctaptypes.Option]bool{ctaptypes.OptionClientPIN: false},
		})

		err := d.SetPIN("123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 4")
		assert.Empty(t, fake.writes.Bytes())
	})

	t.Run("honors minPinLength", func(t *testing.T) {
		fake := newScriptedDevice(t)
		d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
			MinPinLength:       8,
			Options:            map[ctaptypes.Option]bool{ctaptypes.OptionClientPIN: false},
		})

		err := d.SetPIN("1234567")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 8")
		assert.Empty(t, fake.writes.Bytes())
	})
}

func TestChangePINValidatesNewPINBeforeCommand(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		PinUvAuthProtocols: []ctaptypes.PinUvAuthProtocol{ctaptypes.PinUvAuthProtocolOne},
		MinPinLength:       8,
		Options:            map[ctaptypes.Option]bool{ctaptypes.OptionClientPIN: true},
	})

	err := d.ChangePIN("1234", "1234567")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least 8")
	assert.Empty(t, fake.writes.Bytes())
}

func TestGetAssertionValidatesHMACSecretSalts(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Extensions: []webauthntypes.ExtensionIdentifier{webauthntypes.ExtensionIdentifierHMACSecret},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		&webauthntypes.GetAuthenticationExtensionsClientInputs{
			GetHMACSecretInputs: &webauthntypes.GetHMACSecretInputs{
				HMACGetSecret: webauthntypes.HMACGetSecretInput{Salt1: make([]byte, 31)},
			},
		},
		nil,
	) {
		count++
		assert.Nil(t, assertion)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	}

	assert.Equal(t, 1, count)
	assert.Empty(t, fake.writes.Bytes())
}

func TestMakeCredentialValidatesHMACSecretMCSalts(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{
		Extensions: []webauthntypes.ExtensionIdentifier{webauthntypes.ExtensionIdentifierHMACSecretMC},
		Options: map[ctaptypes.Option]bool{
			ctaptypes.OptionMakeCredentialUvNotRequired: true,
		},
	})

	_, err := d.MakeCredential(
		nil,
		[]byte("client-data"),
		webauthntypes.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		webauthntypes.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]webauthntypes.PublicKeyCredentialParameters{{
			Type:      webauthntypes.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		&webauthntypes.CreateAuthenticationExtensionsClientInputs{
			CreateHMACSecretMCInputs: &webauthntypes.CreateHMACSecretMCInputs{
				HMACGetSecret: webauthntypes.HMACGetSecretInput{Salt1: make([]byte, 32), Salt2: make([]byte, 31)},
			},
		},
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSaltSize))
	assert.Empty(t, fake.writes.Bytes())
}

func TestLockRejectsOutOfRangeSeconds(t *testing.T) {
	fake := newScriptedDevice(t)
	d := newTestDevice(fake, &ctaptypes.AuthenticatorGetInfoResponse{})

	err := d.Lock(11)
	require.Error(t, err)
	assert.True(t, errors.Is(err, SyntaxError))
	assert.Empty(t, fake.writes.Bytes())
}

var _ io.ReadWriteCloser = (*scriptedDevice)(nil)
