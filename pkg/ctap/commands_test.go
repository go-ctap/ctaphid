package ctap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/crypto"
	"github.com/go-ctap/ctaphid/pkg/ctaphid"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	ecdhkey "github.com/ldclabs/cose/key/ecdh"
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

func firstCTAPRequestMap(t *testing.T, fake *scriptedDevice) (ctaptypes.Command, map[uint64]any) {
	t.Helper()

	command, requestCBOR := firstCTAPPayload(t, fake)
	var request map[uint64]any
	require.NoError(t, cbor.Unmarshal(requestCBOR, &request))

	return command, request
}

func assertRequestKeys(t *testing.T, request map[uint64]any, keys ...uint64) {
	t.Helper()

	actual := make([]uint64, 0, len(request))
	for key := range request {
		actual = append(actual, key)
	}
	assert.ElementsMatch(t, keys, actual)
}

func testKeyAgreement(t *testing.T) key.Key {
	t.Helper()

	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	coseKey, err := ecdhkey.KeyFromPublic(privateKey.Public().(*ecdh.PublicKey))
	require.NoError(t, err)
	require.NoError(t, coseKey.Set(iana.KeyParameterAlg, -25))
	delete(coseKey, iana.KeyParameterKid)

	return coseKey
}

func pinUvAuthToken() []byte {
	return bytes.Repeat([]byte{0x11}, 32)
}

func testClientDataHash() []byte {
	clientDataHash := sha256.Sum256([]byte("client-data"))
	return clientDataHash[:]
}

func TestNormalizeAndValidatePIN(t *testing.T) {
	t.Run("rejects too short PIN", func(t *testing.T) {
		_, err := normalizeAndValidatePIN("123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 4")
	})

	t.Run("rejects PIN below explicit minimum", func(t *testing.T) {
		_, err := NormalizeAndValidatePIN("12345", 6)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least 6")
	})

	t.Run("rejects PIN over 63 UTF-8 bytes", func(t *testing.T) {
		_, err := normalizeAndValidatePIN(strings.Repeat("a", 64))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "63 UTF-8 bytes")
	})

	t.Run("normalizes PIN to NFC", func(t *testing.T) {
		pin, err := normalizeAndValidatePIN("Cafe\u0301123")
		require.NoError(t, err)
		assert.Equal(t, "Caf\u00e9123", pin)
		assert.LessOrEqual(t, len([]byte(pin)), 63)
	})

	t.Run("rejects PIN ending in NUL byte", func(t *testing.T) {
		_, err := normalizeAndValidatePIN("1234\x00")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "0x00")
	})
}

func TestMakeCredentialRequestShapeAndPINAuthParam(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := newScriptedDevice(t, encodeCBOR(t, &ctaptypes.AuthenticatorMakeCredentialResponse{
		Format:      webauthntypes.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	}))

	resp, err := NewClient().MakeCredential(
		fake,
		testCID,
		ctaptypes.PinUvAuthProtocolOne,
		token,
		clientDataHash,
		webauthntypes.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		webauthntypes.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]webauthntypes.PublicKeyCredentialParameters{{
			Type:      webauthntypes.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		nil,
		nil,
		0,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorMakeCredential, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 8, 9)

	assert.Equal(t, clientDataHash, request[uint64(1)])
	assert.Equal(t, crypto.Authenticate(ctaptypes.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(8)])
	assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(9)])
}

func TestGetAssertionRequestShapeAndPINAuthParam(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := newScriptedDevice(t, encodeCBOR(t, &ctaptypes.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		ctaptypes.PinUvAuthProtocolOne,
		token,
		"example.com",
		clientDataHash,
		nil,
		nil,
		nil,
	) {
		require.NoError(t, err)
		require.NotNil(t, assertion)
		assertions++
	}
	require.Equal(t, 1, assertions)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorGetAssertion, command)
	assertRequestKeys(t, request, 1, 2, 6, 7)

	assert.Equal(t, "example.com", request[uint64(1)])
	assert.Equal(t, clientDataHash, request[uint64(2)])
	assert.Equal(t, crypto.Authenticate(ctaptypes.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(6)])
	assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(7)])
}

func TestClientPINRequestShapes(t *testing.T) {
	response := encodeCBOR(t, &ctaptypes.AuthenticatorClientPINResponse{})

	t.Run("set PIN", func(t *testing.T) {
		fake := newScriptedDevice(t, response)
		err := NewClient().SetPIN(fake, testCID, ctaptypes.PinUvAuthProtocolOne, testKeyAgreement(t), "1234")
		require.NoError(t, err)

		command, request := firstCTAPRequestMap(t, fake)
		assert.Equal(t, ctaptypes.AuthenticatorClientPIN, command)
		assertRequestKeys(t, request, 1, 2, 3, 4, 5)
		assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(1)])
		assert.Equal(t, uint64(ctaptypes.ClientPINSubCommandSetPIN), request[uint64(2)])
		assert.Len(t, request[uint64(4)], 16)
		assert.Len(t, request[uint64(5)], 64)
	})

	t.Run("change PIN", func(t *testing.T) {
		fake := newScriptedDevice(t, response)
		err := NewClient().ChangePIN(fake, testCID, ctaptypes.PinUvAuthProtocolOne, testKeyAgreement(t), "1234", "5678")
		require.NoError(t, err)

		command, request := firstCTAPRequestMap(t, fake)
		assert.Equal(t, ctaptypes.AuthenticatorClientPIN, command)
		assertRequestKeys(t, request, 1, 2, 3, 4, 5, 6)
		assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(1)])
		assert.Equal(t, uint64(ctaptypes.ClientPINSubCommandChangePIN), request[uint64(2)])
		assert.Len(t, request[uint64(4)], 16)
		assert.Len(t, request[uint64(5)], 64)
		assert.Len(t, request[uint64(6)], 16)
	})

	t.Run("get PIN token validates PIN before command", func(t *testing.T) {
		fake := newScriptedDevice(t)
		_, err := NewClient().GetPinToken(fake, testCID, ctaptypes.PinUvAuthProtocolOne, testKeyAgreement(t), "123\x00")
		require.Error(t, err)
		assert.Empty(t, fake.writes.Bytes())
	})

	t.Run("get PIN/UV auth token with permissions validates PIN before command", func(t *testing.T) {
		fake := newScriptedDevice(t)
		_, err := NewClient().GetPinUvAuthTokenUsingPinWithPermissions(
			fake,
			testCID,
			ctaptypes.PinUvAuthProtocolOne,
			testKeyAgreement(t),
			"123\x00",
			ctaptypes.PermissionCredentialManagement,
			"",
		)
		require.Error(t, err)
		assert.Empty(t, fake.writes.Bytes())
	})
}

func TestBioEnrollmentRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	timeoutMilliseconds := uint(1000)
	fake := newScriptedDevice(t, encodeCBOR(t, &ctaptypes.AuthenticatorBioEnrollmentResponse{}))

	resp, err := NewClient().BeginEnroll(fake, testCID, false, ctaptypes.PinUvAuthProtocolOne, token, timeoutMilliseconds)
	require.NoError(t, err)
	require.NotNil(t, resp)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorBioEnrollment, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 5)
	assert.Equal(t, uint64(ctaptypes.BioModalityFingerprint), request[uint64(1)])
	assert.Equal(t, uint64(ctaptypes.BioEnrollmentSubCommandEnrollBegin), request[uint64(2)])

	params := ctaptypes.BioEnrollmentSubCommandParams{TimeoutMilliseconds: timeoutMilliseconds}
	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		ctaptypes.PinUvAuthProtocolOne,
		token,
		slices.Concat([]byte{byte(ctaptypes.BioModalityFingerprint), byte(ctaptypes.BioEnrollmentSubCommandEnrollBegin)}, paramsCBOR),
	)
	assert.Equal(t, expectedParam, request[uint64(5)])
}

func TestCredentialManagementRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := newScriptedDevice(t, encodeCBOR(t, &ctaptypes.AuthenticatorCredentialManagementResponse{}))

	resp, err := NewClient().GetCredsMetadata(fake, testCID, false, ctaptypes.PinUvAuthProtocolOne, token)
	require.NoError(t, err)
	require.NotNil(t, resp)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorCredentialManagement, command)
	assertRequestKeys(t, request, 1, 3, 4)
	assert.Equal(t, uint64(ctaptypes.CredentialManagementSubCommandGetCredsMetadata), request[uint64(1)])
	assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(3)])
	assert.Equal(
		t,
		crypto.Authenticate(ctaptypes.PinUvAuthProtocolOne, token, []byte{byte(ctaptypes.CredentialManagementSubCommandGetCredsMetadata)}),
		request[uint64(4)],
	)
}

func TestLargeBlobsRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	set := []byte("large-blob-fragment")
	offset := uint(7)
	length := uint(9)
	fake := newScriptedDevice(t, nil)

	resp, err := NewClient().LargeBlobs(fake, testCID, ctaptypes.PinUvAuthProtocolOne, token, 0, set, offset, length)
	require.NoError(t, err)
	require.Nil(t, resp)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorLargeBlobs, command)
	assertRequestKeys(t, request, 2, 3, 4, 5, 6)
	assert.Equal(t, set, request[uint64(2)])
	assert.Equal(t, uint64(offset), request[uint64(3)])
	assert.Equal(t, uint64(length), request[uint64(4)])

	padding := bytes.Repeat([]byte{0xff}, 32)
	offsetBin := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetBin, uint32(offset))
	hash := sha256.Sum256(set)
	expectedParam := crypto.Authenticate(
		ctaptypes.PinUvAuthProtocolOne,
		token,
		slices.Concat(padding, []byte{0x0c, 0x00}, offsetBin, hash[:]),
	)
	assert.Equal(t, expectedParam, request[uint64(5)])
	assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(6)])
}

func TestConfigRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := newScriptedDevice(t, nil)

	err := NewClient().SetMinPINLength(fake, testCID, ctaptypes.PinUvAuthProtocolOne, token, 8, []string{"example.com"}, true, false)
	require.NoError(t, err)

	command, request := firstCTAPRequestMap(t, fake)
	assert.Equal(t, ctaptypes.AuthenticatorConfig, command)
	assertRequestKeys(t, request, 1, 2, 3, 4)
	assert.Equal(t, uint64(ctaptypes.ConfigSubCommandSetMinPINLength), request[uint64(1)])
	assert.Equal(t, uint64(ctaptypes.PinUvAuthProtocolOne), request[uint64(3)])

	params := &ctaptypes.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:   8,
		MinPinLengthRPIDs: []string{"example.com"},
		ForceChangePin:    true,
	}
	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		ctaptypes.PinUvAuthProtocolOne,
		token,
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte{0x0d, byte(ctaptypes.ConfigSubCommandSetMinPINLength)}, paramsCBOR),
	)
	assert.Equal(t, expectedParam, request[uint64(4)])
}
