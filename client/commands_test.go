package client

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
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	ecdhkey "github.com/ldclabs/cose/key/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCID = ctaphid.ChannelID{1, 2, 3, 4}

func encodeCBOR(t *testing.T, v any) []byte {
	t.Helper()

	b, err := cbor.Marshal(v)
	require.NoError(t, err)
	return b
}

func minimalAuthData() []byte {
	return make([]byte, 37)
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
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	}))

	resp, err := NewClient().MakeCredential(
		fake,
		testCID,
		protocol.PinUvAuthProtocolOne,
		token,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
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

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 8, 9)

	assert.Equal(t, clientDataHash, request[uint64(1)])
	assert.Equal(t, crypto.Authenticate(protocol.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(8)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(9)])
}

func TestMakeCredentialMinimalRequestOmitsEmptyExcludeList(t *testing.T) {
	clientDataHash := testClientDataHash()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	}))

	resp, err := NewClient().MakeCredential(
		fake,
		testCID,
		0,
		nil,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		[]credential.PublicKeyCredentialDescriptor{},
		nil,
		nil,
		0,
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, resp.AuthData)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	assertRequestKeys(t, request, 1, 2, 3, 4)
}

func TestMakeCredentialFullRequestShape(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
		Format:      attestation.AttestationStatementFormatIdentifierPacked,
		AuthDataRaw: minimalAuthData(),
	}))

	resp, err := NewClient().MakeCredential(
		fake,
		testCID,
		protocol.PinUvAuthProtocolOne,
		token,
		clientDataHash,
		credential.PublicKeyCredentialRpEntity{ID: "example.com", Name: "Example"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id"), Name: "user"},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		[]credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}},
		&protocol.CreateExtensionInputs{
			CreateCredProtectInput: &protocol.CreateCredProtectInput{CredProtect: 2},
		},
		map[protocol.Option]bool{
			protocol.OptionResidentKeys:     true,
			protocol.OptionUserVerification: false,
		},
		1,
		[]attestation.AttestationStatementFormatIdentifier{
			attestation.AttestationStatementFormatIdentifierPacked,
			attestation.AttestationStatementFormatIdentifierNone,
		},
	)
	require.NoError(t, err)
	require.NotNil(t, resp.AuthData)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorMakeCredential, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11)
	assert.Equal(t, crypto.Authenticate(protocol.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(8)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(9)])
	assert.Equal(t, uint64(1), request[uint64(10)])
}

func TestMakeCredentialRejectsInvalidClientDataHashBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)

	_, err := NewClient().MakeCredential(
		fake,
		testCID,
		0,
		nil,
		[]byte("too-short"),
		credential.PublicKeyCredentialRpEntity{ID: "example.com"},
		credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
		[]credential.PublicKeyCredentialParameters{{
			Type:      credential.PublicKeyCredentialTypePublicKey,
			Algorithm: -7,
		}},
		nil,
		nil,
		nil,
		0,
		nil,
	)
	require.Error(t, err)
	assert.Empty(t, fake.Writes())
}

func TestMakeCredentialReturnsResponseDecodeErrors(t *testing.T) {
	t.Run("invalid CBOR", func(t *testing.T) {
		fake := testhid.New(t, testhid.CBOROK(testCID, []byte{0xff}))

		_, err := NewClient().MakeCredential(
			fake,
			testCID,
			0,
			nil,
			testClientDataHash(),
			credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
			[]credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: -7,
			}},
			nil,
			nil,
			nil,
			0,
			nil,
		)
		require.Error(t, err)
	})

	t.Run("invalid authData", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorMakeCredentialResponse{
			Format:      attestation.AttestationStatementFormatIdentifierPacked,
			AuthDataRaw: []byte{1},
		}))

		_, err := NewClient().MakeCredential(
			fake,
			testCID,
			0,
			nil,
			testClientDataHash(),
			credential.PublicKeyCredentialRpEntity{ID: "example.com"},
			credential.PublicKeyCredentialUserEntity{ID: []byte("user-id")},
			[]credential.PublicKeyCredentialParameters{{
				Type:      credential.PublicKeyCredentialTypePublicKey,
				Algorithm: -7,
			}},
			nil,
			nil,
			nil,
			0,
			nil,
		)
		require.Error(t, err)
	})
}

func TestGetAssertionRequestShapeAndPINAuthParam(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		protocol.PinUvAuthProtocolOne,
		token,
		"example.com",
		clientDataHash,
		nil,
		nil,
		nil,
	) {
		require.NoError(t, err)
		require.NotNil(t, assertion.AuthData)
		assertions++
	}
	require.Equal(t, 1, assertions)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	assertRequestKeys(t, request, 1, 2, 6, 7)

	assert.Equal(t, "example.com", request[uint64(1)])
	assert.Equal(t, clientDataHash, request[uint64(2)])
	assert.Equal(t, crypto.Authenticate(protocol.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(6)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(7)])
}

func TestGetAssertionMinimalRequestOmitsEmptyAllowList(t *testing.T) {
	clientDataHash := testClientDataHash()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		0,
		nil,
		"example.com",
		clientDataHash,
		[]credential.PublicKeyCredentialDescriptor{},
		nil,
		nil,
	) {
		require.NoError(t, err)
		require.NotNil(t, assertion.AuthData)
		assertions++
	}
	require.Equal(t, 1, assertions)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	assertRequestKeys(t, request, 1, 2)
}

func TestGetAssertionFullRequestShape(t *testing.T) {
	clientDataHash := testClientDataHash()
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{1},
	}))

	var assertions int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		protocol.PinUvAuthProtocolOne,
		token,
		"example.com",
		clientDataHash,
		[]credential.PublicKeyCredentialDescriptor{{
			Type: credential.PublicKeyCredentialTypePublicKey,
			ID:   []byte("credential-id"),
		}},
		&protocol.GetExtensionInputs{
			GetCredBlobInput: &protocol.GetCredBlobInput{CredBlob: true},
		},
		map[protocol.Option]bool{
			protocol.OptionUserPresence:     true,
			protocol.OptionUserVerification: false,
		},
	) {
		require.NoError(t, err)
		require.NotNil(t, assertion.AuthData)
		assertions++
	}
	require.Equal(t, 1, assertions)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 5, 6, 7)
	assert.Equal(t, crypto.Authenticate(protocol.PinUvAuthProtocolOne, token, clientDataHash), request[uint64(6)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(7)])
}

func TestGetAssertionRejectsInvalidClientDataHashBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)

	var yielded int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		0,
		nil,
		"example.com",
		[]byte("too-short"),
		nil,
		nil,
		nil,
	) {
		yielded++
		assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
		require.Error(t, err)
	}
	require.Equal(t, 1, yielded)
	assert.Empty(t, fake.Writes())
}

func TestGetAssertionFetchesNextAssertions(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: new(uint(3)),
	})
	second := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{2},
	})
	third := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw: minimalAuthData(),
		Signature:   []byte{3},
	})
	fake := testhid.NewCBORDevice(t, testCID, first, second, third)

	var signatures [][]byte
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		0,
		nil,
		"example.com",
		testClientDataHash(),
		nil,
		nil,
		nil,
	) {
		require.NoError(t, err)
		signatures = append(signatures, assertion.Signature)
	}

	require.Equal(t, [][]byte{{1}, {2}, {3}}, signatures)
	requests := fake.Requests(t)
	require.Len(t, requests, 3)

	command, _ := requests[0].CTAPPayload(t)
	assert.Equal(t, protocol.AuthenticatorGetAssertion, command)
	for _, request := range requests[1:] {
		command, body := request.CTAPPayload(t)
		assert.Equal(t, protocol.AuthenticatorGetNextAssertion, command)
		assert.Empty(t, body)
	}
}

func TestGetAssertionStopsBeforeGetNextAssertionWhenIteratorStops(t *testing.T) {
	first := encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
		AuthDataRaw:         minimalAuthData(),
		Signature:           []byte{1},
		NumberOfCredentials: new(uint(2)),
	})
	fake := testhid.NewCBORDevice(t, testCID, first)

	var assertions int
	for assertion, err := range NewClient().GetAssertion(
		fake,
		testCID,
		0,
		nil,
		"example.com",
		testClientDataHash(),
		nil,
		nil,
		nil,
	) {
		require.NoError(t, err)
		assert.Equal(t, []byte{1}, assertion.Signature)
		assertions++
		break
	}

	require.Equal(t, 1, assertions)
	require.Len(t, fake.Requests(t), 1)
}

func TestGetAssertionReturnsResponseDecodeErrors(t *testing.T) {
	t.Run("invalid CBOR", func(t *testing.T) {
		fake := testhid.New(t, testhid.CBOROK(testCID, []byte{0xff}))

		var yielded int
		for assertion, err := range NewClient().GetAssertion(
			fake,
			testCID,
			0,
			nil,
			"example.com",
			testClientDataHash(),
			nil,
			nil,
			nil,
		) {
			yielded++
			assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
			require.Error(t, err)
		}
		require.Equal(t, 1, yielded)
	})

	t.Run("invalid authData", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorGetAssertionResponse{
			AuthDataRaw: []byte{1},
			Signature:   []byte{1},
		}))

		var yielded int
		for assertion, err := range NewClient().GetAssertion(
			fake,
			testCID,
			0,
			nil,
			"example.com",
			testClientDataHash(),
			nil,
			nil,
			nil,
		) {
			yielded++
			assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
			require.Error(t, err)
		}
		require.Equal(t, 1, yielded)
	})
}

func TestClientPINRequestShapes(t *testing.T) {
	t.Run("set PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		err := NewClient().SetPIN(fake, testCID, protocol.PinUvAuthProtocolOne, testKeyAgreement(t), "1234")
		require.NoError(t, err)

		command, request := fake.FirstCTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorClientPIN, command)
		assertRequestKeys(t, request, 1, 2, 3, 4, 5)
		assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)])
		assert.Equal(t, uint64(protocol.ClientPINSubCommandSetPIN), request[uint64(2)])
		assert.Len(t, request[uint64(4)], 16)
		assert.Len(t, request[uint64(5)], 64)
	})

	t.Run("change PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		err := NewClient().ChangePIN(fake, testCID, protocol.PinUvAuthProtocolOne, testKeyAgreement(t), "1234", "5678")
		require.NoError(t, err)

		command, request := fake.FirstCTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorClientPIN, command)
		assertRequestKeys(t, request, 1, 2, 3, 4, 5, 6)
		assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)])
		assert.Equal(t, uint64(protocol.ClientPINSubCommandChangePIN), request[uint64(2)])
		assert.Len(t, request[uint64(4)], 16)
		assert.Len(t, request[uint64(5)], 64)
		assert.Len(t, request[uint64(6)], 16)
	})

	t.Run("get PIN token validates PIN before command", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		_, err := NewClient().GetPinToken(fake, testCID, protocol.PinUvAuthProtocolOne, testKeyAgreement(t), "123\x00")
		require.Error(t, err)
		assert.Empty(t, fake.Writes())
	})

	t.Run("get PIN/UV auth token with permissions validates PIN before command", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		_, err := NewClient().GetPinUvAuthTokenUsingPinWithPermissions(
			fake,
			testCID,
			protocol.PinUvAuthProtocolOne,
			testKeyAgreement(t),
			"123\x00",
			protocol.PermissionCredentialManagement,
			"",
		)
		require.Error(t, err)
		assert.Empty(t, fake.Writes())
	})
}

func TestBioEnrollmentRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	timeoutMilliseconds := uint(1000)
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorBioEnrollmentResponse{}))

	resp, err := NewClient().EnrollBegin(fake, testCID, false, protocol.PinUvAuthProtocolOne, token, timeoutMilliseconds)
	require.NoError(t, err)
	require.NotNil(t, resp)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorBioEnrollment, command)
	assertRequestKeys(t, request, 1, 2, 3, 4, 5)
	assert.Equal(t, uint64(protocol.BioModalityFingerprint), request[uint64(1)])
	assert.Equal(t, uint64(protocol.BioEnrollmentSubCommandEnrollBegin), request[uint64(2)])

	params := protocol.BioEnrollmentSubCommandParams{TimeoutMilliseconds: timeoutMilliseconds}
	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		token,
		slices.Concat([]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)}, paramsCBOR),
	)
	assert.Equal(t, expectedParam, request[uint64(5)])
}

func TestCredentialManagementRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, &protocol.AuthenticatorCredentialManagementResponse{}))

	resp, err := NewClient().GetCredsMetadata(fake, testCID, false, protocol.PinUvAuthProtocolOne, token)
	require.NoError(t, err)
	require.NotNil(t, resp)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorCredentialManagement, command)
	assertRequestKeys(t, request, 1, 3, 4)
	assert.Equal(t, uint64(protocol.CredentialManagementSubCommandGetCredsMetadata), request[uint64(1)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(3)])
	assert.Equal(
		t,
		crypto.Authenticate(protocol.PinUvAuthProtocolOne, token, []byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)}),
		request[uint64(4)],
	)
}

func TestLargeBlobsRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	set := []byte("large-blob-fragment")
	offset := uint(7)
	length := uint(9)
	fake := testhid.NewCBORDevice(t, testCID, nil)

	resp, err := NewClient().LargeBlobs(fake, testCID, protocol.PinUvAuthProtocolOne, token, 0, set, offset, length)
	require.NoError(t, err)
	require.Empty(t, resp.Config)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorLargeBlobs, command)
	assertRequestKeys(t, request, 2, 3, 4, 5, 6)
	assert.Equal(t, set, request[uint64(2)])
	assert.Equal(t, uint64(offset), request[uint64(3)])
	assert.Equal(t, uint64(length), request[uint64(4)])

	padding := bytes.Repeat([]byte{0xff}, 32)
	offsetBin := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetBin, uint32(offset))
	hash := sha256.Sum256(set)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		token,
		slices.Concat(padding, []byte{0x0c, 0x00}, offsetBin, hash[:]),
	)
	assert.Equal(t, expectedParam, request[uint64(5)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(6)])
}

func TestConfigRequestShapeAndPINAuthParam(t *testing.T) {
	token := pinUvAuthToken()
	fake := testhid.NewCBORDevice(t, testCID, nil)

	err := NewClient().SetMinPINLength(fake, testCID, protocol.PinUvAuthProtocolOne, token, 8, []string{"example.com"}, true, false)
	require.NoError(t, err)

	command, request := fake.FirstCTAPRequestMap(t)
	assert.Equal(t, protocol.AuthenticatorConfig, command)
	assertRequestKeys(t, request, 1, 2, 3, 4)
	assert.Equal(t, uint64(protocol.ConfigSubCommandSetMinPINLength), request[uint64(1)])
	assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(3)])

	params := &protocol.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:   8,
		MinPinLengthRPIDs: []string{"example.com"},
		ForceChangePin:    true,
	}
	paramsCBOR := encodeCBOR(t, params)
	expectedParam := crypto.Authenticate(
		protocol.PinUvAuthProtocolOne,
		token,
		slices.Concat(bytes.Repeat([]byte{0xff}, 32), []byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)}, paramsCBOR),
	)
	assert.Equal(t, expectedParam, request[uint64(4)])
}
