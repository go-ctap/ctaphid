package ctaptypes

import (
	"bytes"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctaphid/pkg/webauthntypes"
	"github.com/google/uuid"
	"github.com/ldclabs/cose/key"
)

func (f AuthDataFlag) UserPresent() bool {
	return f&AuthDataFlagUserPresent != 0
}
func (f AuthDataFlag) UserVerified() bool {
	return f&AuthDataFlagUserVerified != 0
}
func (f AuthDataFlag) AttestedCredentialDataIncluded() bool {
	return f&AuthDataFlagAttestedCredentialDataIncluded != 0
}
func (f AuthDataFlag) ExtensionDataIncluded() bool {
	return f&AuthDataFlagExtensionDataIncluded != 0
}

type authData struct {
	RPIDHash               []byte
	Flags                  AuthDataFlag
	SignCount              uint32
	AttestedCredentialData *AttestedCredentialData
	Extensions             []byte
}

func parseAuthData(data []byte) (*authData, error) {
	d := &authData{
		RPIDHash:  data[:32],
		Flags:     AuthDataFlag(data[32]),
		SignCount: binary.BigEndian.Uint32(data[33:37]),
	}
	offset := 37
	if d.Flags.AttestedCredentialDataIncluded() {
		credData := &AttestedCredentialData{
			AAGUID: uuid.UUID(data[offset : offset+16]),
		}
		offset += 16

		// Credential ID
		length := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		credData.CredentialID = data[offset : offset+int(length)]
		offset += int(length)

		// Credential Public Key
		dec := cbor.NewDecoder(bytes.NewReader(data[offset:]))
		if err := dec.Decode(&credData.CredentialPublicKey); err != nil {
			return nil, err
		}
		offset += dec.NumBytesRead()

		d.AttestedCredentialData = credData
	}

	if d.Flags.ExtensionDataIncluded() {
		d.Extensions = data[offset:]
	}

	return d, nil
}

func (vv Versions) Supports(ver Version) bool {
	for _, v := range vv {
		if v == ver {
			return true
		}
	}

	return false
}

func (vv Versions) IsPreviewOnly() bool {
	fidoTwo := false
	fidoTwoOnePre := false
	fidoTwoOne := false
	fidoTwoTwo := false

	for _, v := range vv {
		switch v {
		case FIDO_2_0:
			fidoTwo = true
		case FIDO_2_1_PRE:
			fidoTwoOnePre = true
		case FIDO_2_1:
			fidoTwoOne = true
		case FIDO_2_2:
			fidoTwoTwo = true
		}
	}

	return fidoTwo && (!fidoTwoOne && !fidoTwoTwo && fidoTwoOnePre)
}

func (r *AuthenticatorMakeCredentialResponse) PackedAttestationStatementFormat() (*webauthntypes.PackedAttestationStatementFormat, bool) {
	algRaw, ok := r.AttestationStatement["alg"]
	if !ok {
		return nil, false
	}
	alg, ok := algRaw.(int64)
	if !ok {
		return nil, false
	}

	sigRaw, ok := r.AttestationStatement["sig"]
	if !ok {
		return nil, false
	}
	sig, ok := sigRaw.([]byte)
	if !ok {
		return nil, false
	}

	x5cRaw, ok := r.AttestationStatement["x5c"]
	if !ok {
		return nil, false
	}
	x5cSlice, ok := x5cRaw.([]any)
	if !ok {
		return nil, false
	}
	var x5c [][]byte
	for _, certRaw := range x5cSlice {
		cert, ok := certRaw.([]byte)
		if !ok {
			return nil, false
		}
		x5c = append(x5c, cert)
	}

	return &webauthntypes.PackedAttestationStatementFormat{
		Algorithm: key.Alg(alg),
		Signature: sig,
		X509Chain: x5c,
	}, true
}

func (r *AuthenticatorMakeCredentialResponse) FIDOU2FAttestationStatementFormat() (*webauthntypes.FIDOU2FAttestationStatementFormat, bool) {
	x5cRaw, ok := r.AttestationStatement["x5c"]
	if !ok {
		return nil, false
	}
	x5c, ok := x5cRaw.([][]byte)
	if !ok {
		return nil, false
	}

	sigRaw, ok := r.AttestationStatement["sig"]
	if !ok {
		return nil, false
	}
	sig, ok := sigRaw.([]byte)
	if !ok {
		return nil, false
	}

	return &webauthntypes.FIDOU2FAttestationStatementFormat{
		Signature: sig,
		X509Chain: x5c,
	}, true
}

func (r *AuthenticatorMakeCredentialResponse) TPMAttestationStatementFormat() (*webauthntypes.TPMAttestationStatementFormat, bool) {
	verRaw, ok := r.AttestationStatement["ver"]
	if !ok {
		return nil, false
	}
	ver, ok := verRaw.(string)
	if !ok {
		return nil, false
	}

	algRaw, ok := r.AttestationStatement["alg"]
	if !ok {
		return nil, false
	}
	alg, ok := algRaw.(int64)
	if !ok {
		return nil, false
	}

	x5cRaw, ok := r.AttestationStatement["x5c"]
	if !ok {
		return nil, false
	}
	x5cSlice, ok := x5cRaw.([]any)
	if !ok {
		return nil, false
	}
	var x5c [][]byte
	for _, certRaw := range x5cSlice {
		cert, ok := certRaw.([]byte)
		if !ok {
			return nil, false
		}
		x5c = append(x5c, cert)
	}

	aikCertRaw, ok := r.AttestationStatement["aikCert"]
	if !ok {
		return nil, false
	}
	aikCert, ok := aikCertRaw.([]byte)
	if !ok {
		return nil, false
	}

	sigRaw, ok := r.AttestationStatement["sig"]
	if !ok {
		return nil, false
	}
	sig, ok := sigRaw.([]byte)
	if !ok {
		return nil, false
	}

	certInfoRaw, ok := r.AttestationStatement["certInfo"]
	if !ok {
		return nil, false
	}
	certInfo, ok := certInfoRaw.([]byte)
	if !ok {
		return nil, false
	}

	pubAreaRaw, ok := r.AttestationStatement["pubArea"]
	if !ok {
		return nil, false
	}
	pubArea, ok := pubAreaRaw.([]byte)
	if !ok {
		return nil, false
	}

	return &webauthntypes.TPMAttestationStatementFormat{
		Version:   ver,
		Algorithm: key.Alg(alg),
		X509Chain: x5c,
		AIKCert:   aikCert,
		Signature: sig,
		CertInfo:  certInfo,
		PubArea:   pubArea,
	}, true
}
