package ctaptypes

import (
	"bytes"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
	"github.com/ldclabs/cose/key"
)

func (d *AuthData) UserPresent() bool {
	return d.Flags&AuthDataFlagUserPresent != 0
}

func (d *AuthData) UserVerified() bool {
	return d.Flags&AuthDataFlagUserVerified != 0
}

func (d *AuthData) AttestedCredentialDataIncluded() bool {
	return d.Flags&AuthDataFlagAttestedCredentialDataIncluded != 0
}

func (d *AuthData) ExtensionDataIncluded() bool {
	return d.Flags&AuthDataFlagExtensionDataIncluded != 0
}

func ParseAuthData(authData []byte) (*AuthData, error) {
	d := &AuthData{
		RPIDHash:  authData[:32],
		Flags:     AuthDataFlag(authData[32]),
		SignCount: binary.BigEndian.Uint32(authData[33:37]),
	}
	offset := 55
	if d.AttestedCredentialDataIncluded() {
		credData := &AttestedCredentialData{
			AAGUID: uuid.UUID(authData[37 : 37+16]),
		}

		// Credential ID
		length := binary.BigEndian.Uint16(authData[53 : 53+2])
		credData.CredentialID = authData[55 : 55+length]
		offset += int(length)

		// Credential Public Key
		dec := cbor.NewDecoder(bytes.NewReader(authData[55+length:]))
		if err := dec.Decode(&credData.CredentialPublicKey); err != nil {
			return nil, err
		}
		offset += dec.NumBytesRead()

		d.AttestedCredentialData = credData
	}

	if d.ExtensionDataIncluded() {
		if err := cbor.NewDecoder(bytes.NewReader(authData[offset:])).
			Decode(&d.Extensions); err != nil {
			return nil, err
		}
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

func (r *AuthenticatorMakeCredentialResponse) PackedAttestationStatementFormat() (*PackedAttestationStatementFormat, bool) {
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

	return &PackedAttestationStatementFormat{
		Algorithm: key.Alg(alg),
		Signature: sig,
		X509Chain: x5c,
	}, true
}

func (r *AuthenticatorMakeCredentialResponse) FIDOU2FAttestationStatementFormat() (*FIDOU2FAttestationStatementFormat, bool) {
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

	return &FIDOU2FAttestationStatementFormat{
		Signature: sig,
		X509Chain: x5c,
	}, true
}
