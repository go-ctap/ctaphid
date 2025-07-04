package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/go-ctap/ctaphid/pkg/crypto/protocolone"
	"github.com/go-ctap/ctaphid/pkg/crypto/protocoltwo"
	"github.com/go-ctap/ctaphid/pkg/ctaptypes"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	ecdh2 "github.com/ldclabs/cose/key/ecdh"
)

type PinUvAuthProtocol struct {
	Number             ctaptypes.PinUvAuthProtocol
	platformPrivateKey *ecdh.PrivateKey
	platformCoseKey    key.Key
}

func NewPinUvAuthProtocol(number ctaptypes.PinUvAuthProtocol) (*PinUvAuthProtocol, error) {
	platformPrivkey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate platform P-256 keypair: %w", err)
	}

	platformPubkey, err := ecdh2.KeyFromPublic(platformPrivkey.Public().(*ecdh.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("cannot convert platform public key to COSE_Key: %w", err)
	}
	if err := platformPubkey.Set(iana.KeyParameterAlg, -25); err != nil {
		return nil, fmt.Errorf("cannot set alg parameter for COSE_Key: %w", err)
	}

	// Specification explicitly requires COSE_Key to contain only the necessary parameters.
	// Some keys accept it anyway, but some are not, e.g., SoloKeys Solo 2.
	delete(platformPubkey, iana.KeyParameterKid)

	return &PinUvAuthProtocol{
		Number:             number,
		platformPrivateKey: platformPrivkey,
		platformCoseKey:    platformPubkey,
	}, nil
}

func (p *PinUvAuthProtocol) ECDH(peerCoseKey key.Key) ([]byte, error) {
	peerPubkey, err := ecdh2.KeyToPublic(peerCoseKey)
	if err != nil {
		return nil, fmt.Errorf("cannot convert peer public key to Go *ecdh.PublicKey: %w", err)
	}

	sharedSecret, err := p.platformPrivateKey.ECDH(peerPubkey)
	if err != nil {
		return nil, fmt.Errorf("cannot derive shared secret: %w", err)
	}

	return p.KDF(sharedSecret)
}

func (p *PinUvAuthProtocol) KDF(z []byte) ([]byte, error) {
	switch p.Number {
	case ctaptypes.PinUvAuthProtocolOne:
		return protocolone.KDF(z), nil
	case ctaptypes.PinUvAuthProtocolTwo:
		return protocoltwo.KDF(z)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

func (p *PinUvAuthProtocol) Encrypt(sharedSecret []byte, demPlaintext []byte) ([]byte, error) {
	switch p.Number {
	case ctaptypes.PinUvAuthProtocolOne:
		return protocolone.Encrypt(sharedSecret, demPlaintext)
	case ctaptypes.PinUvAuthProtocolTwo:
		return protocoltwo.Encrypt(sharedSecret, demPlaintext)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

func (p *PinUvAuthProtocol) Decrypt(sharedSecret []byte, demCiphertext []byte) ([]byte, error) {
	switch p.Number {
	case ctaptypes.PinUvAuthProtocolOne:
		return protocolone.Decrypt(sharedSecret, demCiphertext)
	case ctaptypes.PinUvAuthProtocolTwo:
		return protocoltwo.Decrypt(sharedSecret, demCiphertext)
	default:
		return nil, ErrInvalidAuthProtocol
	}
}

func (p *PinUvAuthProtocol) Encapsulate(peerCoseKey key.Key) (key.Key, []byte, error) {
	sharedSecret, err := p.ECDH(peerCoseKey)
	if err != nil {
		return nil, nil, err
	}

	return p.platformCoseKey, sharedSecret, nil
}

func Authenticate(number ctaptypes.PinUvAuthProtocol, sharedSecret []byte, message []byte) []byte {
	switch number {
	case ctaptypes.PinUvAuthProtocolOne:
		return protocolone.Authenticate(sharedSecret, message)
	case ctaptypes.PinUvAuthProtocolTwo:
		return protocoltwo.Authenticate(sharedSecret, message)
	default:
		panic("invalid auth protocol")
	}
}

func EncryptLargeBlob(key []byte, origData []byte) (*ctaptypes.LargeBlob, error) {
	plaintext, err := compress(origData)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	origSize := len(origData)
	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(origSize))

	ciphertext := gcm.Seal(nil, nonce, plaintext, slices.Concat([]byte("blob"), origSizeBin))
	return &ctaptypes.LargeBlob{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		OrigSize:   uint(origSize),
	}, nil
}

func DecryptLargeBlob(key []byte, blob *ctaptypes.LargeBlob) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(blob.OrigSize))

	plaintext, err := gcm.Open(nil, blob.Nonce, blob.Ciphertext, slices.Concat([]byte("blob"), origSizeBin))
	if err != nil {
		return nil, err
	}

	origData, err := decompress(plaintext)
	if err != nil {
		return nil, err
	}

	return origData, nil
}
