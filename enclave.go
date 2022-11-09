package enclave

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"sync"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"

	"github.com/edgebitio/nitro-enclaves-sdk-go/crypto/cms"
)

const (
	defaultKeyBits = 2048
)

var (
	globalHandle        *EnclaveHandle
	initializationError error
	initMutex           sync.Mutex
)

type AttestationOptions struct {
	// Nonce is an optional cryptographic nonce which may be signed as part of the attestation
	// for use by applications in preventing replay attacks.
	Nonce []byte

	// UserData is an optional opaque blob which will be signed as part of the attestation
	// for application-defined purposes.
	UserData []byte

	// NoPublicKey will prevent the defaul public key from being included in the attestation.
	NoPublicKey bool

	// PublicKey is an optional public key which will be included in the attestation. Valid types
	// are *rsa.PublicKey, *ecdsa.PublicKey, and ed25519.PublicKey.
	PublicKey any
}

type EnclaveHandle struct {
	nsm *nsm.Session
	key *rsa.PrivateKey
}

func (enclave *EnclaveHandle) initialize() error {
	var err error

	enclave.nsm, err = nsm.OpenDefaultSession()
	if err != nil {
		return err
	}

	enclave.key, err = rsa.GenerateKey(rand.Reader, defaultKeyBits)
	if err != nil {
		return err
	}

	return nil
}

// Obtain an attestation document from the enclave's Nitro Security Module.
// See AttestationOptions for
func (enclave *EnclaveHandle) Attest(args AttestationOptions) ([]byte, error) {
	var publicKey []byte
	var err error
	if args.PublicKey != nil && !args.NoPublicKey {
		publicKey, err = x509.MarshalPKIXPublicKey(args.PublicKey)
		if err != nil {
			return nil, err
		}
	} else if !args.NoPublicKey {
		publicKey, err = x509.MarshalPKIXPublicKey(enclave.PublicKey())
		if err != nil {
			return nil, err
		}
	}

	res, err := enclave.nsm.Send(&request.Attestation{
		Nonce:     args.Nonce,
		UserData:  args.UserData,
		PublicKey: publicKey,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("attestation response missing attestation document")
	}

	return res.Attestation.Document, nil
}

func (enclave *EnclaveHandle) PublicKey() *rsa.PublicKey {
	return &enclave.key.PublicKey
}

func (enclave *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	return enclave.key
}

func (enclave *EnclaveHandle) DecryptKMSEnvelopedKey(content []byte) ([]byte, error) {
	return cms.DecryptEnvelopedKey(enclave.PrivateKey(), content)
}

func GetOrInitializeHandle() (*EnclaveHandle, error) {
	initMutex.Lock()
	defer initMutex.Unlock()

	if globalHandle == nil && initializationError == nil {
		enclave := &EnclaveHandle{}
		if err := enclave.initialize(); err != nil {
			initializationError = err
		} else {
			globalHandle = enclave
		}
	}

	return globalHandle, initializationError
}
