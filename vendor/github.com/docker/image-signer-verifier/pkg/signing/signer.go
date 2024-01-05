package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/docker/image-signer-verifier/internal/util"
	"github.com/lestrrat-go/jwx/v2/jwa"
	awssigner "github.com/sigstore/sigstore/pkg/signature/kms/aws"
)

const (
	AwsKmsPublicKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgH23D1i2+ZIOtVjmfB7iFvX8AhVN\n9CPJ4ie9axw+WRHozGnRy99U2dRge3zueBBg2MweF0zrToXGig2v3YOrdw==\n-----END PUBLIC KEY-----"
)

// using AWS KMS
func GetAWSSigner(ctx context.Context, keyId, region string) (crypto.Signer, error) {
	sv, err := awssigner.LoadSignerVerifier(ctx, keyId, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("error loading aws signer verifier: %w", err)
	}
	signer, _, err := sv.CryptoSigner(context.Background(), func(err error) {})
	if err != nil {
		return nil, fmt.Errorf("error getting aws crypto signer: %w", err)
	}
	return signer, nil
}

// using mock KMS
func GetMockSigner(ctx context.Context) (crypto.Signer, error) {
	signer, err := util.GenKeyPair(jwa.ES256)
	if err != nil {
		return nil, fmt.Errorf("error failed to generate key pair: %w", err)
	}
	return signer, nil
}

func GetPublicVerificationKey() (*ecdsa.PublicKey, error) {
	// TODO - get public key from TUF repo
	// return hardcoded public key for now
	p, _ := pem.Decode([]byte(AwsKmsPublicKey))
	pubKey, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error failed to parse public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error public key is not an ecdsa key: %w", err)
	}
	return ecdsaPubKey, nil
}
