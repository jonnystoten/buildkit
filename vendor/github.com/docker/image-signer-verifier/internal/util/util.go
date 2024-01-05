package util

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

func HexHashString(input string) string {
	return HexHashBytes([]byte(input))
}

func HexHashBytes(input []byte) string {
	s256 := sha256.New()
	s256.Write(input)
	hashSum := s256.Sum(nil)
	return hex.EncodeToString(hashSum)
}

func S256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func GenKeyPair(alg jwa.KeyAlgorithm) (crypto.Signer, error) {
	switch alg {
	case jwa.ES256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jwa.RS256: // RSASSA-PKCS-v1.5 using SHA-256
		return rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg.String())
	}
}
