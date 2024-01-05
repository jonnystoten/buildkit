package attestation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/docker/image-signer-verifier/internal/tl"
	"github.com/docker/image-signer-verifier/internal/util"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

const (
	DsseExtKind = "TL"
)

// the following types are needed until https://github.com/secure-systems-lab/dsse/pull/61 is merged
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}
type Signature struct {
	KeyID     string    `json:"keyid"`
	Sig       string    `json:"sig"`
	Extension Extension `json:"extension"`
}
type Extension struct {
	Kind string         `json:"kind"`
	Ext  map[string]any `json:"ext"`
}

func SignInTotoStatement(ctx context.Context, stmt intoto.Statement, signer crypto.Signer) (*Envelope, error) {
	t, ok := ctx.Value(tl.TlCtxKey(tl.DefaultCtxKey)).(tl.TL)
	if !ok {
		t = &tl.RekorTL{}
	}

	// encode in-toto statement
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, err
	}
	env := new(Envelope)
	env.Payload = base64.StdEncoding.EncodeToString(payload)
	env.PayloadType = intoto.PayloadType
	encPayload := dsse.PAE(intoto.PayloadType, payload)

	// statement message digest
	hash := util.S256(encPayload)

	// sign message digest
	sig, err := signer.Sign(rand.Reader, hash, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("error signing attestation: %w", err)
	}

	// get Key ID from signer
	// TODO - implement this in SignerVerifier KeyID()
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("error marshalling public key: %w", err)
	}
	keyId := util.HexHashBytes(pub)

	// upload to TL
	entry, err := t.UploadLogEntry(ctx, keyId, encPayload, sig, signer)
	if err != nil {
		return nil, fmt.Errorf("error uploading TL entry: %w", err)
	}

	// add signature w/ tl extension to dsse envelope
	env.Signatures = append(env.Signatures, Signature{
		KeyID: keyId,
		Sig:   base64.StdEncoding.EncodeToString(sig),
		Extension: Extension{
			Kind: DsseExtKind,
			Ext: map[string]any{
				"tl": entry, // transparency log entry metadata
			},
		},
	})

	return env, nil
}
