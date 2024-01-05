package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/docker/image-signer-verifier/internal/tl"
	"github.com/docker/image-signer-verifier/internal/util"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func VerifyInTotoEnvelope(ctx context.Context, env *Envelope, publicKey *ecdsa.PublicKey) (*intoto.Statement, error) {
	t, ok := ctx.Value(tl.TlCtxKey(tl.DefaultCtxKey)).(tl.TL)
	if !ok {
		t = &tl.RekorTL{}
	}

	// enforce payload type
	if env.PayloadType != intoto.PayloadType {
		return nil, fmt.Errorf("unsupported payload type %s", env.PayloadType)
	}

	// verify signatures and transparency log entry
	for _, sig := range env.Signatures {
		if sig.Extension.Kind != DsseExtKind {
			return nil, fmt.Errorf("error unsupported signature extension kind: %s", sig.Extension.Kind)
		}
		// decode signature
		signature, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode signature: %w", err)
		}

		// verify payload ecdsa signature
		payload, err := base64.RawStdEncoding.DecodeString(env.Payload)
		if err != nil {
			return nil, fmt.Errorf("error failed to decode payload: %w", err)
		}
		encPayload := dsse.PAE(intoto.PayloadType, payload)

		ok := ecdsa.VerifyASN1(publicKey, util.S256(encPayload), signature)
		if !ok {
			return nil, fmt.Errorf("payload signature is not valid: %w", err)
		}

		// verify TL entry
		entryBytes := sig.Extension.Ext["tl"].([]byte)
		err = t.VerifyLogEntry(ctx, entryBytes)
		if err != nil {
			return nil, fmt.Errorf("TL entry failed verification: %w", err)
		}

		// verify TL entry payload
		encodedPub, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("error failed to marshal public key: %w", err)
		}
		err = t.VerifyEntryPayload(entryBytes, encPayload, encodedPub)
		if err != nil {
			return nil, fmt.Errorf("TL entry failed payload verification: %w", err)
		}
	}

	// decode in-toto statement
	stmt := new(intoto.Statement)
	stmtBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode in-toto statement: %w", err)
	}
	err = json.Unmarshal(stmtBytes, stmt)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal in-toto statement: %w", err)
	}
	return stmt, nil
}
