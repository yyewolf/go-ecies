package eciesgo

import (
	"bytes"
	"crypto/elliptic"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
)

// PublicKey instance with nested elliptic.Curve interface (secp256k1 instance in our case)
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// NewPublicKeyFromHex decodes hex form of public key raw bytes and returns PublicKey instance
func NewPublicKeyFromHex(s string) (*PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cannot decode hex string: %w", err)
	}

	return NewPublicKeyFromBytes(b)
}

// NewPublicKeyFromBytes decodes public key raw bytes and returns PublicKey instance;
// Supports both compressed and uncompressed public keys
func NewPublicKeyFromBytes(b []byte) (*PublicKey, error) {
	curve := getCurve()

	switch b[0] {
	case 0x04:
		if len(b) != 133 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x := new(big.Int).SetBytes(b[1:67])
		y := new(big.Int).SetBytes(b[67:])

		if x.Cmp(curve.Params().P) >= 0 || y.Cmp(curve.Params().P) >= 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		x3 := new(big.Int).Sqrt(x).Mul(x, x)
		if t := new(big.Int).Sqrt(y).Sub(y, x3.Add(x3, curve.Params().B)); t.IsInt64() && t.Int64() == 0 {
			return nil, fmt.Errorf("cannot parse public key")
		}

		return &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}, nil
	default:
		return nil, fmt.Errorf("cannot parse public key")
	}
}

// Bytes returns public key raw bytes;
func (k *PublicKey) Bytes() []byte {
	x := k.X.Bytes()
	if len(x) < 66 {
		for i := 0; i < 66-len(x); i++ {
			x = append([]byte{0}, x...)
		}
	}

	y := k.Y.Bytes()
	if len(y) < 66 {
		for i := 0; i < 66-len(y); i++ {
			y = append([]byte{0}, y...)
		}
	}

	return bytes.Join([][]byte{{0x04}, x, y}, nil)
}

// Hex returns public key bytes in hex form
func (k *PublicKey) Hex() string {
	return hex.EncodeToString(k.Bytes())
}

// Decapsulate decapsulates key by using Key Encapsulation Mechanism and returns symmetric key;
// can be safely used as encryption key
func (k *PublicKey) Decapsulate(priv *PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("public key is empty")
	}

	var secret bytes.Buffer
	secret.Write(k.Bytes())

	sx, sy := priv.Curve.ScalarMult(k.X, k.Y, priv.D.Bytes())
	secret.Write([]byte{0x04})

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(priv.Curve.Params().P.Bytes())
	secret.Write(zeroPad(sx.Bytes(), l))
	secret.Write(zeroPad(sy.Bytes(), l))

	return kdf(secret.Bytes())
}

// Equals compares two public keys with constant time (to resist timing attacks)
func (k *PublicKey) Equals(pub *PublicKey) bool {
	eqX := subtle.ConstantTimeCompare(k.X.Bytes(), pub.X.Bytes()) == 1
	eqY := subtle.ConstantTimeCompare(k.Y.Bytes(), pub.Y.Bytes()) == 1
	return eqX && eqY
}
