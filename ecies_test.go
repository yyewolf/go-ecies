package eciesgo

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/hkdf"
)

const testingMessage = "helloworld"
const testingJsonMessage = `{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}{"code":0,"msg":"ok","data":{"pageNumber":1,"pageSize":10,"total":0,"list":[],"realTotal":0}}`
const testingReceiverPubkeyHex = "04002da2cc9ac376f85a3968da3d896cae147f2b96c53f149499c1a6aed988832aca571c4f4eeb62f1070bff91ed4a4aa8ad6cd81f180faeac441e69bdf92b68d84e7d01875396f834501719eeb74f5f5eb4595dabf4bc3fa3f8847c28059448da03f727d5b78e147f2886ff0a96bc4892671d666deacf4997a0faf520d192075c77456899"
const testingReceiverPrivkeyHex = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"
const pythonBackend = "https://ecies.deta.dev/"

var testingReceiverPrivkey = []byte{51, 37, 145, 156, 66, 168, 189, 189, 176, 19, 177, 30, 148, 104, 25, 140, 155, 42, 248, 190, 121, 110, 16, 174, 143, 148, 72, 129, 94, 113, 219, 58}

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey()
	assert.NoError(t, err)
}

func BenchmarkEncrypt(b *testing.B) {
	privkey := NewPrivateKeyFromBytes(testingReceiverPrivkey)

	msg := []byte(testingJsonMessage)
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(privkey.PublicKey, msg)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	privkey := NewPrivateKeyFromBytes(testingReceiverPrivkey)
	msg := []byte(testingJsonMessage)

	ciphertext, err := Encrypt(privkey.PublicKey, msg)
	if err != nil {
		b.Fail()
	}

	for i := 0; i < b.N; i++ {
		_, err := Decrypt(privkey, ciphertext)
		if err != nil {
			b.Fail()
		}
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	privkey := NewPrivateKeyFromBytes(testingReceiverPrivkey)

	ciphertext, err := Encrypt(privkey.PublicKey, []byte(testingMessage))
	if !assert.NoError(t, err) {
		return
	}

	plaintext, err := Decrypt(privkey, ciphertext)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, testingMessage, string(plaintext))
}

func TestPublicKeyDecompression(t *testing.T) {
	// Generate public key
	privkey, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	// Drop Y part and restore it
	pubkey, err := NewPublicKeyFromHex(privkey.PublicKey.Hex())
	if !assert.NoError(t, err) {
		return
	}

	// Check that point is still at curve
	assert.True(t, privkey.IsOnCurve(pubkey.X, pubkey.Y))
}

func TestKEM(t *testing.T) {
	derived := make([]byte, 32)
	kdf := hkdf.New(sha256.New, []byte("secret"), nil, nil)
	if _, err := io.ReadFull(kdf, derived); err != nil {
		if !assert.Equal(
			t,
			"2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf",
			hex.EncodeToString(derived),
		) {
			return
		}
	}

	k1 := NewPrivateKeyFromBytes(new(big.Int).SetInt64(2).Bytes())
	k2 := NewPrivateKeyFromBytes(new(big.Int).SetInt64(3).Bytes())

	sk1, err := k1.Encapsulate(k2.PublicKey)
	if !assert.NoError(t, err) {
		return
	}
	sk2, err := k1.PublicKey.Decapsulate(k2)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.Equal(t, sk1, sk2) {
		return
	}

	assert.Equal(
		t,
		"28b2499b06f812aa06267a4e84f4afb653c8067195dd3485ff5685e8c6a0ed3a",
		hex.EncodeToString(sk1),
	)
}
