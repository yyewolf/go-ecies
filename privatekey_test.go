package eciesgo

import (
	"crypto/subtle"
	"testing"

	"github.com/stretchr/testify/assert"
)

const privkeyBase = "95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d"

var privkeys = []string{
	"95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d",
	"95d3c5e483e9b1d4f5fc8e79b2deaf51362980de62dbb082a9a4257eef653d7d",
}

func TestNewPrivateKeyFromHex(t *testing.T) {
	_, err := NewPrivateKeyFromHex(testingReceiverPrivkeyHex)
	assert.NoError(t, err)
}

func TestPrivateKey_Hex(t *testing.T) {
	privkey, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	privkey.Hex()
}

func TestPrivateKey_Equals(t *testing.T) {
	privkey, err := GenerateKey()
	if !assert.NoError(t, err) {
		return
	}

	assert.True(t, privkey.Equals(privkey))
}

func TestPrivateKey_UnsafeECDH(t *testing.T) {
	privkey1, err := NewPrivateKeyFromHex(privkeyBase)
	if !assert.NoError(t, err) {
		return
	}
	for _, key := range privkeys {
		privkey2, err := NewPrivateKeyFromHex(key)
		if !assert.NoError(t, err) {
			return
		}
		ss1, err := privkey1.ECDH(privkey2.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		ss2, err := privkey2.ECDH(privkey1.PublicKey)
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, subtle.ConstantTimeCompare(ss1, ss2), 1)
	}
}
