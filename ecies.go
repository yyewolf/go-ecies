package eciesgo

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	var ct bytes.Buffer

	// Generate ephemeral key
	ek, err := GenerateKey()
	if err != nil {
		return nil, err
	}

	ct.Write(ek.PublicKey.Bytes())

	// Derive shared secret
	ss, err := ek.Encapsulate(pubkey)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	// CHACHAA20 encryption
	aesgcm, err := chacha20poly1305.NewX(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	ct.Write(nonce)

	ciphertext := aesgcm.Seal(nil, nonce, msg, nil)

	tag := ciphertext[len(ciphertext)-aesgcm.NonceSize():]
	ct.Write(tag)
	ciphertext = ciphertext[:len(ciphertext)-len(tag)]
	ct.Write(ciphertext)

	return ct.Bytes(), nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func Decrypt(privkey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key (65) + nonce (16) + tag (16)
	if len(msg) <= (1 + 64 + 64 + 16 + 16) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// Ephemeral sender public key
	ethPubkey := &PublicKey{
		Curve: getCurve(),
		X:     new(big.Int).SetBytes(msg[1:67]),
		Y:     new(big.Int).SetBytes(msg[67:133]),
	}

	// Shift message
	msg = msg[133:]

	// Derive shared secret
	ss, err := ethPubkey.Decapsulate(privkey)
	if err != nil {
		return nil, err
	}

	// AES decryption part
	nonce := msg[:24]
	tag := msg[24:48]

	// Create Golang-accepted ciphertext
	ciphertext := bytes.Join([][]byte{msg[48:], tag}, nil)

	// CHACHAA20 encryption
	gcm, err := chacha20poly1305.NewX(ss)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt ciphertext: %w", err)
	}

	return plaintext, nil
}
