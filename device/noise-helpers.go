/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"

	"golang.org/x/crypto/curve25519"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"  // Para manipular as chaves Kyber
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// KDF-related functions: Implementing the Key Derivation Functions (KDF) using HMAC
func HMAC1(sum *[blake2s.Size]byte, key, in0 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[blake2s.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[blake2s.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

// Check if a byte array is zeroed out
func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

// Function to clear an array by setting all elements to zero
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

// Private key generation for Noise using random bytes
func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])  // Gera uma chave privada aleatória Noise
	sk.clamp()  // Aplica o clamping à chave privada Noise
	return
}

// Clamp the Noise private key (this is part of the Noise protocol spec)
func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

// Deriving public key from private key for Noise protocol
func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)  // Perform scalar base multiplication
	return
}

// Private key for Kyber1024
func newKyberPrivateKey() (*kyber1024.PrivateKey, error) {
    sk, pk, err := kyber1024.GenerateKeyPair(rand.Reader)  // Gera a chave privada Kyber1024
    if err != nil {
        return nil, nil, err
    }
    return sk, pk, nil
}

// Função para gerar a chave pública Kyber
func (sk *kyber1024.PrivateKey) public() *kyber1024.PublicKey {
    return &sk.PublicKey
}


// Shared secret calculation using Noise private key and Noise public key
func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)  // Calculating the shared secret using scalar multiplication
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

// Shared secret calculation for Kyber (using Kyber1024) private key and public key
func (sk *kyber1024.PrivateKey) sharedSecret(pk kyber1024.PublicKey) (ss [kyber1024.PublicKeySize]byte, err error) {
	// We perform Kyber decapsulation here
	ss, err = kyber1024.NewKeyPair(rand.Reader).Decapsulate(ciphertext) // Using the Kyber decapsulation to get the shared secret
	if err != nil {
		return ss, err
	}
	return ss, nil
}

var errInvalidPublicKey = errors.New("invalid public key")

