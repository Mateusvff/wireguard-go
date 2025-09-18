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
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/blake2s"
)

// ==============================
// KDF (BLAKE2s via HMAC)
// ==============================

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
	if t1 != nil {
		HMAC2(t1, prk[:], t0[:], []byte{0x2})
	}
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[blake2s.Size]byte, key, input []byte) {
	var prk [blake2s.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	if t1 != nil {
		HMAC2(t1, prk[:], t0[:], []byte{0x2})
	}
	if t2 != nil && t1 != nil {
		HMAC2(t2, prk[:], t1[:], []byte{0x3})
	}
	setZero(prk[:])
}

// ==============================
// Utils
// ==============================

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

var errInvalidPublicKey = errors.New("invalid public key")

// ==============================
// Noise (X25519)
// ==============================

// newPrivateKey gera uma chave privada Noise (X25519) e aplica clamp.
func newPrivateKey() (sk NoisePrivateKey, err error) {
	_, err = rand.Read(sk[:])
	sk.clamp()
	return
}

// clamp conforme especificação do X25519.
func (sk *NoisePrivateKey) clamp() {
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64
}

// publicKey deriva a pública X25519 a partir da privada.
func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarBaseMult(apk, ask)
	return
}

// sharedSecret calcula o segredo compartilhado X25519.
func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte, err error) {
	apk := (*[NoisePublicKeySize]byte)(&pk)
	ask := (*[NoisePrivateKeySize]byte)(sk)
	curve25519.ScalarMult(&ss, ask, apk)
	if isZero(ss[:]) {
		return ss, errInvalidPublicKey
	}
	return ss, nil
}

// ==============================
// Kyber1024 (ML-KEM) helpers
// ==============================

// mlkemGenerateKeypair gera (public, private) Kyber1024.
func mlkemGenerateKeypair() (*kyber1024.PublicKey, *kyber1024.PrivateKey, error) {
	return kyber1024.GenerateKeyPair(rand.Reader)
}

// mlkemPublicFromPrivate obtém a pública via sk.Public() (sem definir método em tipo externo).
func mlkemPublicFromPrivate(sk *kyber1024.PrivateKey) *kyber1024.PublicKey {
	pk, _ := sk.Public().(*kyber1024.PublicKey) // sk.Public() retorna kem.PublicKey
	return pk
}

// mlkemEncapsulate realiza o encapsulamento KEM para a pública dada.
// Retorna o ciphertext (ct) e o shared secret (ss).
func mlkemEncapsulate(pk *kyber1024.PublicKey) (ct, ss []byte, err error) {
	ct = make([]byte, kyber1024.CiphertextSize)
	ss = make([]byte, kyber1024.SharedKeySize)
	// seed=nil => usa crypto/rand.Reader
	pk.EncapsulateTo(ct, ss, nil)
	return ct, ss, nil
}

// mlkemDecapsulate realiza o decapsulamento KEM usando a privada e o ct.
// Retorna o shared secret (ss).
func mlkemDecapsulate(sk *kyber1024.PrivateKey, ct []byte) (ss []byte, err error) {
	if len(ct) != kyber1024.CiphertextSize {
		return nil, errors.New("invalid Kyber ciphertext size")
	}
	ss = make([]byte, kyber1024.SharedKeySize)
	sk.DecapsulateTo(ss, ct)
	return ss, nil
}

// ---------- Serialização (Pack/Unpack) ----------

// mlkemPackPublic serializa a chave pública em buffer de tamanho fixo.
func mlkemPackPublic(pk *kyber1024.PublicKey) []byte {
	buf := make([]byte, kyber1024.PublicKeySize)
	pk.Pack(buf)
	return buf
}

// mlkemPackPrivate serializa a chave privada em buffer de tamanho fixo.
func mlkemPackPrivate(sk *kyber1024.PrivateKey) []byte {
	buf := make([]byte, kyber1024.PrivateKeySize)
	sk.Pack(buf)
	return buf
}

// mlkemUnpackPublic desserializa uma pública de um buffer (Unpack não retorna erro).
func mlkemUnpackPublic(b []byte) (*kyber1024.PublicKey, error) {
	if len(b) != kyber1024.PublicKeySize {
		return nil, errors.New("invalid Kyber public key size")
	}
	var pk kyber1024.PublicKey
	pk.Unpack(b)
	return &pk, nil
}

// mlkemUnpackPrivate desserializa uma privada de um buffer (Unpack não retorna erro).
func mlkemUnpackPrivate(b []byte) (*kyber1024.PrivateKey, error) {
	if len(b) != kyber1024.PrivateKeySize {
		return nil, errors.New("invalid Kyber private key size")
	}
	var sk kyber1024.PrivateKey
	sk.Unpack(b)
	return &sk, nil
}
