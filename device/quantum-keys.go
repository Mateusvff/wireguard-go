package device

import (
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

func GenerateQuantumKeyPair() (pub []byte, priv []byte, err error) {
	pk, sk, err := kyber1024.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pub, _ = pk.MarshalBinary()
	priv, _ = sk.MarshalBinary()
	return pub, priv, nil
}
