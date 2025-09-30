package device

import (
	"bytes"
	"encoding/hex"
	"testing"
 	"time"
    "golang.zx2c4.com/wireguard/tai64n"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

func BenchmarkKyberEncapsulate(b *testing.B) {
	scheme := kyber1024.Scheme()
	pk, _, err := scheme.GenerateKeyPair()
	if err != nil { b.Fatal(err) }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := scheme.Encapsulate(pk)
		if err != nil { b.Fatal(err) }
	}
}

func BenchmarkKyberDecapsulate(b *testing.B) {
	scheme := kyber1024.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil { b.Fatal(err) }
	ct, _, err := scheme.Encapsulate(pk) // ct fixo é OK para decap
	if err != nil { b.Fatal(err) }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := scheme.Decapsulate(sk, ct)
		if err != nil { b.Fatal(err) }
	}
}

// Handshake fim-a-fim (sem rede), com ML-KEM integrado
func BenchmarkHandshakeWithMLKEM(b *testing.B) {
	// devs e peers em memória
	skA, _ := newPrivateKey()
	skB, _ := newPrivateKey()
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer devA.Close()
	defer devB.Close()

	if err := devA.SetPrivateKey(skA); err != nil { b.Fatal(err) }
	if err := devB.SetPrivateKey(skB); err != nil { b.Fatal(err) }

	peerB, err := devA.NewPeer(skB.publicKey())
	if err != nil { b.Fatal(err) }
	peerA, err := devB.NewPeer(skA.publicKey())
	if err != nil { b.Fatal(err) }

	// injeta ML-KEM via UAPI (como em produção)
	scheme := kyber1024.Scheme()
	pkA, skAkem, _ := scheme.GenerateKeyPair()
	pkB, skBkem, _ := scheme.GenerateKeyPair()
	pkAb, _ := pkA.MarshalBinary()
	pkBb, _ := pkB.MarshalBinary()
	skAb, _ := skAkem.MarshalBinary()
	skBb, _ := skBkem.MarshalBinary()

	if err := devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb))); err != nil { b.Fatal(err) }
	if err := devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb))); err != nil { b.Fatal(err) }
	if err := devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerB.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkBb))); err != nil { b.Fatal(err) }
	if err := devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerA.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkAb))); err != nil { b.Fatal(err) }

	peerA.Start()
	peerB.Start()

	// >>> helper local: relaxa o rate-limit do receptor (devB/peerA)
	relaxFlood := func() {
    peerA.handshake.mutex.Lock()
    // evita "flood"
    peerA.handshake.lastInitiationConsumption = time.Now().Add(-10 * time.Second)
    // evita "replay"
    peerA.handshake.lastTimestamp = tai64n.Timestamp{} // zero
    peerA.handshake.mutex.Unlock()
}

	// warmup
	relaxFlood()
	msg1, err := devA.CreateMessageInitiation(peerB); if err != nil { b.Fatal(err) }
	if p := devB.ConsumeMessageInitiation(msg1); p == nil { b.Fatal("initiation fail (warmup)") }
	msg2, err := devB.CreateMessageResponse(peerA);   if err != nil { b.Fatal(err) }
	if p := devA.ConsumeMessageResponse(msg2); p == nil { b.Fatal("response fail (warmup)") }
	if err := peerA.BeginSymmetricSession(); err != nil { b.Fatal(err) }
	if err := peerB.BeginSymmetricSession(); err != nil { b.Fatal(err) }

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		relaxFlood() // <<< chama antes de cada initiation
		msg1, err := devA.CreateMessageInitiation(peerB); if err != nil { b.Fatal(err) }
		if p := devB.ConsumeMessageInitiation(msg1); p == nil { b.Fatal("initiation fail") }
		msg2, err := devB.CreateMessageResponse(peerA);   if err != nil { b.Fatal(err) }
		if p := devA.ConsumeMessageResponse(msg2); p == nil { b.Fatal("response fail") }
		if err := peerA.BeginSymmetricSession(); err != nil { b.Fatal(err) }
		if err := peerB.BeginSymmetricSession(); err != nil { b.Fatal(err) }
	}
}

// (opcional) mede a cifra/decifra de um payload curto com as chaves da sessão
func BenchmarkDataPlaneAEAD(b *testing.B) {
	// reaproveita o setup do handshake acima
	skA, _ := newPrivateKey()
	skB, _ := newPrivateKey()
	tunA := tuntest.NewChannelTUN()
	tunB := tuntest.NewChannelTUN()
	devA := NewDevice(tunA.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	devB := NewDevice(tunB.TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer devA.Close()
	defer devB.Close()
	devA.SetPrivateKey(skA); devB.SetPrivateKey(skB)
	peerB, _ := devA.NewPeer(skB.publicKey())
	peerA, _ := devB.NewPeer(skA.publicKey())

	// ML-KEM
	scheme := kyber1024.Scheme()
	pkA, skAkem, _ := scheme.GenerateKeyPair()
	pkB, skBkem, _ := scheme.GenerateKeyPair()
	pkAb, _ := pkA.MarshalBinary()
	pkBb, _ := pkB.MarshalBinary()
	skAb, _ := skAkem.MarshalBinary()
	skBb, _ := skBkem.MarshalBinary()
	devA.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skAb)))
	devB.IpcSet(uapiCfg("mlkem_private_key", hex.EncodeToString(skBb)))
	devA.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerB.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkBb)))
	devB.IpcSet(uapiCfg("public_key", hex.EncodeToString(peerA.handshake.remoteStatic[:]), "mlkem_public_key", hex.EncodeToString(pkAb)))
	peerA.Start(); peerB.Start()

	// establish one session
	msg1, _ := devA.CreateMessageInitiation(peerB)
	devB.ConsumeMessageInitiation(msg1)
	msg2, _ := devB.CreateMessageResponse(peerA)
	devA.ConsumeMessageResponse(msg2)
	peerA.BeginSymmetricSession()
	peerB.BeginSymmetricSession()

	keyA := peerA.keypairs.next.Load()
	keyB := peerB.keypairs.current
	msg := bytes.Repeat([]byte{0x42}, 128) // 128B
	var nonce [12]byte

	b.ReportAllocs()
	b.SetBytes(int64(len(msg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := keyA.send.Seal(nil, nonce[:], msg, nil)
		_, err := keyB.receive.Open(nil, nonce[:], out, nil)
		if err != nil { b.Fatal(err) }
	}
}
