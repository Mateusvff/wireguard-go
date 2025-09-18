/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148 + (MLKEMCiphertextSize + poly1305.TagSize)
	MessageResponseSize        = 92
	MessageCookieReplySize     = 64
	MessageTransportHeaderSize = 16
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize
	MessageKeepaliveSize       = MessageTransportSize
	MessageHandshakeSize       = MessageInitiationSize
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	MLKEM     [MLKEMCiphertextSize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

var errMessageLengthMismatch = errors.New("message length mismatch")

func (msg *MessageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	copy(msg.Static[:], b[8+len(msg.Ephemeral):])
	copy(msg.MLKEM[:], b[8+len(msg.Ephemeral)+len(msg.Static):])
	copy(msg.Timestamp[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM):])
	copy(msg.MAC1[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM)+len(msg.Timestamp):])
	copy(msg.MAC2[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM)+len(msg.Timestamp)+len(msg.MAC1):])
	return nil
}

func (msg *MessageInitiation) marshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	copy(b[8+len(msg.Ephemeral):], msg.Static[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static):], msg.MLKEM[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM):], msg.Timestamp[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM)+len(msg.Timestamp):], msg.MAC1[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.MLKEM)+len(msg.Timestamp)+len(msg.MAC1):], msg.MAC2[:])
	return nil
}

func (msg *MessageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	copy(msg.Empty[:], b[12+len(msg.Ephemeral):])
	copy(msg.MAC1[:], b[12+len(msg.Ephemeral)+len(msg.Empty):])
	copy(msg.MAC2[:], b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):])
	return nil
}

func (msg *MessageResponse) marshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	copy(b[12+len(msg.Ephemeral):], msg.Empty[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty):], msg.MAC1[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):], msg.MAC2[:])
	return nil
}

func (msg *MessageCookieReply) unmarshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}
	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Receiver = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Nonce[:], b[8:])
	copy(msg.Cookie[:], b[8+len(msg.Nonce):])
	return nil
}

func (msg *MessageCookieReply) marshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}
	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Receiver)
	copy(b[8:], msg.Nonce[:])
	copy(b[8+len(msg.Nonce):], msg.Cookie[:])
	return nil
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte
	chainKey                  [blake2s.Size]byte
	presharedKey              NoisePresharedKey
	localEphemeral            NoisePrivateKey
	localIndex                uint32
	remoteIndex               uint32
	remoteStatic              NoisePublicKey
	remoteMLKEMStatic         MLKEMPublicKey
	remoteEphemeral           NoisePublicKey
	precomputedStaticStatic   [NoisePublicKeySize]byte
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hh, _ := blake2s.New256(nil)
	hh.Write(h[:])
	hh.Write(data)
	hh.Sum(dst[:0])
	hh.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) { mixHash(&h.hash, &h.hash, data) }
func (h *Handshake) mixKey(data []byte)  { mixKey(&h.chainKey, &h.chainKey, data) }

func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	hs := &peer.handshake
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	var err error
	hs.hash = InitialHash
	hs.chainKey = InitialChainKey
	hs.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}

	hs.mixHash(hs.remoteStatic[:])

	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: hs.localEphemeral.publicKey(),
	}

	hs.mixKey(msg.Ephemeral[:])
	hs.mixHash(msg.Ephemeral[:])

	// PQC: encapsula para a chave remota ML-KEM
	scheme := kyber1024.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(hs.remoteMLKEMStatic[:])
	if err != nil {
		return nil, err
	}
	ciphertext, mlkemSecret, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, err
	}

	// cifra o ciphertext do KEM e mistura no hash
	var key [chacha20poly1305.KeySize]byte
	KDF1(&key, hs.chainKey[:], []byte("pqc-ciphertext-key"))
	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.MLKEM[:0], ZeroNonce[:], ciphertext, hs.hash[:])
	hs.mixHash(msg.MLKEM[:])

	// criptografa a estática (Noise)
	ss, err := hs.localEphemeral.sharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}

	// combina segredo clássico + PQC
	var combinedSecret [blake2s.Size]byte
	KDF2(&combinedSecret, nil, ss[:], mlkemSecret)

	KDF2(&hs.chainKey, &key, hs.chainKey[:], combinedSecret[:])

	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], device.staticIdentity.publicKey[:], hs.hash[:])
	hs.mixHash(msg.Static[:])

	// timestamp
	if isZero(hs.precomputedStaticStatic[:]) {
		return nil, errInvalidPublicKey
	}
	KDF2(&hs.chainKey, &key, hs.chainKey[:], hs.precomputedStaticStatic[:])
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], hs.hash[:])

	// índice
	device.indexTable.Delete(hs.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, hs)
	if err != nil {
		return nil, err
	}
	hs.localIndex = msg.Sender

	hs.mixHash(msg.Timestamp[:])
	hs.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss, err := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
	var tempChainKey [blake2s.Size]byte
	KDF2(&tempChainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer
	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}
	hs := &peer.handshake

	// decode ML-KEM ciphertext
	KDF1(&key, chainKey[:], []byte("pqc-ciphertext-key"))
	aead, _ = chacha20poly1305.New(key[:])
	var ciphertext [MLKEMCiphertextSize]byte
	_, err = aead.Open(ciphertext[:0], ZeroNonce[:], msg.MLKEM[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.MLKEM[:])

	// decapsula usando a chave privada ML-KEM do device (sem tentar fazer slice do struct!)
	scheme := kyber1024.Scheme()
	mlkemSecret, err := scheme.Decapsulate(device.staticIdentity.mlkemPrivateKey, ciphertext[:])
	if err != nil {
		return nil
	}

	// combina clássico + PQC
	var combinedSecret [blake2s.Size]byte
	KDF2(&combinedSecret, nil, ss[:], mlkemSecret)

	// atualiza a chainKey com o combinado
	KDF2(&chainKey, &key, chainKey[:], combinedSecret[:])

	// verifica identidade
	var timestamp tai64n.Timestamp
	hs.mutex.RLock()
	if isZero(hs.precomputedStaticStatic[:]) {
		hs.mutex.RUnlock()
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], hs.precomputedStaticStatic[:])
	hs.mutex.RUnlock()

	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// anti replay / flood
	hs.mutex.RLock()
	replay := !timestamp.After(hs.lastTimestamp)
	flood := time.Since(hs.lastInitiationConsumption) <= HandshakeInitationRate
	hs.mutex.RUnlock()
	if replay || flood {
		return nil
	}

	// atualiza estado
	hs.mutex.Lock()
	hs.hash = hash
	hs.chainKey = chainKey
	hs.remoteIndex = msg.Sender
	hs.remoteEphemeral = msg.Ephemeral
	if timestamp.After(hs.lastTimestamp) {
		hs.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(hs.lastInitiationConsumption) {
		hs.lastInitiationConsumption = now
	}
	hs.state = handshakeInitiationConsumed
	hs.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])
	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	hs := &peer.handshake
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	if hs.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// index
	var err error
	device.indexTable.Delete(hs.localIndex)
	hs.localIndex, err = device.indexTable.NewIndexForHandshake(peer, hs)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = hs.localIndex
	msg.Receiver = hs.remoteIndex

	// ephemeral
	hs.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = hs.localEphemeral.publicKey()
	hs.mixHash(msg.Ephemeral[:])
	hs.mixKey(msg.Ephemeral[:])

	ss, err := hs.localEphemeral.sharedSecret(hs.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ss[:])
	ss, err = hs.localEphemeral.sharedSecret(hs.remoteStatic)
	if err != nil {
		return nil, err
	}
	hs.mixKey(ss[:])

	// PSK
	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	KDF3(&hs.chainKey, &tau, &key, hs.chainKey[:], hs.presharedKey[:])
	hs.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, hs.hash[:])
	hs.mixHash(msg.Empty[:])

	hs.state = handshakeResponseCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}
	lookup := device.indexTable.Lookup(msg.Receiver)
	hs := lookup.handshake
	if hs == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {
		hs.mutex.RLock()
		defer hs.mutex.RUnlock()

		if hs.state != handshakeInitiationCreated {
			return false
		}

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		mixHash(&hash, &hs.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &hs.chainKey, msg.Ephemeral[:])

		ss, err := hs.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(&chainKey, &tau, &key, chainKey[:], hs.presharedKey[:])
		mixHash(&hash, &hash, tau[:])

		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	hs.mutex.Lock()
	hs.hash = hash
	hs.chainKey = chainKey
	hs.remoteIndex = msg.Sender
	hs.state = handshakeResponseConsumed
	hs.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])
	return lookup.peer
}

func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	hs := &peer.handshake
	hs.mutex.Lock()
	defer hs.mutex.Unlock()

	var isInitiator bool
	var sendKey, recvKey [chacha20poly1305.KeySize]byte

	if hs.state == handshakeResponseConsumed {
		KDF2(&sendKey, &recvKey, hs.chainKey[:], nil)
		isInitiator = true
	} else if hs.state == handshakeResponseCreated {
		KDF2(&recvKey, &sendKey, hs.chainKey[:], nil)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", hs.state)
	}

	setZero(hs.chainKey[:])
	setZero(hs.hash[:])
	setZero(hs.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	device.indexTable.SwapIndexForKeypair(hs.localIndex, keypair)
	hs.localIndex = 0

	kps := &peer.keypairs
	kps.Lock()
	defer kps.Unlock()

	previous := kps.previous
	next := kps.next.Load()
	current := kps.current

	if isInitiator {
		if next != nil {
			kps.next.Store(nil)
			kps.previous = next
			device.DeleteKeypair(current)
		} else {
			kps.previous = current
		}
		device.DeleteKeypair(previous)
		kps.current = keypair
	} else {
		kps.next.Store(keypair)
		device.DeleteKeypair(next)
		kps.previous = nil
		device.DeleteKeypair(previous)
	}
	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	kps := &peer.keypairs
	if kps.next.Load() != receivedKeypair {
		return false
	}
	kps.Lock()
	defer kps.Unlock()
	if kps.next.Load() != receivedKeypair {
		return false
	}
	old := kps.previous
	kps.previous = kps.current
	peer.device.DeleteKeypair(old)
	kps.current = kps.next.Load()
	kps.next.Store(nil)
	return true
}
