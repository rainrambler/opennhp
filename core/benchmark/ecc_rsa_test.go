package benchmark

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/OpenNHP/opennhp/core"
)

var aeadCount uint64 = 0

func TestRSASignAndVerify(t *testing.T) {
	msg := "Qt for Windows - Building from Source" +
		"This page describes the process of configuring and building Qt for Windows. To download" +
		" and install a pre-built Qt for Windows, follow the instructions on the Getting Started with Qt page."

	now := time.Now()

	for i := 0; i < 10; i++ {
		priv, pub := GenerateRSAKeys()
		hashed, signature, err := SignWithRSAPrivateKey(priv, []byte(msg))

		if err != nil {
			fmt.Printf("RSA sign error: %v", err)
			return
		}

		err = VerifyWithRSAPublicKey(pub, hashed, signature)
		if err != nil {
			fmt.Printf("RSA verify error: %v", err)
			return
		}
	}

	d := time.Since(now)
	fmt.Printf("RSA verify success with %d microseconds.\n", d.Microseconds())
}

func TestECCSharedKey(t *testing.T) {
	now := time.Now()

	msg := "Qt for Windows - Building from Source" +
		"This page describes the process of configuring and building Qt for Windows. To download" +
		" and install a pre-built Qt for Windows, follow the instructions on the Getting Started with Qt page."

	for i := 0; i < 10; i++ {
		ecdh := core.NewECDH(core.ECC_CURVE25519)
		ecdhr := core.NewECDH(core.ECC_CURVE25519)

		ssc := ecdh.SharedSecret(ecdhr.PublicKey())
		sss := ecdhr.SharedSecret(ecdh.PublicKey())

		//if !bytes.Equal(ssc[:], sss[:]) {
		//	fmt.Printf("shared key is not identical, quit")
		//	return
		//}

		var sscKey, sssKey [core.SymmetricKeySize]byte
		copy(sscKey[:], ssc[:])
		copy(sssKey[:], sss[:])

		hashc := sha256.New()
		hashc.Write(ssc[:])
		hashedc := hashc.Sum(nil)

		hashs := sha256.New()
		hashs.Write(ssc[:])
		hasheds := hashs.Sum(nil)

		aeadc := core.AeadFromKey(core.GCM_AES256, &sscKey)
		aeads := core.AeadFromKey(core.GCM_AES256, &sssKey)

		var nonceBytes [12]byte
		aeadCount++
		binary.BigEndian.PutUint64(nonceBytes[:], aeadCount)

		encrypted := aeadc.Seal(nil, nonceBytes[:], []byte(msg), hashedc)
		decrypted, err := aeads.Open(nil, nonceBytes[:], encrypted, hasheds)
		_ = decrypted
		if err != nil {
			fmt.Printf("aead decrypt error: %v", err)
			return
		}
	}

	d := time.Since(now)
	//fmt.Printf("Decrypted message:\n%s\n", string(decrypted))
	fmt.Printf("ECC verify success with %d microseconds.\n", d.Microseconds())
}

func TestGMSharedKey(t *testing.T) {
	now := time.Now()

	msg := "Qt for Windows - Building from Source" +
		"This page describes the process of configuring and building Qt for Windows. To download" +
		" and install a pre-built Qt for Windows, follow the instructions on the Getting Started with Qt page."

	for i := 0; i < 10; i++ {
		ecdh := core.NewECDH(core.ECC_SM2)
		ecdhr := core.NewECDH(core.ECC_SM2)

		ssc := ecdh.SharedSecret(ecdhr.PublicKey())
		sss := ecdhr.SharedSecret(ecdh.PublicKey())

		//if !bytes.Equal(ssc[:], sss[:]) {
		//	fmt.Printf("shared key is not identical, quit")
		//	return
		//}

		var sscKey, sssKey [core.SymmetricKeySize]byte
		copy(sscKey[:], ssc[:])
		copy(sssKey[:], sss[:])

		hashc := sha256.New()
		hashc.Write(ssc[:])
		hashedc := hashc.Sum(nil)

		hashs := sha256.New()
		hashs.Write(ssc[:])
		hasheds := hashs.Sum(nil)

		aeadc := core.AeadFromKey(core.GCM_SM4, &sscKey)
		aeads := core.AeadFromKey(core.GCM_SM4, &sssKey)

		var nonceBytes [12]byte
		aeadCount++
		binary.BigEndian.PutUint64(nonceBytes[:], aeadCount)

		encrypted := aeadc.Seal(nil, nonceBytes[:], []byte(msg), hashedc)
		decrypted, err := aeads.Open(nil, nonceBytes[:], encrypted, hasheds)
		_ = decrypted
		if err != nil {
			fmt.Printf("aead decrypt error: %v", err)
			return
		}
	}

	d := time.Since(now)
	//fmt.Printf("Decrypted message:\n%s\n", string(decrypted))
	fmt.Printf("ECC verify success with %d microseconds.\n", d.Microseconds())
}

func TestGMSharedKeyLog(t *testing.T) {
	now := time.Now()

	msg := "Qt for Windows - Building from Source" +
		"This page describes the process of configuring and building Qt for Windows. To download" +
		" and install a pre-built Qt for Windows, follow the instructions on the Getting Started with Qt page."

	ecdh := core.NewECDH(core.ECC_SM2)
	ecdhr := core.NewECDH(core.ECC_SM2)
	pk64 := `bNS9x/i87E/mefEtbPKyD0CFRpE7HKM5+F/bhJANiXI=`
	pkbs := core.Decode(pk64)
	ecdhr.SetPrivateKey(pkbs)

	fmt.Printf("Pub: %s, Priv: %s\n", ecdh.PublicKeyBase64(), ecdh.PrivateKeyBase64())
	fmt.Printf("Remote: Pub: %s, Priv: %s\n", ecdhr.PublicKeyBase64(), ecdhr.PrivateKeyBase64())
	fmt.Printf("Remote: Pub: %X, Priv: %X\n", ecdhr.PublicKey(), ecdhr.PrivateKey())

	ssc := ecdh.SharedSecret(ecdhr.PublicKey())
	sss := ecdhr.SharedSecret(ecdh.PublicKey())

	//if !bytes.Equal(ssc[:], sss[:]) {
	//	fmt.Printf("shared key is not identical, quit")
	//	return
	//}

	var sscKey, sssKey [core.SymmetricKeySize]byte
	copy(sscKey[:], ssc[:])
	copy(sssKey[:], sss[:])

	hashc := sha256.New()
	hashc.Write(ssc[:])
	hashedc := hashc.Sum(nil)

	hashs := sha256.New()
	hashs.Write(ssc[:])
	hasheds := hashs.Sum(nil)

	aeadc := core.AeadFromKey(core.GCM_SM4, &sscKey)
	aeads := core.AeadFromKey(core.GCM_SM4, &sssKey)

	var nonceBytes [12]byte
	aeadCount++
	binary.BigEndian.PutUint64(nonceBytes[:], aeadCount)

	encrypted := aeadc.Seal(nil, nonceBytes[:], []byte(msg), hashedc)
	decrypted, err := aeads.Open(nil, nonceBytes[:], encrypted, hasheds)
	_ = decrypted
	if err != nil {
		fmt.Printf("aead decrypt error: %v", err)
		return
	}

	d := time.Since(now)
	//fmt.Printf("Decrypted message:\n%s\n", string(decrypted))
	fmt.Printf("ECC verify success with %d microseconds.\n", d.Microseconds())
}
