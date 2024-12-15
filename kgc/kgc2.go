package KGC

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/OpenNHP/opennhp/core"
	"github.com/OpenNHP/opennhp/log"
	"github.com/emmansun/gmsm/sm2"
)

type KGC2 struct {
	priv_key   *sm2.PrivateKey
	wa_pub     *ecdsa.PublicKey
	lambda_val *big.Int
}

func (p *KGC2) LoadFixed() {
	log.Error("WARN: Loaded a fixed key pair for KGC!")
	ms_gen := core.Gen_fixed_256bits("efg")
	privkeystr := ms_gen
	pkbs := core.Hex_to_bytes(privkeystr)
	if len(pkbs) == 0 {
		fmt.Printf("WARN: Cannot convert Priv Key: %s\n", privkeystr)
		return
	}
	var err error
	p.priv_key, err = sm2.NewPrivateKey(pkbs)
	if err != nil {
		fmt.Printf("WARN: Cannot generate Priv Key: %s\n", privkeystr)
		return
	}

	pubfull := []byte{}
	pubfull = append(pubfull, p.priv_key.PublicKey.X.Bytes()...)
	pubfull = append(pubfull, p.priv_key.PublicKey.Y.Bytes()...)
	core.PrintKey("KGC Pub", pubfull)
	core.PrintKey("KGC Priv", p.priv_key.D.Bytes())
}

func (p *KGC2) GetFixedMasterKeyPair() (*sm2.PrivateKey, *ecdsa.PublicKey) {
	return p.priv_key, &p.priv_key.PublicKey
}

func (p *KGC2) InitRandMasterKeyPair() (*sm2.PrivateKey, *ecdsa.PublicKey) {
	var err error
	p.priv_key, err = sm2.GenerateKey(rand.Reader)
	if err != nil {
		log.Error("Cannot generate KGC Master Key: %v", err)
		return nil, nil
	}
	return p.priv_key, &p.priv_key.PublicKey
}

// 基于 SM2 算法的无证书公钥密码机制
// K5：KGC计算tA=(w+l*ms) mod n，并KGC向用户A返回tA和WA；
// return tA, WA
func (p *KGC2) GenerateKGCPartialKey(userID, uastr string) (*big.Int, string) {
	if len(uastr) != 128 {
		log.Error("UA format error: %s (%d)!", uastr, len(uastr))
		return nil, ""
	}
	w_gen := core.Gen_fixed_256bits("123")
	w_val, isok := new(big.Int).SetString(w_gen, 16)
	if !isok {
		fmt.Printf("WARN: Cannot convert w string: %s\n", w_gen)
		return nil, ""
	}
	//core.PrintKey("KGC w", w_val.Bytes())

	// KGC private key
	//ms_gen := gen_fixed_256bits("efg")
	ms_gen := p.priv_key.D
	//core.PrintKey("KGC D", ms_gen.Bytes())

	//_, pubk := core.Gen_sm2_keypair("aaabbb")
	pubk := uastr
	//fmt.Printf("DBG UA from user: %s\n", pubk)

	var ta_i *big.Int
	var wa string
	ta_i, p.lambda_val, wa = core.Gen_ta(userID, pubk, w_val, ms_gen)
	if (ta_i == nil) || (wa == "") {
		return nil, ""
	}

	p.wa_pub = core.Str_to_pk(wa)

	//core.PrintKey("TA", ta_i.Bytes())
	//fmt.Printf("WA: %s\n", wa)
	//core.PrintKey("WA X", .Bytes())
	//core.PrintKey("WA Y", ta_i.Bytes())
	return ta_i, wa
}

func (p *KGC2) VerifyUserKey(pkstr string, userID string, entlenA int) bool {
	pa := core.CalculatePa(p.wa_pub, &p.priv_key.PublicKey, p.lambda_val)
	pk_input := core.Str_to_pk(pkstr)
	return pa.Equal(pk_input)
}
