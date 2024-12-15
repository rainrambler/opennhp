package core

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm2/sm2ec"
	"github.com/emmansun/gmsm/sm3"
)

var default_ecc_table map[string]string
var N_Value *big.Int
var wa_pubkey string
var lambda_val *big.Int

func Dbg_print_bigint(info string, v *big.Int) {
	PrintKey(info, v.Bytes())
}

// "aa@qq.com" ==> "61614071712e636f6d"
func to_hex(s string) string {
	bs := []byte(s)
	return fmt.Sprintf("%x", bs)
}

func Hex_to_bytes(hs string) []byte {
	bs, err := hex.DecodeString(hs)
	if err != nil {
		fmt.Printf("WARN: hex_to_bytes Cannot convert hex string: %s\n", hs)
		return []byte{}
	}

	return bs
}

// result: HEX String
func pk_to_str(pk *ecdsa.PublicKey) string {
	return fmt.Sprintf("%x%x", pk.X.Bytes(), pk.Y.Bytes())
}

func pk_to_bytes(pk *ecdsa.PublicKey) []byte {
	bs := []byte{}
	bs = append(bs, pk.X.Bytes()...)
	bs = append(bs, pk.Y.Bytes()...)
	return bs
}

func PublicKeyToString(pk *ecdsa.PublicKey) string {
	return pk_to_str(pk)
}

func BigIntToHexString(v *big.Int) string {
	return bigint_to_hex(v)
}

func bigint_to_hex(v *big.Int) string {
	if v == nil {
		return ""
	}

	return fmt.Sprintf("%x", v.Bytes())
}

// Input: Public Key in Hex string
func Str_to_pk(s string) *ecdsa.PublicKey {
	x, y := Get_x_y(s)

	xi, err := new(big.Int).SetString(x, 16)
	if !err {
		fmt.Printf("WARN: str_to_pk Cannot convert x string: %s\n", x)
		return nil
	}

	yi, err := new(big.Int).SetString(y, 16)
	if !err {
		fmt.Printf("WARN: str_to_pk Cannot convert y string: %s\n", y)
		return nil
	}

	ecdsaPublicKey := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     xi,
		Y:     yi,
	}

	return ecdsaPublicKey
}

func GenPubKeyfromPrivKey(privkey *big.Int) *ecdsa.PublicKey {
	pkinst, err := sm2.NewPrivateKeyFromInt(privkey)
	if err != nil {
		fmt.Printf("WARN: gen_p Cannot generate Priv Key: %s\n", privkey)
		return nil
	}

	return &pkinst.PublicKey
}

func GeneratePubKeyfromPrivKey(privkey string) string {
	return gen_p(privkey)
}

// privkey: 256-bit hex string
func gen_p(privkey string) string {
	pkbs := Hex_to_bytes(privkey)
	if len(pkbs) == 0 {
		fmt.Printf("WARN: gen_p Cannot convert Priv Key: %s\n", privkey)
		return ""
	}
	pkinst, err := sm2.NewPrivateKey(pkbs)
	if err != nil {
		fmt.Printf("WARN: gen_p Cannot generate Priv Key: %s\n", privkey)
		return ""
	}

	pbk := &pkinst.PublicKey
	return pk_to_str(pbk)
	//return hex.EncodeToString(pbk.//)
}

func Gen_sm2_keypair(s string) (string, string) {
	privk := Gen_fixed_256bits(s)
	pbk := gen_p(privk)
	return privk, pbk
}

func Get_x_y(pubkey string) (string, string) {
	size := len(pubkey)
	return pubkey[:(size / 2)], pubkey[(size / 2):]
}

// SM3 HASH(s) ==> HEX String
func Gen_fixed_256bits(s string) string {
	hashed := sm3.Sum([]byte(s))
	return byte2hex(hashed[:])
}

// Input: w, ms: KGC generated secret
// ta = (w + lambda*ms) mod N
// Return: tA, lambda, wa_pub
func Gen_ta(userid, userpk string, ws, ms *big.Int) (*big.Int, *big.Int, string) {
	kgc_privk, err := sm2.NewPrivateKeyFromInt(ms)
	if err != nil {
		fmt.Printf("WARN Cannot create private key for KGC (%v): %x\n",
			err, ms.Bytes())
		return nil, nil, ""
	}
	kgc_pubk := pk_to_str(&kgc_privk.PublicKey)

	whex := bigint_to_hex(ws)

	lambda_val = gen_lamda(userid, kgc_pubk, userpk, whex)
	if lambda_val == nil {
		return nil, nil, ""
	}

	w_val := ws
	ms_val := ms

	tmp := new(big.Int).Mul(lambda_val, ms_val)
	tmp = tmp.Add(tmp, w_val)

	tmp = tmp.Mod(tmp, N_Value)
	//Dbg_print_bigint("ta", tmp)
	return tmp, lambda_val, wa_pubkey
}

// Input: user id (email), KGC public key, user public key, w (temp priv key)
// Output: lambda = SM3_HASH(wa_x||wa_y||HA) mod N
func gen_lamda(userid, kgc_pk, userpk, w_hex string) *big.Int {
	user_email := userid

	//_, pubk := Gen_sm2_keypair("aaabbb")
	pubk := kgc_pk
	kgc_pubx, kgc_puby := Get_x_y(pubk)
	//fmt.Printf("gen_lamda: KGC X=%s, Y=%s\n", kgc_pubx, kgc_puby)
	HA := gen_ha(user_email, kgc_pubx, kgc_puby)
	if HA == "" {
		return nil
	}

	//fmt.Printf("DBG gen_lamda: HA=%s\n", HA)

	//w := Gen_fixed_256bits("dfnwrfvf")
	w := w_hex
	//PrintKey("w", hex_to_bytes(w))

	//_, userpubk := Gen_sm2_keypair("rgevcbdh")
	userpubk := userpk
	userx, usery := Get_x_y(userpubk)
	//dbg_print_bigint("user x", userx)
	//fmt.Printf("User X=%s, Y=%s\n", userx, usery)

	WA_x, Wa_y := gen_wa(w, userx, usery)
	wa_pubkey = WA_x + Wa_y
	lambda_before_hash := WA_x + Wa_y + HA
	//fmt.Printf("lambda_before_hash: %s\n", lambda_before_hash)
	lambda_before_hash_bytes := Hex_to_bytes(lambda_before_hash)
	//PrintKey("lambda", lambda_before_hash_bytes)

	lamda_sm3 := sm3.Sum(lambda_before_hash_bytes)
	lamda_sm3_val := new(big.Int).SetBytes(lamda_sm3[:])
	//dbg_print_bigint("lambda sm3 val", lamda_sm3_val)

	lambda_bigint := new(big.Int).Mod(lamda_sm3_val, N_Value)
	//dbg_print_bigint("lambda", lambda_bigint)
	return lambda_bigint
}

// Params:
// wstr: hex string (KGC generated w)
// ua_x, ua_y: User public key (correspond to d'A)
// Returns: WA = [w]G + Ua
func gen_wa(wstr, uax, uay string) (string, string) {
	w_h := wstr
	wa_p_h := gen_p(w_h)
	ua_h := uax + uay

	w_pub := Str_to_pk(wa_p_h)
	ua_pub := Str_to_pk(ua_h)

	if (w_pub == nil) || (ua_pub == nil) {
		return "", ""
	}

	curve_sm2 := sm2ec.P256()
	wa_x, wa_y := curve_sm2.Add(w_pub.X, w_pub.Y, ua_pub.X, ua_pub.Y)
	xbs := wa_x.Bytes()
	ybs := wa_y.Bytes()
	//PrintKey("wa x", xbs)
	//PrintKey("wa y", ybs)

	return byte2hex(xbs), byte2hex(ybs)
}

// Param: user id (email), KGC public key
// a, b, G: constant values on the curve
// Return:
// HA = SM3_HASH(ENTla || IDa || a || b || G_x || G_y || pub_x || pub_y)
func gen_ha(user_id, kgc_pub_x, kgc_pub_y string) string {
	ida := to_hex(user_id)
	ida_h := ida
	//fmt.Printf("IDA HEX: %v\n", ida_h)
	pubx := kgc_pub_x
	puby := kgc_pub_y
	entla := len(ida) * 4 // Bytes
	//fmt.Printf("entla: %v\n", entla)
	entla_h := fmt.Sprintf("%04x", entla)
	HA_before_hash := entla_h + ida_h + default_ecc_table[`a`] +
		default_ecc_table[`b`] + default_ecc_table[`g`] + pubx + puby
	//fmt.Printf("HA_before_hash %v\n", HA_before_hash)
	HA_before_hash_bytes := Hex_to_bytes(HA_before_hash)
	if len(HA_before_hash_bytes) == 0 {
		fmt.Printf("WARN: Cannot convert HA before hash: %s\n", HA_before_hash)
		return ""
	}

	ha_h := sm3.Sum(HA_before_hash_bytes)
	//fmt.Printf("INFO: HA: %x\n", ha_h)
	return byte2hex(ha_h[:])
}

func CalculatePa(wa, kgc_pubk *ecdsa.PublicKey, lambda *big.Int) *ecdsa.PublicKey {
	return calc_Pa(wa, kgc_pubk, lambda)
}

// PA=WA+[lambda]Ppub
func calc_Pa(wa, kgc_pubk *ecdsa.PublicKey, lambda *big.Int) *ecdsa.PublicKey {
	// 函数ScalarBaseMult是椭圆曲线有限域上n * G的乘法, 其中n为参数
	x1, y1 := kgc_pubk.ScalarMult(kgc_pubk.X, kgc_pubk.Y, lambda.Bytes())
	Dbg_print_bigint("Pa X1", x1)
	Dbg_print_bigint("Pa Y1", y1)

	xsum, ysum := kgc_pubk.Curve.Add(x1, y1, wa.X, wa.Y)

	Dbg_print_bigint("Pa X", xsum)
	Dbg_print_bigint("Pa Y", ysum)

	ecdsaPublicKey := &ecdsa.PublicKey{
		Curve: sm2.P256(),
		X:     xsum,
		Y:     ysum,
	}

	return ecdsaPublicKey
}

func GetSM2CurveParams() (gx, gy, n *big.Int) {
	g := default_ecc_table["g"]
	gxstr, gystr := Get_x_y(g)

	isok := false
	gx, isok = new(big.Int).SetString(gxstr, 16)
	if !isok {
		fmt.Printf("WARN: Cannot convert gx string: %s\n", gxstr)
	}
	gy, isok = new(big.Int).SetString(gystr, 16)
	if !isok {
		fmt.Printf("WARN: Cannot convert gy string: %s\n", gystr)
	}
	n = N_Value
	return
}

func init() {
	default_ecc_table = map[string]string{
		`n`: `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123`,
		`p`: `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF`,
		`g`: `32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7` +
			`bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0`,
		`a`: `FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC`,
		`b`: `28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93`,
	}

	n_str := default_ecc_table["n"]
	isok := false
	N_Value, isok = new(big.Int).SetString(n_str, 16)
	if !isok {
		fmt.Printf("WARN: Cannot convert n string: %s\n", n_str)
	}
}
