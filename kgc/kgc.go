package KGC

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	_ "github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm2"
)

// 定义 SM2 曲线的固定参数
var fixedA, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16) // 固定值 a
var fixedB, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFD", 16) // 固定值 b

// 计算用户标识 HA = H256(ENTLA‖IDA‖a‖b‖xG‖yG‖xPub‖yPub)
func CalculateHA(userID string, entlenA int, xPub, yPub *big.Int) []byte {
	entla := make([]byte, 2)
	binary.BigEndian.PutUint16(entla, uint16(entlenA))

	ida := []byte(userID)

	// 获取椭圆曲线参数 G 点的坐标
	curve1 := sm2.P256Sm2()
	params := curve1.Params()
	xG := params.Gx
	yG := params.Gy

	// 拼接所有数据
	ab := append(fixedA.Bytes(), fixedB.Bytes()...) // 使用固定值 a 和 b
	gCoords := append(xG.Bytes(), yG.Bytes()...)
	pubCoords := append(xPub.Bytes(), yPub.Bytes()...)

	data := bytes.Join([][]byte{entla, ida, ab, gCoords, pubCoords}, nil)

	// 计算哈希值
	hash := sm3.New()
	hash.Write(data)
	return hash.Sum(nil)
}

// KGC 为用户生成部分密钥 (tA 和 WA).
func GenerateKGCPartialKey(userID string, entlenA int, kgcPrivateKey *sm2.PrivateKey,
	userPublicKey *sm2.PublicKey) (*sm2.PublicKey, *big.Int) {
	curve := sm2.P256Sm2() // 使用 SM2 P256 曲线
	xPub, yPub := kgcPrivateKey.PublicKey.X, kgcPrivateKey.PublicKey.Y

	// 检查 KGC 公私钥
	IsOnCurve(kgcPrivateKey.D, kgcPrivateKey.X, kgcPrivateKey.Y)

	// 计算 HA
	ha := CalculateHA(userID, entlenA, xPub, yPub)

	// 生成 KGC 部分私钥 w
	w, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate KGC partial key: %v", err)
	}

	// 计算 WA = [w]G + UA
	waX, waY := curve.Add(userPublicKey.X, userPublicKey.Y, w.PublicKey.X, w.PublicKey.Y)

	// 验证 WA 是否在曲线上
	if !isPointOnCurve(curve, waX, waY) {
		fmt.Printf("WA is not on the curve!")
	}

	// 计算 tA = (w + H * masterPrivateKey) mod n
	haInt := new(big.Int).SetBytes(ha)
	tA := new(big.Int).Mod(new(big.Int).Add(w.D, new(big.Int).Mul(haInt, kgcPrivateKey.D)), curve.Params().N)

	waPublicKey := &sm2.PublicKey{
		Curve: curve,
		X:     waX,
		Y:     waY,
	}

	IsOnCurve(tA, waX, waY)

	return waPublicKey, tA
}

// 验证点是否在曲线上
func isPointOnCurve(curve elliptic.Curve, x, y *big.Int) bool {
	return curve.IsOnCurve(x, y)
}

func GetCurveParams() (gx, gy, n *big.Int) {
	curve := sm2.P256Sm2() // 使用 SM2 P256 曲线
	gx = curve.Params().Gx
	gy = curve.Params().Gy
	n = curve.Params().N
	return
}

func convertPrivKeyBytes(bs []byte) (*sm2.PrivateKey, error) {
	d := new(big.Int).SetBytes(bs)
	return convertPrivKey(d)
}

func VerifyUserKey(privkstr, pkstr string, userID string, entlenA int) bool {
	pkbs, err := hex.DecodeString(pkstr)
	if err != nil {
		panic(err)
	}

	privkbs, err := hex.DecodeString(privkstr)
	if err != nil {
		panic(err)
	}

	pk, err := convertPrivKeyBytes(privkbs)
	if err != nil {
		panic(err)
	}

	PrintKey("User Public Key", pkbs)

	/*
		pubk, err := sm2.NewPublicKey(pkbs)
		if err != nil {
			panic(err)
		}
	*/

	//pubk := convPublicKey(pkbs)
	pubk := &pk.PublicKey
	pubk.Curve = sm2.P256Sm2()
	PrintKey("User Private Key", privkbs)

	return VerifyKeyPair(pk.D, pubk, userID, entlenA)
}

func convPublicKey(bs []byte) *sm2.PublicKey {
	bsx := bs[:32]
	bsy := bs[32:]
	bsix := new(big.Int).SetBytes(bsx)
	bsiy := new(big.Int).SetBytes(bsy)

	waPublicKey := &sm2.PublicKey{
		Curve: sm2.P256Sm2(),
		X:     bsix,
		Y:     bsiy,
	}

	return waPublicKey
}

// VerifyKeyPair 验证密钥对的正确性
func VerifyKeyPair(dA *big.Int, WA *sm2.PublicKey, userID string, entlenA int) bool {
	// A1: 计算 HA
	ha := CalculateHA(userID, entlenA, WA.X, WA.Y)

	// A2: 转换 WA 的坐标为比特串并计算 l
	xWA := WA.X
	yWA := WA.Y
	l := new(big.Int).SetBytes(sm3.New().Sum(append(append(xWA.Bytes(), yWA.Bytes()...), ha...)))

	// 按照规范转换为整数
	lInt := new(big.Int).Mod(l, WA.Curve.Params().N)
	fmt.Printf("DBG l: %v\n", lInt)

	_, kgcPubKey := GetFixedMasterKeyPair()

	// A3: 计算 PA = WA + [l]Ppub
	PAx, PAy := WA.X, WA.Y
	//Ppub := &ecdsa.PublicKey{Curve: WA.Curve, X: kgcPubKey.X, Y: kgcPubKey.Y}
	cx := new(big.Int).Mul(lInt, kgcPubKey.X)
	cy := new(big.Int).Mul(lInt, kgcPubKey.Y)

	PrintKey("CX", cx.Bytes())
	PrintKey("CX", cy.Bytes())

	PAx, PAy = WA.Curve.Add(PAx, PAy, cx, cy)

	// A4: 计算 P'A = [dA]G
	PAPx, PAPy := WA.Curve.ScalarBaseMult(dA.Bytes())

	// A5: 检查 PA = P'A
	if PAx.Cmp(PAPx) == 0 && PAy.Cmp(PAPy) == 0 {
		fmt.Println("Verification successful")
		return true
	}
	fmt.Println("Verification failed")
	return false
}

type KGCenter struct {
	MasterPrivateKey *sm2.PrivateKey // 系统主私钥 s
	MasterPublicKey  *sm2.PublicKey  // 系统主公钥 P_pub
}

const (
	PrivKey = `mxOLE8AD5Rg6FHELWn8rKfUqhwR5X47ggZdzcGtK6IQ=`
	PubX    = `ELVMSG786oyTXVPlWi992DyichSDwQ2hnAC9E9Hrzz0=`
	PubY    = `6NzvF6rs3IeNYLhUK6y3fuPVs/3h8TDgc0V2/18bHLM=`
)

func LoadDefault() *KGCenter {
	privbs, _ := base64.StdEncoding.DecodeString(PrivKey)
	kg := new(KGCenter)
	pk, err := convertPrivKeyBytes(privbs)
	if err != nil {
		panic(err)
	}
	kg.MasterPrivateKey = pk
	return kg
}

// 系统主密钥对 (KGC).
func GetFixedMasterKeyPair() (*sm2.PrivateKey, *sm2.PublicKey) {
	kg := LoadDefault()
	return kg.MasterPrivateKey, &kg.MasterPrivateKey.PublicKey
}
